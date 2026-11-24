// CESR and KERI message serialization for the did:webs resolver.
//
// A port of OpenVTC/vti-didcomm-js `src/did-webs-cesr.js`, itself a port of
// the parts of `affinidi-cesr` 0.1.4 and `affinidi-keri-core` 0.8.1 that
// resolving a did:webs reads: Base64 primitives (`Matter`, `Indexer`),
// counters and the attachment groups of both counter tables, version strings,
// order-preserving JSON ("SAD" values), SAIDs, and native CESR bodies. Every
// rule — what is accepted, what is refused, and in what order — follows that
// code; where this module differs it says so.
//
// Message content is held as a SAD value: `Map<String, Object?>` (Dart's
// default map keeps insertion order, so member order is exactly the order the
// bytes had — a SAID and a signature cover those bytes), `List<Object?>`,
// `String`, `bool`, `null`, and [SadNumber] for numbers, which keeps their
// decimal text.
//
// Not supported, and refused rather than guessed at: CBOR and MessagePack
// bodies, and JSON numbers that are not integers in the signed or unsigned
// 64-bit range.

// ignore_for_file: public_member_api_docs

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/dart.dart' show DartBlake2s;
import 'package:pointycastle/digests/blake2b.dart';
import 'package:pointycastle/digests/sha3.dart';

import '../crypto/blake3.dart';

part 'cesr_native.dart';
part 'cesr_stream.dart';

/// An error in a KERI message or stream (affinidi-keri-core `CoreError`).
class KeriError implements Exception {
  KeriError(this.message, [this.type = 'parse']);

  final String message;

  /// One of `parse`, `validation`, `unsupported`, `said`, `threshold`,
  /// `crypto`, `json`.
  final String type;

  @override
  String toString() => 'KeriError($type): $message';
}

Never fail(String message, [String type = 'parse']) =>
    throw KeriError(message, type);

// ─── Bytes and text ─────────────────────────────────────────────────────

Uint8List utf8Bytes(String s) => Uint8List.fromList(utf8.encode(s));

/// Strict UTF-8 decoding; throws [FormatException] on malformed input.
String fromUtf8(List<int> bytes) => utf8.decode(bytes);

/// Bytes as text when every byte is ASCII, else null.
String? asciiText(List<int> bytes) {
  for (final b in bytes) {
    if (b > 0x7f) return null;
  }
  return String.fromCharCodes(bytes);
}

bool isAscii(String s) {
  for (var i = 0; i < s.length; i++) {
    if (s.codeUnitAt(i) > 0x7f) return false;
  }
  return true;
}

/// Rust's byte-wise string order (UTF-8 code units), for sorted maps.
int compareUtf8(String a, String b) {
  if (a == b) return 0;
  final x = utf8.encode(a);
  final y = utf8.encode(b);
  final n = x.length < y.length ? x.length : y.length;
  for (var i = 0; i < n; i++) {
    if (x[i] != y[i]) return x[i] - y[i];
  }
  return x.length - y.length;
}

final BigInt u64Max = BigInt.parse('ffffffffffffffff', radix: 16);
final BigInt i64Min = -BigInt.parse('8000000000000000', radix: 16);
final RegExp _hexDigits = RegExp(r'^[0-9a-fA-F]+$');
final RegExp _decDigits = RegExp(r'^[0-9]+$');

/// `u64::from_str_radix` and friends: an optional `+`, then at least one
/// digit of [radix]. Null when it does not parse or exceeds [max].
BigInt? parseUnsigned(Object? text, int radix, [BigInt? max]) {
  if (text is! String) return null;
  final digits = text.startsWith('+') ? text.substring(1) : text;
  final pattern = radix == 16 ? _hexDigits : _decDigits;
  if (!pattern.hasMatch(digits)) return null;
  final value = BigInt.parse(digits, radix: radix);
  return value > (max ?? u64Max) ? null : value;
}

const int maxSafeInteger = 9007199254740991;

/// A sequence number or count as an int when it is exactly representable on
/// every platform (the web included), else null.
int? toSafeNumber(BigInt? big) {
  if (big == null || big > BigInt.from(maxSafeInteger)) return null;
  return big.toInt();
}

// ─── Base64 (URL-safe, unpadded) ────────────────────────────────────────

const String _b64 =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
final Map<String, int> _b64Index = {
  for (var i = 0; i < _b64.length; i++) _b64[i]: i,
};

int? b64Value(String c) => _b64Index[c];

bool isB64(String text) {
  for (var i = 0; i < text.length; i++) {
    if (!_b64Index.containsKey(text[i])) return false;
  }
  return true;
}

/// Big-endian value of a run of Base64 digits.
BigInt b64ToInt(String text) {
  var n = BigInt.zero;
  final b64 = BigInt.from(64);
  for (var i = 0; i < text.length; i++) {
    final v = _b64Index[text[i]];
    if (v == null) {
      fail('invalid Base64 digit ${jsonQuote(text[i])} in ${jsonQuote(text)}');
    }
    n = n * b64 + BigInt.from(v);
  }
  return n;
}

/// [value] as [width] Base64 digits, higher digits dropped.
String intToB64(Object value, int width) {
  var n = value is BigInt ? value : BigInt.from(value as int);
  final b64 = BigInt.from(64);
  final out = List<String>.filled(width, 'A');
  for (var i = width - 1; i >= 0; i--) {
    out[i] = _b64[(n % b64).toInt()];
    n = n ~/ b64;
  }
  return out.join();
}

/// Encode bytes as unpadded URL-safe Base64.
String b64Encode(List<int> bytes) {
  final out = StringBuffer();
  var i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    final n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out
      ..write(_b64[n >> 18])
      ..write(_b64[(n >> 12) & 63])
      ..write(_b64[(n >> 6) & 63])
      ..write(_b64[n & 63]);
  }
  final rest = bytes.length - i;
  if (rest == 1) {
    final n = bytes[i] << 16;
    out
      ..write(_b64[n >> 18])
      ..write(_b64[(n >> 12) & 63]);
  } else if (rest == 2) {
    final n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out
      ..write(_b64[n >> 18])
      ..write(_b64[(n >> 12) & 63])
      ..write(_b64[(n >> 6) & 63]);
  }
  return out.toString();
}

/// Decode unpadded URL-safe Base64 the way `base64ct` does: no padding, no
/// other alphabet, no dangling character, and the unused bits of a partial
/// final group must be zero.
Uint8List b64Decode(String text) {
  if (text.length % 4 == 1) fail('invalid Base64 length ${text.length}');
  final out = Uint8List((text.length * 3) ~/ 4);
  var o = 0;
  var i = 0;
  int v(int k) {
    final x = _b64Index[text[k]];
    if (x == null) fail('invalid Base64 character ${jsonQuote(text[k])}');
    return x;
  }

  for (; i + 4 <= text.length; i += 4) {
    final n = (v(i) << 18) | (v(i + 1) << 12) | (v(i + 2) << 6) | v(i + 3);
    out[o++] = n >> 16;
    out[o++] = (n >> 8) & 255;
    out[o++] = n & 255;
  }
  final rest = text.length - i;
  if (rest == 2) {
    final a = v(i);
    final b = v(i + 1);
    if (b & 15 != 0) fail('non-canonical Base64 encoding');
    out[o++] = ((a << 2) | (b >> 4)) & 255;
  } else if (rest == 3) {
    final a = v(i);
    final b = v(i + 1);
    final c = v(i + 2);
    if (c & 3 != 0) fail('non-canonical Base64 encoding');
    out[o++] = ((a << 2) | (b >> 4)) & 255;
    out[o++] = (((b & 15) << 4) | (c >> 2)) & 255;
  }
  return out;
}

// ─── SAD values: order-preserving JSON (affinidi-keri-core `sad.rs`) ────

/// A JSON number, held as its decimal text (an integer in i64 or u64 range).
class SadNumber {
  const SadNumber(this.text);

  final String text;

  BigInt get big => BigInt.parse(text);

  @override
  bool operator ==(Object other) => other is SadNumber && other.text == text;

  @override
  int get hashCode => text.hashCode;

  @override
  String toString() => text;
}

/// Member [key] of a SAD object, or null.
Object? sadGet(Object? value, String key) =>
    value is Map<String, Object?> ? value[key] : null;

/// The string, if [value] is one.
String? sadStr(Object? value) => value is String ? value : null;

/// Deep equality of SAD values (serde_json `Value` / `SadValue` `PartialEq`).
bool sadEqual(Object? a, Object? b) {
  if (identical(a, b)) return true;
  if (a is SadNumber && b is SadNumber) return a.text == b.text;
  if (a is List && b is List) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (!sadEqual(a[i], b[i])) return false;
    }
    return true;
  }
  if (a is Map && b is Map) {
    if (a.length != b.length) return false;
    for (final e in a.entries) {
      if (!b.containsKey(e.key) || !sadEqual(e.value, b[e.key])) return false;
    }
    return true;
  }
  if (a is String || a is bool) return a == b;
  return a == null && b == null;
}

/// A deep copy.
Object? sadClone(Object? value) {
  if (value is List) return [for (final v in value) sadClone(v)];
  if (value is Map) {
    return <String, Object?>{
      for (final e in value.entries) e.key as String: sadClone(e.value),
    };
  }
  return value;
}

/// The SAD as plain JSON: numbers that fit a JS safe integer become [int],
/// others stay as their text (as the JS port does).
Object? toJson(Object? value) {
  if (value is SadNumber) {
    final n = BigInt.parse(value.text);
    return n.abs() <= BigInt.from(maxSafeInteger) ? n.toInt() : value.text;
  }
  if (value is List) return [for (final v in value) toJson(v)];
  if (value is Map) {
    return <String, Object?>{
      for (final e in value.entries) e.key as String: toJson(e.value),
    };
  }
  return value;
}

/// Plain JSON as a SAD value (a parsed did.json, a built document).
Object? fromJson(Object? value) {
  if (value == null || value is bool || value is String) return value;
  if (value is int) {
    if (value.abs() > maxSafeInteger) {
      fail('a non-integer number is not supported', 'unsupported');
    }
    return SadNumber('$value');
  }
  if (value is double) {
    if (value != value.truncateToDouble() || value.abs() > maxSafeInteger) {
      fail('a non-integer number is not supported', 'unsupported');
    }
    return SadNumber('${value.toInt()}');
  }
  if (value is List) return [for (final v in value) fromJson(v)];
  if (value is Map) {
    return <String, Object?>{
      for (final e in value.entries) e.key as String: fromJson(e.value),
    };
  }
  fail('not a JSON value: ${value.runtimeType}', 'json');
}

const int _maxJsonDepth = 128; // serde_json's recursion limit
final RegExp _number = RegExp(
  r'-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?',
);

/// Parse JSON as `serde_json::from_slice` into a `SadValue` does: strict
/// syntax, UTF-8, duplicate members refused, at most 127 levels of nesting,
/// only whitespace after the value.
///
/// With [plain], as `serde_json::from_slice` into a `serde_json::Value` does
/// instead: plain maps and numbers (`num`), and the last of a repeated member.
Object? parseJson(List<int> bytes, {bool plain = false}) {
  final String text;
  try {
    text = fromUtf8(bytes);
  } on FormatException {
    fail('invalid UTF-8 in JSON', 'json');
  }
  var i = 0;
  Never err(String m) => fail('JSON: $m at $i', 'json');
  void ws() {
    while (i < text.length) {
      final c = text.codeUnitAt(i);
      if (c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d) {
        i++;
      } else {
        break;
      }
    }
  }

  Object? literal(String word, Object? value) {
    if (text.startsWith(word, i)) {
      i += word.length;
      return value;
    }
    err('invalid literal');
  }

  String string() {
    i++; // opening quote
    final out = StringBuffer();
    var start = i;
    for (;;) {
      if (i >= text.length) err('unterminated string');
      final c = text.codeUnitAt(i);
      if (c == 0x22) {
        out.write(text.substring(start, i));
        i++;
        return out.toString();
      }
      if (c < 0x20) err('control character in string');
      if (c != 0x5c) {
        i++;
        continue;
      }
      out.write(text.substring(start, i));
      final e = i + 1 < text.length ? text[i + 1] : '';
      i += 2;
      switch (e) {
        case '"':
          out.write('"');
        case r'\':
          out.write(r'\');
        case '/':
          out.write('/');
        case 'b':
          out.write('\b');
        case 'f':
          out.write('\f');
        case 'n':
          out.write('\n');
        case 'r':
          out.write('\r');
        case 't':
          out.write('\t');
        case 'u':
          int hex() {
            final h = i + 4 <= text.length ? text.substring(i, i + 4) : '';
            if (!RegExp(r'^[0-9a-fA-F]{4}$').hasMatch(h)) {
              err(r'invalid \u escape');
            }
            i += 4;
            return int.parse(h, radix: 16);
          }

          final u = hex();
          if (u >= 0xd800 && u <= 0xdbff) {
            if (i + 1 >= text.length || text[i] != r'\' || text[i + 1] != 'u') {
              err('lone leading surrogate');
            }
            i += 2;
            final lo = hex();
            if (lo < 0xdc00 || lo > 0xdfff) err('invalid trailing surrogate');
            out.writeCharCode(u);
            out.writeCharCode(lo);
          } else if (u >= 0xdc00 && u <= 0xdfff) {
            err('lone trailing surrogate');
          } else {
            out.writeCharCode(u);
          }
        default:
          err('invalid escape');
      }
      start = i;
    }
  }

  Object number() {
    final m = _number.matchAsPrefix(text, i);
    if (m == null) err('invalid number');
    final lexeme = m[0]!;
    i += lexeme.length;
    if (plain) {
      final n = num.tryParse(lexeme);
      if (n == null || !n.isFinite) err('number out of range');
      return n;
    }
    if (m[2] == null && m[3] == null) {
      final big = BigInt.parse(lexeme);
      final ok = lexeme.startsWith('-')
          ? big < BigInt.zero && big >= i64Min
          : big <= u64Max;
      if (ok) return SadNumber(big.toString());
    }
    // serde_json holds anything else as an f64, whose text form this module
    // does not reproduce: refused rather than re-serialized wrongly.
    fail(
      'JSON number $lexeme is not an integer this implementation supports',
      'unsupported',
    );
  }

  Object? value(int depth) {
    ws();
    final c = i < text.length ? text[i] : '';
    if (c == '{' || c == '[') {
      if (depth + 1 >= _maxJsonDepth) err('recursion limit exceeded');
      i++;
      if (c == '[') {
        final out = <Object?>[];
        ws();
        if (i < text.length && text[i] == ']') {
          i++;
          return out;
        }
        for (;;) {
          out.add(value(depth + 1));
          ws();
          final d = i < text.length ? text[i] : '';
          if (d == ',') {
            i++;
          } else if (d == ']') {
            i++;
            return out;
          } else {
            err('expected , or ]');
          }
        }
      }
      final out = <String, Object?>{};
      ws();
      if (i < text.length && text[i] == '}') {
        i++;
        return out;
      }
      for (;;) {
        ws();
        if (i >= text.length || text[i] != '"') err('expected a member name');
        final key = string();
        ws();
        if (i >= text.length || text[i] != ':') err('expected :');
        i++;
        final v = value(depth + 1);
        if (plain) {
          // serde_json::Value keeps the last of a repeated member, in the
          // position of the first.
          out[key] = v;
        } else {
          if (out.containsKey(key)) {
            fail('duplicate member in a KERI message', 'json');
          }
          out[key] = v;
        }
        ws();
        final d = i < text.length ? text[i] : '';
        if (d == ',') {
          i++;
        } else if (d == '}') {
          i++;
          return out;
        } else {
          err('expected , or }');
        }
      }
    }
    if (c == '"') return string();
    if (c == 't') return literal('true', true);
    if (c == 'f') return literal('false', false);
    if (c == 'n') return literal('null', null);
    if (c == '-' ||
        (c.isNotEmpty && c.codeUnitAt(0) >= 0x30 && c.codeUnitAt(0) <= 0x39)) {
      return number();
    }
    err('expected a value');
  }

  final out = value(0);
  ws();
  if (i != text.length) err('trailing characters');
  return out;
}

/// A JSON string literal, escaped as `JSON.stringify` and serde_json both do
/// for the strings KERI carries (control characters as `\uXXXX` lowercase,
/// except the five short escapes).
String jsonQuote(String s) {
  final out = StringBuffer('"');
  for (var i = 0; i < s.length; i++) {
    final c = s.codeUnitAt(i);
    switch (c) {
      case 0x22:
        out.write(r'\"');
      case 0x5c:
        out.write(r'\\');
      case 0x08:
        out.write(r'\b');
      case 0x0c:
        out.write(r'\f');
      case 0x0a:
        out.write(r'\n');
      case 0x0d:
        out.write(r'\r');
      case 0x09:
        out.write(r'\t');
      default:
        if (c < 0x20) {
          out.write(r'\u');
          out.write(c.toRadixString(16).padLeft(4, '0'));
        } else {
          out.writeCharCode(c);
        }
    }
  }
  out.write('"');
  return out.toString();
}

/// Serialize a SAD as compact JSON, as `serde_json::to_vec` writes it.
String serializeJson(Object? value) {
  if (value == null) return 'null';
  if (value == true) return 'true';
  if (value == false) return 'false';
  if (value is String) return jsonQuote(value);
  if (value is SadNumber) return value.text;
  if (value is List) return '[${value.map(serializeJson).join(',')}]';
  if (value is Map) {
    return '{${value.entries.map((e) => '${jsonQuote(e.key as String)}:${serializeJson(e.value)}').join(',')}}';
  }
  fail('not a SAD value: ${value.runtimeType}', 'json');
}

// ─── Version strings (affinidi-keri-core `version.rs`) ──────────────────

const int keriVerFullsize = 17;
const int keriVer2Fullsize = 19;
const Set<String> _kinds = {'JSON', 'CBOR', 'MGPK', 'CESR'};

/// A KERI/ACDC version string, parsed.
class Version {
  Version({
    required this.protocol,
    required this.major,
    required this.minor,
    required this.kind,
    required this.size,
    this.genus,
  });

  final String protocol;
  final int major;
  final int minor;
  final String kind;
  final int size;

  /// `(major, minor)` of the genus, version 2 only.
  final (int, int)? genus;

  Version copyWith({int? size}) => Version(
    protocol: protocol,
    major: major,
    minor: minor,
    kind: kind,
    size: size ?? this.size,
    genus: genus,
  );
}

String _parseProtocol(String p) {
  if (!RegExp(r'^[A-Z]{4}$').hasMatch(p)) {
    fail('invalid protocol: ${jsonQuote(p)}', 'validation');
  }
  return p;
}

String _kindOf(String tag) {
  if (!_kinds.contains(tag)) {
    fail('unknown serialization kind: $tag', 'validation');
  }
  return tag;
}

int? _hexDigit(String c) =>
    RegExp(r'^[0-9a-fA-F]$').hasMatch(c) ? int.parse(c, radix: 16) : null;

int _b64Small(String text, String what) {
  final v = b64ToInt(text);
  if (v > BigInt.from(255)) fail('$what $v is out of range', 'validation');
  return v.toInt();
}

bool _allAscii(List<int> bytes) => bytes.every((b) => b < 0x80);

/// Parse a version string, in either form (`Version::parse_str`).
Version parseVersionString(String vs) {
  final bytes = utf8Bytes(vs);
  if (bytes.length >= keriVer2Fullsize &&
      bytes[18] == 0x2e &&
      _allAscii(bytes.sublist(0, 19))) {
    return _parseV2(String.fromCharCodes(bytes.sublist(0, 19)));
  }
  return _parseV1(bytes);
}

Version _parseV1(Uint8List bytes) {
  if (bytes.length < keriVerFullsize) {
    fail(
      'version string too short: ${bytes.length} chars (need $keriVerFullsize)',
      'validation',
    );
  }
  if (!_allAscii(bytes.sublist(0, 17))) {
    fail('version string contains non-ASCII bytes', 'validation');
  }
  final vs = String.fromCharCodes(bytes.sublist(0, 17));
  final protocol = _parseProtocol(vs.substring(0, 4));
  final major = _hexDigit(vs[4]);
  final minor = _hexDigit(vs[5]);
  if (major == null) {
    fail('invalid major version digit: ${vs[4]}', 'validation');
  }
  if (minor == null) {
    fail('invalid minor version digit: ${vs[5]}', 'validation');
  }
  if (major > 1) {
    fail('a version 1 string cannot name major version $major', 'validation');
  }
  final kind = _kindOf(vs.substring(6, 10));
  if (kind == 'CESR') {
    fail('native CESR serialization does not exist in version 1', 'validation');
  }
  final size = parseUnsigned(vs.substring(10, 16), 16);
  if (size == null) {
    fail('invalid hex size: ${vs.substring(10, 16)}', 'validation');
  }
  if (vs[16] != '_') {
    fail(
      "expected '_' terminator at position 16, got '${vs[16]}'",
      'validation',
    );
  }
  return Version(
    protocol: protocol,
    major: major,
    minor: minor,
    kind: kind,
    size: size.toInt(),
  );
}

Version _parseV2(String vs) {
  final protocol = _parseProtocol(vs.substring(0, 4));
  final major = _b64Small(vs.substring(4, 5), 'protocol major');
  final minor = _b64Small(vs.substring(5, 7), 'protocol minor');
  final genusMajor = _b64Small(vs.substring(7, 8), 'genus major');
  final genusMinor = _b64Small(vs.substring(8, 10), 'genus minor');
  if (major != 2) {
    fail(
      'a version 2 string must name protocol major version 2, not $major',
      'validation',
    );
  }
  if (genusMajor != 2) {
    fail(
      'a version 2 string must name genus major version 2, not $genusMajor',
      'validation',
    );
  }
  final kind = _kindOf(vs.substring(10, 14));
  final size = b64ToInt(vs.substring(14, 18)).toInt();
  return Version(
    protocol: protocol,
    major: major,
    minor: minor,
    kind: kind,
    size: size,
    genus: (genusMajor, genusMinor),
  );
}

/// Parse the version string at the start of [data] (`Version::parse`).
Version parseVersionBytes(Uint8List data) {
  final v1 = data.length >= keriVerFullsize && data[16] == 0x5f;
  final v2 = data.length >= keriVer2Fullsize && data[18] == 0x2e;
  if (v1 && v2) {
    fail(
      'version string has both a version 1 and a version 2 terminator',
      'validation',
    );
  }
  if (!v1 && !v2) fail('no version string', 'validation');
  final len = v1 ? keriVerFullsize : keriVer2Fullsize;
  final head = data.sublist(0, len);
  if (!_allAscii(head)) {
    fail('version string contains non-ASCII bytes', 'validation');
  }
  return parseVersionString(String.fromCharCodes(head));
}

/// The version string for a version (`Version::to_version_string`).
String versionString(Version v) {
  if (v.major >= 2) {
    final (gm, gn) = v.genus ?? (2, 0);
    return '${v.protocol}${intToB64(v.major, 1)}${intToB64(v.minor, 2)}'
        '${intToB64(gm, 1)}${intToB64(gn, 2)}${v.kind}${intToB64(v.size, 4)}.';
  }
  final size = v.size.toRadixString(16).padLeft(6, '0');
  return '${v.protocol}${v.major.toRadixString(16)}${v.minor.toRadixString(16)}'
      '${v.kind}${size.substring(size.length - 6)}_';
}

/// The protocol major version a message's `v` field names.
int protocolMajor(Object? sad) {
  final vs = sadStr(sadGet(sad, 'v'));
  if (vs == null) fail('missing field v', 'validation');
  return parseVersionString(vs).major;
}

// ─── Digests ────────────────────────────────────────────────────────────

Uint8List _blake2b(List<int> d, int size) {
  final digest = Blake2bDigest(digestSize: size);
  final data = Uint8List.fromList(d);
  digest.update(data, 0, data.length);
  final out = Uint8List(size);
  digest.doFinal(out, 0);
  return out;
}

Uint8List _sha3(List<int> d, int bits) {
  final digest = SHA3Digest(bits);
  final data = Uint8List.fromList(d);
  return digest.process(data);
}

final Map<String, Uint8List Function(List<int>)> _digests = {
  'E': blake3,
  'F': (d) => _blake2b(d, 32),
  'G': (d) => Uint8List.fromList(const DartBlake2s().hashSync(d).bytes),
  'H': (d) => _sha3(d, 256),
  'I': (d) => Uint8List.fromList(crypto.sha256.convert(d).bytes),
  '0D': (d) => blake3(d, 64),
  '0E': (d) => _blake2b(d, 64),
  '0F': (d) => _sha3(d, 512),
  '0G': (d) => Uint8List.fromList(crypto.sha512.convert(d).bytes),
};

/// Whether [code] is a digest code (affinidi-keri-crypto `Diger`).
bool isDigestCode(String code) => _digests.containsKey(code);

/// The qb64 digest of [data] under [code] (`Diger::from_data(...).qb64()`).
String digest(String code, List<int> data) {
  final fn = _digests[code];
  if (fn == null) fail('unsupported digest code: $code', 'crypto');
  return matterQb64(code, fn(data));
}

/// Whether qb64 digest [qb64] is the digest of [data] (`Diger::verify`).
bool digestMatches(String qb64, List<int> data) {
  final m = matterFromQb64(qb64);
  final fn = _digests[m.code];
  if (fn == null) fail('unsupported digest code: ${m.code}', 'crypto');
  final raw = fn(data);
  if (raw.length != m.raw.length) return false;
  var diff = 0;
  for (var i = 0; i < raw.length; i++) {
    diff |= raw[i] ^ m.raw[i];
  }
  return diff == 0;
}

// ─── Matter (affinidi-cesr `matter.rs` / `tables.rs`) ───────────────────

bool _isLetter(String c) {
  if (c.isEmpty) return false;
  final u = c.codeUnitAt(0);
  return (u >= 0x41 && u <= 0x5a) || (u >= 0x61 && u <= 0x7a);
}

/// First character to hard size (`tables::hardage`).
int? hardage(String c) {
  if (_isLetter(c)) return 1;
  if (c == '0' || c == '4' || c == '5' || c == '6') return 2;
  if (c == '1' || c == '2' || c == '3' || c == '7' || c == '8' || c == '9') {
    return 4;
  }
  if (c == '-') return 2;
  return null;
}

/// Sizes of a Matter code: hard, soft and full size (0 = variable).
class Sizage {
  const Sizage(this.hs, this.ss, this.fs);
  final int hs;
  final int ss;
  final int fs;
}

const Map<String, List<int>> _matter = {
  'B': [1, 0, 44],
  'D': [1, 0, 44],
  'E': [1, 0, 44],
  'F': [1, 0, 44],
  'G': [1, 0, 44],
  'H': [1, 0, 44],
  'I': [1, 0, 44],
  'J': [1, 0, 24],
  'K': [1, 0, 44],
  'L': [1, 0, 24],
  'C': [1, 0, 44],
  'A': [1, 0, 44],
  '1AAA': [4, 0, 48],
  '1AAB': [4, 0, 48],
  '1AAC': [4, 0, 80],
  '1AAD': [4, 0, 80],
  '1AAE': [4, 0, 156],
  '1AAF': [4, 0, 8],
  '1AAG': [4, 0, 36],
  '1AAI': [4, 0, 48],
  '1AAJ': [4, 0, 48],
  '1AAH': [4, 0, 92],
  '1AAK': [4, 0, 92],
  '1AAL': [4, 0, 92],
  '1AAM': [4, 0, 92],
  '0A': [2, 0, 24],
  '0B': [2, 0, 88],
  '0C': [2, 0, 88],
  '0D': [2, 0, 88],
  '0E': [2, 0, 88],
  '0F': [2, 0, 88],
  '0G': [2, 0, 88],
  '0I': [2, 0, 88],
  '4A': [2, 2, 0],
  '4B': [2, 2, 0],
  '5A': [2, 2, 0],
  '5B': [2, 2, 0],
  '6A': [2, 2, 0],
  '6B': [2, 2, 0],
  '7AAA': [4, 4, 0],
  '7AAB': [4, 4, 0],
  '8AAA': [4, 4, 0],
  '8AAB': [4, 4, 0],
  '9AAA': [4, 4, 0],
  '9AAB': [4, 4, 0],
};

/// The sizes of a Matter code as `affinidi-cesr` knows it, or null.
Sizage? matterSizage(String code) {
  final s = _matter[code];
  return s == null ? null : Sizage(s[0], s[1], s[2]);
}

int _leadOf(int hs) => hs == 1
    ? 1
    : hs == 2
    ? 2
    : hs == 4
    ? 3
    : 0;

/// A decoded primitive.
class MatterValue {
  MatterValue(this.code, this.raw, this.fs);
  final String code;
  final Uint8List raw;
  final int fs;
}

/// Read a primitive (`Matter::from_qb64`). As in `affinidi-cesr`, only the
/// first `fs` characters are read and anything after them is ignored;
/// callers that need a whole primitive compare lengths themselves.
MatterValue matterFromQb64(Object? qb64) {
  if (qb64 is! String || qb64.isEmpty) fail('empty input', 'crypto');
  if (!isAscii(qb64)) fail('invalid character', 'crypto');
  final hs = hardage(qb64[0]);
  if (hs == null) fail('unknown code ${qb64[0]}', 'crypto');
  if (qb64.length < hs) fail('unexpected end', 'crypto');
  final code = qb64.substring(0, hs);
  final s = matterSizage(code);
  if (s == null) fail('unknown code $code', 'crypto');
  if (s.fs > 0) {
    if (qb64.length < s.fs) fail('unexpected end', 'crypto');
    final all = b64Decode(qb64.substring(0, s.fs));
    final lead = _leadOf(s.hs);
    if (all.length <= lead) fail('invalid raw size', 'crypto');
    return MatterValue(code, Uint8List.fromList(all.sublist(lead)), s.fs);
  }
  if (qb64.length < s.hs + s.ss) fail('unexpected end', 'crypto');
  final count = b64ToInt(qb64.substring(s.hs, s.hs + s.ss)).toInt();
  final fs = s.hs + s.ss + count * 4;
  if (qb64.length < fs) fail('unexpected end', 'crypto');
  final all = b64Decode(qb64.substring(s.hs + s.ss, fs));
  var lead = 0;
  while (lead < 2 && lead < all.length && all[lead] == 0) {
    lead++;
  }
  return MatterValue(code, Uint8List.fromList(all.sublist(lead)), fs);
}

/// Encode a fixed-size primitive (`Matter::new(code, raw)?.qb64()`).
String matterQb64(String code, List<int> raw) {
  final s = matterSizage(code);
  if (s == null) fail('unknown code $code', 'crypto');
  if (s.fs == 0) {
    fail('variable-size code $code is not supported here', 'crypto');
  }
  final total = (s.fs * 3) ~/ 4;
  final expected = total - _leadOf(s.hs);
  if (raw.length != expected) {
    fail('invalid raw size: expected $expected, got ${raw.length}', 'crypto');
  }
  final ls = (3 - (raw.length % 3)) % 3;
  final padded = Uint8List(ls + raw.length)..setRange(ls, ls + raw.length, raw);
  final encoded = b64Encode(padded);
  final cs = s.fs - s.hs;
  if (encoded.length < cs) fail('invalid raw size', 'crypto');
  return code + encoded.substring(encoded.length - cs);
}
