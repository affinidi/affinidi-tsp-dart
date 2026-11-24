// `did:webs` resolution from fetched artifacts: did:web discovery with
// KERI-verified key state.
//
//   did:webs:<host>[%3A<port>][:<path>…]:<AID>
//
//   https://<host>[:<port>]/<path>/<AID>/keri.cesr   the key event stream
//   https://<host>[:<port>]/<path>/<AID>/did.json    the document, as a cache
//
// The document is derived from the verified key event stream, never copied
// from `did.json`: every event, signature, pre-rotation commitment,
// delegation and witness receipt is verified; the AID must designate this
// DID (a designated-aliases attestation it issued itself and anchored in its
// own KEL); the document is built from that state; and the published
// `did.json`, read back from its did:web form, must agree with it. A
// disagreement is an error rather than a choice between two answers.
//
// A port of OpenVTC/vti-didcomm-js `src/did-webs.js` (itself a port of
// `affinidi-did-webs` 0.13.1, with the identifier checks of 0.13.2), less its
// fetching, which is `lib/src/ssi/did_webs_resolver.dart`. Free of dart:io.
//
// The JS reads a DID's host with the WHATWG URL parser; this reads it the
// same way for ASCII hosts (lowercase, IPv4 in any of its numeric forms,
// IPv6 in its canonical form, the default port dropped). An
// internationalized host name is refused rather than mapped (IDNA is not
// implemented).

// ignore_for_file: public_member_api_docs

import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';

import 'cesr.dart';
import 'designations.dart';
import 'endpoints.dart';
import 'kel.dart';

/// `code` of every [DidWebsError].
const String didWebsErrorCode = 'E_DID_WEBS';

/// Default upper bound on one `keri.cesr` / `did.json` fetch, as the Rust
/// crate.
const Duration defaultWebsTimeout = Duration(milliseconds: 20000);

/// Largest artifact read (`fetch::MAX_ARTIFACT_BYTES`): 4 MiB.
const int maxWebsArtifactBytes = 4 * 1024 * 1024;

/// Why a did:webs DID did not resolve.
///
/// [kind] is the `affinidi-did-webs` `DidWebsError` variant: `InvalidDid`,
/// `Fetch`, `Stream`, `Kel`, `DocumentMismatch`, `NotDesignated`, `Registry`,
/// `UnsupportedDesignation` (a critical designation this resolver does not
/// implement), `InvalidKey`, `Json`, or `Deactivated` (network resolution
/// only: the DID's last rotation committed to no next keys). A host the
/// egress policy refuses throws `BlockedEndpointException` instead.
class DidWebsError extends SsiException {
  /// Creates the error; [message] is prefixed with `did:webs: `.
  DidWebsError(this.kind, String message, {this.status, this.url})
    : super(
        message: 'did:webs: $message',
        code: SsiExceptionType.unableToResolveDid.code,
      );

  /// The `DidWebsError` variant.
  final String kind;

  /// The HTTP status of a failed fetch.
  final int? status;

  /// The URL of a failed fetch.
  final String? url;

  @override
  String toString() => 'DidWebsError($kind): $message';
}

DidWebsError _error(String kind, String message, {int? status, String? url}) =>
    DidWebsError(kind, message, status: status, url: url);

// ─── The identifier (affinidi-did-webs `identifier.rs`, 0.13.2) ─────────

/// A parsed did:webs DID.
class DidWebs {
  DidWebs(this.did, this.versionId, this.host, this.path, this.aid);

  /// The DID, without query or fragment.
  final String did;

  /// The `versionId` parameter, if any.
  final int? versionId;

  /// The host label, percent-decoded (with any port).
  final String host;

  /// The path labels, as written.
  final List<String> path;

  /// The KERI AID, the last label.
  final String aid;
}

DidWebsError _invalid(String did, String why) =>
    _error('InvalidDid', 'invalid did:webs identifier: ${jsonQuote(did)} $why');

final RegExp _hex2 = RegExp(r'^[0-9a-fA-F]{2}$');

String _percentDecode(String label, String did) {
  final out = <int>[];
  for (var i = 0; i < label.length;) {
    if (label[i] == '%') {
      final end = i + 3 > label.length ? label.length : i + 3;
      final hex = label.substring(i + 1, end);
      if (!_hex2.hasMatch(hex)) {
        throw _invalid(
          did,
          'has a malformed percent-encoding in ${jsonQuote(label)}',
        );
      }
      out.add(int.parse(hex, radix: 16));
      i += 3;
    } else {
      final cu = label.codeUnitAt(i);
      final pair =
          cu >= 0xd800 &&
          cu <= 0xdbff &&
          i + 1 < label.length &&
          label.codeUnitAt(i + 1) >= 0xdc00 &&
          label.codeUnitAt(i + 1) <= 0xdfff;
      final ch = label.substring(i, i + (pair ? 2 : 1));
      out.addAll(utf8.encode(ch));
      i += ch.length;
    }
  }
  try {
    return fromUtf8(out);
  } on FormatException {
    throw _invalid(did, 'has a label that is not UTF-8: ${jsonQuote(label)}');
  }
}

bool _isControl(int c) => c <= 0x1f || (c >= 0x7f && c <= 0x9f);

const Set<int> _whitespace = {
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, //
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
  0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
};

(String, String?) _splitHostPort(String authority) {
  if (authority.startsWith('[')) {
    final end = authority.indexOf(']');
    if (end < 0) return (authority, null);
    final host = authority.substring(0, end + 1);
    final rest = authority.substring(end + 1);
    if (rest.startsWith(':')) return (host, rest.substring(1));
    if (rest == '') return (host, null);
    return (authority, null);
  }
  final colon = authority.indexOf(':');
  return colon < 0
      ? (authority, null)
      : (authority.substring(0, colon), authority.substring(colon + 1));
}

// ─── Hosts as the WHATWG URL parser reads them ──────────────────────────

/// A host the URL parser refuses ("Invalid URL").
class _InvalidUrl implements Exception {}

/// WHATWG IPv6 parser: eight pieces, or null.
List<int>? _parseIpv6(String input) {
  final address = List<int>.filled(8, 0);
  var pieceIndex = 0;
  int? compress;
  var p = 0;
  final n = input.length;
  int? c(int i) => i < n ? input.codeUnitAt(i) : null;
  bool isHex(int? x) =>
      x != null &&
      ((x >= 0x30 && x <= 0x39) ||
          (x >= 0x41 && x <= 0x46) ||
          (x >= 0x61 && x <= 0x66));
  bool isDigit(int? x) => x != null && x >= 0x30 && x <= 0x39;
  if (c(p) == 0x3a) {
    if (c(p + 1) != 0x3a) return null;
    p += 2;
    pieceIndex++;
    compress = pieceIndex;
  }
  while (c(p) != null) {
    if (pieceIndex == 8) return null;
    if (c(p) == 0x3a) {
      if (compress != null) return null;
      p++;
      pieceIndex++;
      compress = pieceIndex;
      continue;
    }
    var value = 0;
    var length = 0;
    while (length < 4 && isHex(c(p))) {
      value = value * 0x10 + int.parse(input[p], radix: 16);
      p++;
      length++;
    }
    if (c(p) == 0x2e) {
      if (length == 0) return null;
      p -= length;
      if (pieceIndex > 6) return null;
      var numbersSeen = 0;
      while (c(p) != null) {
        int? ipv4Piece;
        if (numbersSeen > 0) {
          if (c(p) == 0x2e && numbersSeen < 4) {
            p++;
          } else {
            return null;
          }
        }
        if (!isDigit(c(p))) return null;
        while (isDigit(c(p))) {
          final number = c(p)! - 0x30;
          if (ipv4Piece == null) {
            ipv4Piece = number;
          } else if (ipv4Piece == 0) {
            return null;
          } else {
            ipv4Piece = ipv4Piece * 10 + number;
          }
          if (ipv4Piece > 255) return null;
          p++;
        }
        address[pieceIndex] = address[pieceIndex] * 0x100 + ipv4Piece!;
        numbersSeen++;
        if (numbersSeen == 2 || numbersSeen == 4) pieceIndex++;
      }
      if (numbersSeen != 4) return null;
      break;
    } else if (c(p) == 0x3a) {
      p++;
      if (c(p) == null) return null;
    } else if (c(p) != null) {
      return null;
    }
    address[pieceIndex] = value;
    pieceIndex++;
  }
  if (compress != null) {
    var swaps = pieceIndex - compress;
    pieceIndex = 7;
    while (pieceIndex != 0 && swaps > 0) {
      final t = address[pieceIndex];
      address[pieceIndex] = address[compress + swaps - 1];
      address[compress + swaps - 1] = t;
      pieceIndex--;
      swaps--;
    }
  } else if (pieceIndex != 8) {
    return null;
  }
  return address;
}

String _serializeIpv6(List<int> a) {
  // The first longest run of two or more zero pieces is compressed.
  var best = -1;
  var bestLen = 1;
  for (var i = 0; i < 8;) {
    if (a[i] != 0) {
      i++;
      continue;
    }
    var j = i;
    while (j < 8 && a[j] == 0) {
      j++;
    }
    if (j - i > bestLen) {
      best = i;
      bestLen = j - i;
    }
    i = j;
  }
  final out = StringBuffer();
  var ignore0 = false;
  for (var i = 0; i < 8; i++) {
    if (ignore0 && a[i] == 0) continue;
    ignore0 = false;
    if (best == i) {
      out.write(i == 0 ? '::' : ':');
      ignore0 = true;
      continue;
    }
    out.write(a[i].toRadixString(16));
    if (i != 7) out.write(':');
  }
  return out.toString();
}

/// WHATWG "ends in a number".
bool _endsInNumber(String host) {
  final parts = host.split('.');
  if (parts.last.isEmpty) {
    if (parts.length == 1) return false;
    parts.removeLast();
  }
  final last = parts.last;
  if (last.isNotEmpty && RegExp(r'^[0-9]+$').hasMatch(last)) return true;
  return RegExp(r'^0[xX][0-9a-fA-F]*$').hasMatch(last);
}

BigInt? _ipv4Number(String input) {
  if (input.isEmpty) return null;
  var text = input;
  var radix = 10;
  if (text.length >= 2 && (text.startsWith('0x') || text.startsWith('0X'))) {
    text = text.substring(2);
    radix = 16;
  } else if (text.length >= 2 && text.startsWith('0')) {
    text = text.substring(1);
    radix = 8;
  }
  if (text.isEmpty) return BigInt.zero;
  final pattern = switch (radix) {
    16 => RegExp(r'^[0-9a-fA-F]+$'),
    8 => RegExp(r'^[0-7]+$'),
    _ => RegExp(r'^[0-9]+$'),
  };
  if (!pattern.hasMatch(text)) return null;
  return BigInt.parse(text, radix: radix);
}

String _parseIpv4(String host) {
  final parts = host.split('.');
  if (parts.last.isEmpty && parts.length > 1) parts.removeLast();
  if (parts.length > 4) throw _InvalidUrl();
  final numbers = <BigInt>[];
  for (final part in parts) {
    final n = _ipv4Number(part);
    if (n == null) throw _InvalidUrl();
    numbers.add(n);
  }
  final b255 = BigInt.from(255);
  for (var i = 0; i < numbers.length - 1; i++) {
    if (numbers[i] > b255) throw _InvalidUrl();
  }
  if (numbers.last >= BigInt.from(256).pow(5 - numbers.length)) {
    throw _InvalidUrl();
  }
  var ipv4 = numbers.last;
  for (var i = 0; i < numbers.length - 1; i++) {
    ipv4 += numbers[i] * BigInt.from(256).pow(3 - i);
  }
  final v = ipv4.toInt();
  return '${v >> 24 & 255}.${v >> 16 & 255}.${v >> 8 & 255}.${v & 255}';
}

const String _forbiddenDomain = '\u0000\t\n\r #%/:<>?@[\\]^|\u007f';

/// The host (without port) as the URL parser serializes it.
String _canonicalHost(String host) {
  if (host.startsWith('[')) {
    if (!host.endsWith(']')) throw _InvalidUrl();
    final a = _parseIpv6(host.substring(1, host.length - 1));
    if (a == null) throw _InvalidUrl();
    return '[${_serializeIpv6(a)}]';
  }
  if (host.isEmpty) throw _InvalidUrl();
  for (final c in host.codeUnits) {
    if (c < 0x20 || _forbiddenDomain.codeUnits.contains(c)) {
      throw _InvalidUrl();
    }
  }
  final lower = host.toLowerCase();
  if (_endsInNumber(lower)) return _parseIpv4(lower);
  return lower;
}

/// The authority as the URL parser serializes it under [scheme].
String _canonicalAuthority(String authority, String scheme) {
  final (host, port) = _splitHostPort(authority);
  final h = _canonicalHost(host);
  if (port == null || port.isEmpty) return h;
  final n = int.parse(port);
  final defaultPort = scheme == 'https' ? 443 : 80;
  return n == defaultPort ? h : '$h:$n';
}

bool _isIpv6(String literal) =>
    _parseIpv6(literal) != null && !literal.contains('%');

void _validateHost(String authority, String did) {
  DidWebsError bad(String why) =>
      _invalid(did, 'does not name a host ($why): ${jsonQuote(authority)}');
  final (host, port) = _splitHostPort(authority);
  if (host == '') throw bad('empty host');
  if (port != null &&
      (!RegExp(r'^[0-9]+$').hasMatch(port) ||
          BigInt.parse(port) > BigInt.from(65535))) {
    throw bad('the port is not a port number');
  }
  if (host.startsWith('[') && host.endsWith(']')) {
    if (!_isIpv6(host.substring(1, host.length - 1))) {
      throw bad('not an IPv6 address');
    }
  } else if (host.runes.any(
    (c) =>
        _isControl(c) ||
        _whitespace.contains(c) ||
        r'/\?#@%:[]'.runes.contains(c),
  )) {
    throw bad('a character a host cannot contain');
  }
  if (host.runes.any((c) => c > 0x7f)) {
    throw bad('an internationalized host name is not supported');
  }
  try {
    _canonicalHost(host);
  } on _InvalidUrl {
    throw bad('Invalid URL');
  }
}

void _validatePathSegment(String segment, String did) {
  if (segment == '.' ||
      segment == '..' ||
      segment.runes.any((c) => _isControl(c) || r'/\?#@%'.runes.contains(c))) {
    throw _invalid(
      did,
      'has a path label that is not a single path segment: '
      '${jsonQuote(segment)}',
    );
  }
}

final RegExp _versionIdPattern = RegExp(r'^\+?[0-9]+$');
final RegExp _aidAlphabet = RegExp(r'^[A-Za-z0-9_-]+$');

/// Parse a did:webs DID or DID URL (`DidWebs::parse`). A `versionId` query
/// parameter is the sequence number of the key event to resolve as of.
///
/// Throws a [DidWebsError] of kind `InvalidDid`.
DidWebs parseDidWebs(String did) {
  if (!did.startsWith('did:webs:')) {
    throw _invalid(
      did.length > 80 ? did.substring(0, 80) : did,
      "does not start with 'did:webs:'",
    );
  }
  var rest = did.substring('did:webs:'.length).split('#').first;
  String? query;
  final q = rest.indexOf('?');
  if (q >= 0) {
    query = rest.substring(q + 1);
    rest = rest.substring(0, q);
  }
  if (rest == '') {
    throw _invalid(did, 'has an empty method-specific identifier');
  }
  int? versionId;
  if (query != null) {
    for (final pair in query.split('&')) {
      final eq = pair.indexOf('=');
      final key = eq < 0 ? pair : pair.substring(0, eq);
      final value = eq < 0 ? '' : pair.substring(eq + 1);
      if (key == 'versionId') {
        final n = _versionIdPattern.hasMatch(value)
            ? BigInt.parse(value.replaceFirst('+', ''))
            : null;
        if (n == null || n > u64Max) {
          throw _invalid(
            did,
            'has a versionId that is not a sequence number: '
            '${jsonQuote(value)}',
          );
        }
        // Beyond 2^53 no key event log can reach it.
        versionId = n > BigInt.from(maxSafeInteger)
            ? maxSafeInteger
            : n.toInt();
        break;
      }
    }
  }
  final labels = rest.split(':');
  if (labels.length < 2) {
    throw _invalid(
      did,
      'has no AID: did:webs requires a host and a trailing AID',
    );
  }
  if (labels.any((l) => l == '')) {
    throw _invalid(did, 'contains an empty label');
  }
  final aid = labels.last;
  if (utf8.encode(aid).length < 4) {
    throw _invalid(
      did,
      'has an AID too short to be a CESR primitive: ${jsonQuote(aid)}',
    );
  }
  if (!_aidAlphabet.hasMatch(aid)) {
    throw _invalid(
      did,
      'has an AID with characters outside the CESR base64url alphabet: '
      '${jsonQuote(aid)}',
    );
  }
  final host = _percentDecode(labels.first, did);
  _validateHost(host, did);
  final path = labels.sublist(1, labels.length - 1);
  for (final segment in path) {
    _validatePathSegment(_percentDecode(segment, did), did);
  }
  return DidWebs('did:webs:$rest', versionId, host, path, aid);
}

/// Whether the DID's host is loopback, as a URL parser reads it.
bool isLoopbackDidWebs(DidWebs parsed) {
  try {
    final host = _canonicalHost(_splitHostPort(parsed.host).$1);
    return host == 'localhost' || host == '127.0.0.1' || host == '[::1]';
  } on _InvalidUrl {
    return false;
  }
}

// The path percent-encode set, less what a label cannot hold.
bool _pathEncoded(int c) =>
    c <= 0x20 ||
    c >= 0x7f ||
    c == 0x22 ||
    c == 0x23 ||
    c == 0x3c ||
    c == 0x3e ||
    c == 0x3f ||
    c == 0x60 ||
    c == 0x7b ||
    c == 0x7d;

String _encodePathSegment(String segment) {
  final out = StringBuffer();
  for (final b in utf8.encode(segment)) {
    if (_pathEncoded(b)) {
      out.write('%${b.toRadixString(16).toUpperCase().padLeft(2, '0')}');
    } else {
      out.writeCharCode(b);
    }
  }
  return out.toString();
}

/// The URL of [artifact] for a did:webs DID, as the URL parser serializes it
/// (`href`).
String websArtifactHref(DidWebs parsed, String scheme, String artifact) {
  final authority = _canonicalAuthority(parsed.host, scheme);
  final path = [
    ...parsed.path,
    parsed.aid,
    artifact,
  ].map(_encodePathSegment).join('/');
  return '$scheme://$authority/$path';
}

String _didWebTwin(DidWebs parsed) =>
    'did:web:${parsed.did.substring('did:webs:'.length)}';
String _didKeri(DidWebs parsed) => 'did:keri:${parsed.aid}';

// ─── Percent-encoding and DID comparison (`document.rs`) ────────────────

final RegExp _pct = RegExp('%([0-9a-fA-F]{2})');

/// Uppercase the hex digits of every percent-encoded triplet (RFC 3986
/// §6.2.2.1).
String _normalizePercent(String s) =>
    s.replaceAllMapped(_pct, (m) => '%${m[1]!.toUpperCase()}');

bool _sameDid(String a, String b) =>
    _normalizePercent(a) == _normalizePercent(b);

// ─── Plain JSON helpers ─────────────────────────────────────────────────

typedef _Json = Map<String, Object?>;

Object? _clone(Object? v) {
  if (v is Map) {
    return <String, Object?>{
      for (final e in v.entries) e.key as String: _clone(e.value),
    };
  }
  if (v is List) return [for (final x in v) _clone(x)];
  return v;
}

List<Object?> _asArray(Object? v) => v is List ? v : const [];

String _numberText(num n) {
  if (n is int) return '$n';
  if (n == n.truncateToDouble() && n.abs() < 1e21) {
    return BigInt.from(n).toString();
  }
  return '$n';
}

/// `JSON.stringify` of a plain JSON value.
String _stringify(Object? v) {
  if (v == null) return 'null';
  if (v is String) return jsonQuote(v);
  if (v is bool) return '$v';
  if (v is num) return _numberText(v);
  if (v is List) return '[${v.map(_stringify).join(',')}]';
  if (v is Map) {
    return '{${v.entries.map((e) => '${jsonQuote(e.key as String)}:${_stringify(e.value)}').join(',')}}';
  }
  return jsonQuote('$v');
}

/// serde_json `Value` equality: objects as maps, arrays in order.
bool _jsonEqual(Object? a, Object? b) {
  if (a is num && b is num) return a == b;
  if (a is List && b is List) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (!_jsonEqual(a[i], b[i])) return false;
    }
    return true;
  }
  if (a is Map && b is Map) {
    if (a.length != b.length) return false;
    for (final k in a.keys) {
      if (!b.containsKey(k) || !_jsonEqual(a[k], b[k])) return false;
    }
    return true;
  }
  if (a is Map || b is Map || a is List || b is List) return false;
  return a == b;
}

bool _sameSet<T>(List<T> a, List<T> b, [bool Function(T, T)? eq]) {
  final same = eq ?? (T x, T y) => x == y;
  return a.every((x) => b.any((y) => same(x, y))) &&
      b.every((x) => a.any((y) => same(x, y)));
}

Object? _jsNumber(BigInt n) =>
    n.abs() <= BigInt.from(maxSafeInteger) ? n.toInt() : n.toDouble();

// ─── The document (affinidi-did-webs `document.rs`) ─────────────────────

const List<String> _relationships = [
  'authentication',
  'assertionMethod',
  'keyAgreement',
  'capabilityInvocation',
  'capabilityDelegation',
];

/// The `ConditionalProof2022` method for a threshold above one key, or null.
_Json? _thresholdCondition(
  DidWebs parsed,
  List<String> keys,
  Threshold threshold,
) {
  _Json base(_Json extra) => {
    'id': '#${parsed.aid}',
    'type': 'ConditionalProof2022',
    'controller': parsed.did,
    ...extra,
  };
  switch (threshold) {
    case SimpleThreshold(:final n):
      if (n <= BigInt.one) return null;
      return base({
        'threshold': _jsNumber(n),
        'conditionThreshold': [for (final k in keys) '#$k'],
      });
    case WeightedThreshold(:final clauses):
      if (clauses.length != 1) {
        throw _error(
          'Kel',
          'key event log verification failed: a weighted threshold with '
              '${clauses.length} clauses cannot be expressed as one '
              'ConditionalProof2022',
        );
      }
      final clause = clauses.single;
      if (clause.length != keys.length) {
        throw _error(
          'Kel',
          'key event log verification failed: weighted threshold has '
              '${clause.length} weights for ${keys.length} keys',
        );
      }
      var lcd = BigInt.one;
      for (final w in clause) {
        lcd = (lcd ~/ lcd.gcd(w.den)) * w.den;
        if (lcd >= BigInt.one << 64) {
          throw _error(
            'Kel',
            'key event log verification failed: weighted threshold overflows',
          );
        }
      }
      return base({
        'threshold': _jsNumber(lcd),
        'conditionWeightedThreshold': [
          for (var i = 0; i < keys.length; i++)
            {
              'condition': '#${keys[i]}',
              'weight': _jsNumber(clause[i].num * (lcd ~/ clause[i].den)),
            },
        ],
      });
  }
}

_Json _keyMethod(
  DidWebs parsed,
  String key,
  _Json jwk, [
  _Json extra = const {},
]) => {
  'id': '#$key',
  'type': 'JsonWebKey',
  'controller': parsed.did,
  'publicKeyJwk': jwk,
  ...extra,
};

/// The document implied by verified key state (`derive_document`).
_Json _deriveDocument(
  DidWebs parsed,
  List<String> keys,
  Threshold threshold,
  List<String> aliases,
  List<Object?> services,
) {
  if (keys.isEmpty) {
    throw _error(
      'Kel',
      'key event log verification failed: verified key state has no signing '
          'keys',
    );
  }
  final methods = <Object?>[
    for (final key in keys)
      () {
        try {
          return _keyMethod(parsed, key, jwkFromCesrKey(key));
        } on Exception catch (e) {
          throw _error(
            'Kel',
            'key event log verification failed: ${reasonOf(e)}',
          );
        }
      }(),
  ];
  final condition = _thresholdCondition(parsed, keys, threshold);
  List<String> referenced;
  if (condition != null) {
    methods.add(condition);
    referenced = [condition['id']! as String];
  } else {
    referenced = [for (final k in keys) '#$k'];
  }
  return {
    'id': parsed.did,
    'controller': parsed.did,
    'verificationMethod': methods,
    'authentication': [...referenced],
    'assertionMethod': [...referenced],
    'service': [...services],
    'alsoKnownAs': [...aliases],
  };
}

/// The document of an identifier that designates key roles.
_Json _deriveKeyRoleDocument(
  DidWebs parsed,
  List<(KeyRole, List<String>)> roles,
  List<RevokedKey> revoked,
  List<String> aliases,
  List<Object?> services,
) {
  final methods = <Object?>[];
  final keyRolesOut = <String, Object?>{};
  final relationships = <String, List<Object?>>{
    'authentication': [],
    'assertionMethod': [],
    'keyAgreement': [],
  };
  for (final (role, keys) in roles) {
    if (keys.isEmpty) continue;
    final ids = <String>[];
    for (final key in keys) {
      _Json jwk;
      try {
        jwk = roleKeyJwk(role.name, key);
      } on Exception catch (e) {
        throw _error('InvalidKey', 'invalid key: ${reasonOf(e)}');
      }
      methods.add(_keyMethod(parsed, key, jwk));
      ids.add('#$key');
    }
    relationships[role.relationship]!.addAll(ids);
    keyRolesOut[role.name] = ids;
  }
  for (final entry in revoked) {
    _Json jwk;
    try {
      jwk = revokedKeyJwk(entry.key);
    } on Exception catch (e) {
      throw _error('InvalidKey', 'invalid key: ${reasonOf(e)}');
    }
    methods.add(
      _keyMethod(parsed, entry.key, jwk, {'revoked': entry.compromisedAt}),
    );
  }
  return {
    'id': parsed.did,
    'controller': parsed.did,
    'verificationMethod': methods,
    'authentication': relationships['authentication'],
    'assertionMethod': relationships['assertionMethod'],
    if (relationships['keyAgreement']!.isNotEmpty)
      'keyAgreement': relationships['keyAgreement'],
    'keyRoles': keyRolesOut,
    'service': [...services],
    'alsoKnownAs': [...aliases],
  };
}

/// Add key agreement keys to a document (`with_key_agreement`).
_Json _withKeyAgreement(_Json doc, DidWebs parsed, List<String> keys) {
  if (keys.isEmpty) return doc;
  final out = _clone(doc)! as _Json;
  for (final key in keys) {
    _Json jwk;
    try {
      jwk = keyAgreementJwk(keyAgreementKey(key));
    } on Exception catch (e) {
      throw _error('InvalidKey', 'invalid key: ${reasonOf(e)}');
    }
    final methods = out['verificationMethod'];
    if (methods is List) methods.add(_keyMethod(parsed, key, jwk));
  }
  out['keyAgreement'] = [for (final k in keys) '#$k'];
  return out;
}

/// Rewrite the subject-identifying DIDs of a document from [from] to [to].
_Json _swapSubject(_Json doc, String from, String to) {
  final out = _clone(doc)! as _Json;
  for (final f in const ['id', 'controller']) {
    if (out[f] is String) out[f] = to;
  }
  final methods = out['verificationMethod'];
  if (methods is List) {
    for (final m in methods) {
      if (m is Map &&
          m['controller'] is String &&
          _sameDid(m['controller']! as String, from)) {
        m['controller'] = to;
      }
    }
  }
  final aka = out['alsoKnownAs'];
  if (aka is List) {
    out['alsoKnownAs'] = [
      for (final a in aka) a is String && _sameDid(a, to) ? from : a,
    ];
  }
  return out;
}

/// A published document back in its did:webs form (`from_did_web`).
_Json _fromDidWeb(Object? doc, DidWebs parsed, bool twinDesignated) {
  final id = doc is Map ? doc['id'] : null;
  if (id is! String) {
    throw _error(
      'DocumentMismatch',
      'did.json does not match the verified key state: did.json has no `id`',
    );
  }
  final twin = _didWebTwin(parsed);
  final map = doc! as _Json;
  if (_sameDid(id, parsed.did)) return map;
  if (_sameDid(id, twin)) {
    if (!twinDesignated) {
      throw _error(
        'DocumentMismatch',
        'did.json does not match the verified key state: did.json is the '
            'did:web document ${jsonQuote(id)}, but no designated-aliases '
            'attestation authorises that identifier',
      );
    }
    return _swapSubject(map, id, parsed.did);
  }
  throw _error(
    'DocumentMismatch',
    'did.json does not match the verified key state: did.json is for '
        '${jsonQuote(id)}, which is neither ${jsonQuote(parsed.did)} nor its '
        'did:web twin ${jsonQuote(twin)}',
  );
}

Object? _absolutize(Object? value, String subject) {
  if (value is! String) return value;
  if (value.startsWith('#')) return '$subject$value';
  if (!value.contains(':')) return '$subject#$value';
  return value;
}

/// The did:webs form of a document as the resolved DID document: every
/// relative reference resolved against the subject (`into_document`), and
/// its empty lists left out.
_Json _intoDocument(_Json doc, DidWebs parsed) {
  final subject = parsed.did;
  final out = _clone(doc)! as _Json;
  final methods = out['verificationMethod'];
  if (methods is List) {
    for (final m in methods) {
      if (m is! Map) continue;
      if (m.containsKey('id')) m['id'] = _absolutize(m['id'], subject);
      final ct = m['conditionThreshold'];
      if (ct is List) {
        m['conditionThreshold'] = [for (final r in ct) _absolutize(r, subject)];
      }
      final cwt = m['conditionWeightedThreshold'];
      if (cwt is List) {
        for (final c in cwt) {
          if (c is Map && c.containsKey('condition')) {
            c['condition'] = _absolutize(c['condition'], subject);
          }
        }
      }
    }
  }
  for (final rel in _relationships) {
    final refs = out[rel];
    if (refs is List) {
      out[rel] = [for (final r in refs) _absolutize(r, subject)];
    }
  }
  final services = out['service'];
  if (services is List) {
    for (final s in services) {
      if (s is Map && s.containsKey('id')) {
        s['id'] = _absolutize(s['id'], subject);
      }
    }
  }
  final roles = out['keyRoles'];
  if (roles is Map) {
    for (final role in roles.keys.toList()) {
      final r = roles[role];
      if (r is List) roles[role] = [for (final x in r) _absolutize(x, subject)];
    }
  }
  for (final list in [
    'alsoKnownAs',
    'verificationMethod',
    ..._relationships,
    'service',
  ]) {
    final v = out[list];
    if (v is List && v.isEmpty) out.remove(list);
  }
  return out;
}

// ─── Comparing the published document (`resolver.rs`) ──────────────────

String _relative(String reference, String subject) {
  final norm = _normalizePercent(reference);
  final subj = _normalizePercent(subject);
  if (norm.startsWith(subj) && norm.substring(subj.length).startsWith('#')) {
    return norm.substring(subj.length);
  }
  return norm;
}

Object? _normalized(Object? value, String subject) {
  if (value is String) {
    if (_sameDid(value, subject)) return subject;
    if (value.contains('#')) return _relative(value, subject);
    return value;
  }
  if (value is List) return [for (final v in value) _normalized(v, subject)];
  if (value is Map) {
    return <String, Object?>{
      for (final e in value.entries)
        e.key as String: _normalized(e.value, subject),
    };
  }
  return value;
}

List<(String, Object?)> _keyed(Object? methods, String subject) => [
  for (final m in _asArray(methods))
    if (m is Map && m['id'] is String)
      (_relative(m['id']! as String, subject), m),
];

List<String> _refs(Object? value, String subject) => [
  for (final r in _asArray(value))
    if (r is String)
      _relative(r, subject)
    else if (r is Map && r['id'] is String)
      _relative(r['id']! as String, subject),
];

/// A service's types as a sorted set: a `type` written as one string is the
/// set holding it. Anything that is not a string is kept out, so a malformed
/// `type` compares as no type rather than as some other one.
List<String> _serviceTypes(Object? service) {
  final raw = service is Map ? service['type'] : null;
  final list = raw is String
      ? [raw]
      : raw is List
      ? raw.whereType<String>().toList()
      : const <String>[];
  return list.toSet().toList()..sort();
}

/// Whether [service] is a `DelegatorOOBI` endpoint, however its `type` is
/// written.
bool _isDelegatorOobi(Object? service) =>
    _serviceTypes(service).contains('DelegatorOOBI');

class _Derived {
  _Derived({
    required this.document,
    required this.metadata,
    required this.twinDesignated,
    required this.delegationSeal,
    required this.convertedKeyAgreement,
    required this.retired,
  });

  final _Json document;
  final _Metadata metadata;
  final bool twinDesignated;
  final String? delegationSeal;
  final List<String> convertedKeyAgreement;
  final bool retired;

  _Derived withDocument(_Json doc) => _Derived(
    document: doc,
    metadata: metadata,
    twinDesignated: twinDesignated,
    delegationSeal: delegationSeal,
    convertedKeyAgreement: convertedKeyAgreement,
    retired: retired,
  );
}

class _Metadata {
  _Metadata(
    this.versionId,
    this.nextVersionId,
    this.equivalentId,
    this.deactivated,
  );
  final int versionId;
  final int? nextVersionId;
  final List<String> equivalentId;
  final bool deactivated;
}

/// Check a published document, in its did:webs form, against the derivation.
void _checkPublished(_Derived derived, Object? theirs) {
  final ours = derived.document;
  final subject = ours['id']! as String;
  DidWebsError mismatch(String what) => _error(
    'DocumentMismatch',
    'did.json does not match the verified key state: $what',
  );
  if (theirs is! Map) throw mismatch('did.json is not a JSON object');

  for (final member in theirs.keys) {
    final known =
        const [
          '@context',
          'id',
          'controller',
          'verificationMethod',
          'service',
          'alsoKnownAs',
        ].contains(member) ||
        _relationships.contains(member) ||
        (member == 'keyRoles' && ours.containsKey('keyRoles'));
    if (!known) {
      throw mismatch(
        'did.json carries ${jsonQuote(member as String)}, which nothing in '
        'the key event stream establishes',
      );
    }
  }

  if (theirs.containsKey('controller') &&
      (theirs['controller'] is! String ||
          !_sameDid(theirs['controller']! as String, subject))) {
    throw mismatch(
      'did.json names ${_stringify(theirs['controller'])} as controller, '
      'not ${jsonQuote(subject)}',
    );
  }

  final ourMethods = _keyed(ours['verificationMethod'], subject);
  final theirMethods = _keyed(theirs['verificationMethod'], subject);
  for (final (id, method) in theirMethods) {
    final match = ourMethods.where((m) => m.$1 == id).firstOrNull;
    if (match == null) {
      throw mismatch(
        'did.json publishes ${jsonQuote(id)}, which the verified key event '
        'log never authorised',
      );
    }
    if (!_jsonEqual(
      _normalized(match.$2, subject),
      _normalized(method, subject),
    )) {
      throw mismatch(
        'did.json publishes ${jsonQuote(id)} differently from the verified '
        'key state',
      );
    }
  }
  for (final (id, _) in ourMethods) {
    if (!theirMethods.any((m) => m.$1 == id)) {
      throw mismatch(
        'did.json does not publish ${jsonQuote(id)}, which the verified key '
        'state authorises',
      );
    }
  }

  for (final relationship in _relationships) {
    final ourRefs = _refs(ours[relationship], subject);
    if (!theirs.containsKey(relationship)) {
      if (ourRefs.isEmpty ||
          relationship == 'authentication' ||
          relationship == 'assertionMethod') {
        continue;
      }
      throw mismatch('did.json does not publish $relationship');
    }
    final theirRefs = _refs(theirs[relationship], subject);
    if (!_sameSet(ourRefs, theirRefs)) {
      throw mismatch(
        "did.json's $relationship is ${_stringify(theirRefs)}, but the "
        'verified state implies ${_stringify(ourRefs)}',
      );
    }
  }

  final ourRoles = ours['keyRoles'];
  if (ourRoles is Map) {
    final theirRoles = theirs['keyRoles'];
    if (theirRoles is! Map) {
      throw mismatch('did.json does not publish keyRoles');
    }
    final same =
        ourRoles.length == theirRoles.length &&
        ourRoles.entries.every(
          (e) =>
              theirRoles.containsKey(e.key) &&
              _sameSet(
                _refs(e.value, subject),
                _refs(theirRoles[e.key], subject),
              ),
        );
    if (!same) {
      throw mismatch(
        "did.json's keyRoles differ from those the AID designated",
      );
    }
  }

  // A service's `type` is a string or a set of strings (DID Core §5.4), so
  // "X" and ["X"] are one type: it is compared as a sorted set, never as the
  // JSON it was written as. A `DelegatorOOBI` endpoint is matched by id and
  // type only.
  Object? serviceKey(Object? s) {
    if (s is! Map) return _normalized(s, subject);
    final type = _serviceTypes(s);
    if (_isDelegatorOobi(s)) return {'id': s['id'], 'type': type};
    return {
      ...(_normalized(s, subject)! as Map<String, Object?>),
      'type': type,
    };
  }

  final ourServices = _asArray(ours['service']).map(serviceKey).toList();
  final optionalDelegator =
      derived.delegationSeal != null &&
          ourServices.every((s) => !_isDelegatorOobi(s))
      ? {
          'id': derived.delegationSeal,
          'type': ['DelegatorOOBI'],
        }
      : null;
  final theirServices = _asArray(theirs['service']).map(serviceKey).toList();
  bool contains(List<Object?> list, Object? s) =>
      list.any((x) => _jsonEqual(x, s));
  final unexpected = theirServices.any(
    (s) =>
        !contains(ourServices, s) &&
        !(optionalDelegator != null && _jsonEqual(optionalDelegator, s)),
  );
  final missing = ourServices.any((s) => !contains(theirServices, s));
  if (unexpected || missing) {
    throw mismatch(
      "did.json's services differ from those the stream authorises",
    );
  }

  List<String> aliases(Object? v) {
    final out = <String>[];
    for (final alias in _asArray(v)) {
      if (alias is! String) continue;
      final norm = _normalizePercent(alias);
      if (!_sameDid(alias, subject) && !out.contains(norm)) out.add(norm);
    }
    return out;
  }

  var ourAliases = aliases(ours['alsoKnownAs']);
  final theirAliases = aliases(theirs['alsoKnownAs']);
  // The did:keri form is implied by the AID; leaving it out adds nothing.
  final keri = 'did:keri:${subject.split(':').last}';
  if (!theirAliases.contains(keri)) {
    ourAliases = ourAliases.where((a) => a != keri).toList();
  }
  if (!_sameSet(ourAliases, theirAliases)) {
    throw mismatch(
      "did.json's alsoKnownAs is ${_stringify(theirAliases)}, but the AID "
      'designated ${_stringify(ourAliases)}',
    );
  }
}

/// What a deactivated identifier's document keeps: its subject and aliases
/// (`deactivated_document`).
_Json _deactivatedDocument(_Json doc) => {
  for (final member in const ['@context', 'id', 'alsoKnownAs'])
    if (doc.containsKey(member)) ...{member: _clone(doc[member])},
};

/// Use a published `DelegatorOOBI` service when the stream gave none.
void _carryDelegatorService(_Derived derived, _Json published, _Json document) {
  if (derived.delegationSeal == null ||
      _asArray(document['service']).any(_isDelegatorOobi)) {
    return;
  }
  final delegator = _asArray(
    published['service'],
  ).where(_isDelegatorOobi).firstOrNull;
  final services = document['service'];
  if (delegator != null && services is List) services.add(delegator);
}

// ─── Derivation (`resolver.rs::derive`) ─────────────────────────────────

/// Run [fn], reporting the KERI layer's failures as the Rust does.
T _kel<T>(T Function() fn) {
  try {
    return fn();
  } on DidWebsError {
    rethrow;
  } on StreamError catch (e) {
    throw _error('Stream', 'keri.cesr could not be read: ${e.message}');
  } on RegistryError catch (e) {
    throw _error('Registry', 'designation registry: ${e.message}');
  } on InvalidKeyError catch (e) {
    throw _error('InvalidKey', 'invalid key: ${e.message}');
  } on KelError catch (e) {
    throw _error('Kel', 'key event log verification failed: ${e.message}');
  } on KeriError catch (e) {
    throw _error('Kel', 'key event log verification failed: ${e.message}');
  }
}

_Derived _derive(DidWebs parsed, Uint8List keriCesr) {
  final aid = parsed.aid;
  return _kel(() {
    final full = Kels.parse(keriCesr);
    final current = full.keyState(aid);
    if (current.prefix != aid) {
      throw KelError(
        'verified key state is for ${current.prefix}, not the AID in the DID '
        '($aid)',
      );
    }
    final sequenceNumbers = full.sequenceNumbers(aid);
    final latest = sequenceNumbers.isEmpty
        ? 0
        : sequenceNumbers.reduce((a, b) => a > b ? a : b);
    final version = parsed.versionId ?? latest;
    final kels = parsed.versionId != null && parsed.versionId != latest
        ? full.asOf(aid, parsed.versionId!)
        : full;
    final state = kels.keyState(aid);

    // A critical designation this resolver does not implement fails
    // resolution (P6).
    final critical = unsupportedCritical(kels, aid);
    if (critical != null) {
      throw _error(
        'UnsupportedDesignation',
        'unsupportedDesignation: schema $critical is critical and not '
            'implemented',
      );
    }

    // § Read step 4: the AID must designate this DID.
    final designated = designatedAliases(kels, aid);
    if (!designated.aliases.any((a) => _sameDid(a, parsed.did))) {
      final reason = designated.rejected != null
          ? ' (${designated.rejected})'
          : '';
      throw _error(
        'NotDesignated',
        '${parsed.did} is not designated by its AID: no valid, unrevoked '
            'designated-aliases attestation names it$reason',
      );
    }
    final aliases = <String>[];
    for (final alias in designated.aliases) {
      if (!_sameDid(alias, parsed.did) &&
          !aliases.any((a) => _sameDid(a, alias))) {
        aliases.add(alias);
      }
    }
    if (!aliases.contains(_didKeri(parsed))) aliases.add(_didKeri(parsed));
    final twinDesignated = aliases.any((a) => _sameDid(a, _didWebTwin(parsed)));
    final equivalentId = aliases
        .where((a) => a.startsWith('did:webs:'))
        .toList();

    // Discovery replies are the latest at resolution time; the selected
    // version supplies the witnesses.
    final services = <Object?>[
      for (final e in [
        ...roleEndpoints(full, aid),
        ...witnessEndpoints(full, state.backers),
      ])
        endpointService(e),
    ];
    final delegator = delegatorService(full, aid);
    if (delegator != null) services.add(delegator);
    for (final service in designatedServices(kels, aid).services) {
      final id = toJson(service['id']);
      if (services.every((s) => !_jsonEqual((s! as Map)['id'], id))) {
        services.add(toJson(service));
      }
    }

    // Deactivation is a property of the DID, read from the whole stream; a
    // version is retired when it is the deactivating one.
    int? nextVersionId;
    for (final sn in sequenceNumbers) {
      if (sn > version && (nextVersionId == null || sn < nextVersionId)) {
        nextVersionId = sn;
      }
    }
    final metadata = _Metadata(
      version,
      nextVersionId,
      equivalentId,
      full.isDeactivated(aid),
    );
    final retired = kels.isDeactivated(aid);
    final delegationSeal = state.delegator != null
        ? full.inceptionSaid(aid)
        : null;

    final roles = designatedKeyRoles(kels, aid);
    if (roles.issued) {
      return _Derived(
        document: _deriveKeyRoleDocument(
          parsed,
          roles.roles,
          roles.revoked,
          aliases,
          services,
        ),
        metadata: metadata,
        twinDesignated: twinDesignated,
        delegationSeal: delegationSeal,
        convertedKeyAgreement: const [],
        retired: retired,
      );
    }

    // Designated key agreement keys; a key of the current key state is
    // never one.
    final designatedKa = designatedKeyAgreement(kels, aid);
    final converted =
        designatedKa.issued || designatedKa.rejected != null || retired
        ? const <String>[]
        : convertedKeyAgreement(state.keys);
    final stateRaws = [
      for (final k in state.keys)
        () {
          try {
            return matterFromQb64(k).raw;
          } on KeriError {
            return null;
          }
        }(),
    ];
    final keyAgreement = designatedKa.keys.where((key) {
      KeyAgreementKey designatedKey;
      try {
        designatedKey = keyAgreementKey(key);
      } on Exception {
        return false;
      }
      return !stateRaws.any(
        (raw) =>
            raw != null &&
            raw.length == designatedKey.raw.length &&
            Iterable<int>.generate(
              raw.length,
            ).every((i) => raw[i] == designatedKey.raw[i]),
      );
    }).toList();
    var document = _deriveDocument(
      parsed,
      state.keys,
      state.threshold,
      aliases,
      services,
    );
    document = _withKeyAgreement(document, parsed, keyAgreement);
    return _Derived(
      document: document,
      metadata: metadata,
      twinDesignated: twinDesignated,
      delegationSeal: delegationSeal,
      convertedKeyAgreement: converted,
      retired: retired,
    );
  });
}

_Json _metadataJson(_Metadata m) => {
  'versionId': '${m.versionId}',
  if (m.nextVersionId != null) 'nextVersionId': '${m.nextVersionId}',
  if (m.equivalentId.isNotEmpty) 'equivalentId': m.equivalentId,
  if (m.deactivated) 'deactivated': true,
};

/// A did:webs resolution: the DID document, its resolution metadata and its
/// document metadata, as plain JSON.
class DidWebsResolution {
  DidWebsResolution(
    this.didDocument,
    this.didResolutionMetadata,
    this.didDocumentMetadata,
  );
  final Map<String, Object?> didDocument;
  final Map<String, Object?> didResolutionMetadata;
  final Map<String, Object?> didDocumentMetadata;
}

/// Resolve a did:webs DID from artifacts already fetched
/// (`resolve_with_metadata`). Skips the network; everything else is as for
/// a network resolution.
///
/// [keriCesr] is the only input that carries authority. [didJson] is checked
/// against the derived document and a disagreement fails the resolution. A
/// conforming resolution needs both; null is accepted for verifying a stream
/// offline, and network resolution never passes it.
///
/// Throws a [DidWebsError].
DidWebsResolution resolveDidWebsFromArtifacts(
  String did,
  Uint8List keriCesr, [
  Uint8List? didJson,
]) {
  final parsed = parseDidWebs(did);
  if (keriCesr.length > maxWebsArtifactBytes) {
    throw _error(
      'Stream',
      'keri.cesr could not be read: it is over the '
          '$maxWebsArtifactBytes-byte cap',
    );
  }
  final derived = _derive(parsed, keriCesr);
  var document = _clone(derived.document)! as _Json;

  if (didJson != null) {
    Object? json;
    try {
      json = parseJson(didJson, plain: true);
    } on KeriError catch (e) {
      throw _error('Json', 'JSON error: ${e.message}');
    }
    final published = _fromDidWeb(json, parsed, derived.twinDesignated);
    if (derived.retired) {
      // For the deactivating version a published did.json may be the
      // document without keys, or the full derivation published before.
      try {
        _checkPublished(
          derived.withDocument(_deactivatedDocument(derived.document)),
          published,
        );
      } on DidWebsError {
        _checkPublished(derived, published);
      }
    } else {
      try {
        _checkPublished(derived, published);
      } on DidWebsError catch (e, st) {
        // The converted keys are not part of the derivation the
        // specification defines, so a document published without them
        // agrees, and so does one published with them.
        if (derived.convertedKeyAgreement.isEmpty) rethrow;
        final withConverted = derived.withDocument(
          _withKeyAgreement(
            derived.document,
            parsed,
            derived.convertedKeyAgreement,
          ),
        );
        try {
          _checkPublished(withConverted, published);
        } on DidWebsError {
          Error.throwWithStackTrace(e, st);
        }
      }
    }
    _carryDelegatorService(derived, published, document);
  }
  document = _withKeyAgreement(document, parsed, derived.convertedKeyAgreement);
  if (derived.retired) document = _deactivatedDocument(document);

  return DidWebsResolution(_intoDocument(document, parsed), {
    'contentType': 'application/did+ld+json',
  }, _metadataJson(derived.metadata));
}
