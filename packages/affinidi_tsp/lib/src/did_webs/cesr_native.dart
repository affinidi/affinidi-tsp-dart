// ignore_for_file: public_member_api_docs

part of 'cesr.dart';

// Attachment primitives, indexed signatures, counters and native CESR bodies.
// Port of the matching sections of vti-didcomm-js `src/did-webs-cesr.js`.

// Full sizes of fixed-size codes `affinidi-cesr` does not know but KERI
// attachments carry (affinidi-keri-core `parser::extra_matter_size`).
const Map<String, int> _extraMatter = {
  'M': 4,
  '0H': 8,
  'R': 8,
  'N': 12,
  'S': 16,
  'T': 20,
  'U': 24,
  'a': 44,
  '1AAP': 4,
  '0J': 4,
  '0K': 4,
  'X': 4,
  '0L': 8,
  '0M': 8,
  'Y': 8,
  '1AAN': 12,
};

/// The qb64 of the fixed-size primitive at the head of [text], and its
/// length (affinidi-keri-core `parser::parse_matter_qb64`).
(String, int) readAttachmentMatter(String text, String name) {
  if (text.isEmpty) fail('empty data for $name');
  final hs = hardage(text[0]);
  if (hs == null) fail("unknown hardage for char '${text[0]}' in $name");
  if (text.length < hs) fail('truncated $name code');
  final code = text.substring(0, hs);
  final s = matterSizage(code);
  int fs;
  if (s != null && s.fs > 0) {
    fs = s.fs;
  } else if (s != null) {
    fail('variable-length $name not supported in attachment couples');
  } else {
    final extra = _extraMatter[code];
    if (extra == null) fail('unknown matter code: $code for $name');
    fs = extra;
  }
  if (text.length < fs) fail('truncated $name: need $fs, have ${text.length}');
  return (text.substring(0, fs), fs);
}

// ─── Indexer (affinidi-cesr `indexer.rs`) ───────────────────────────────

class _IdxSize {
  const _IdxSize(this.hs, this.ss, this.fs, this.os, this.rs);
  final int hs;
  final int ss;
  final int fs;
  final int os;
  final int rs;
}

final Map<String, _IdxSize> _indexer = {
  for (final c in ['A', 'B', 'C', 'D', 'E', 'F'])
    c: const _IdxSize(1, 1, 88, 0, 64),
  for (final c in ['0A', '0B']) c: const _IdxSize(2, 2, 156, 1, 114),
  for (final c in ['2A', '2B', '2C', '2D', '2E', '2F'])
    c: const _IdxSize(2, 4, 92, 2, 64),
  for (final c in ['3A', '3B']) c: const _IdxSize(2, 6, 160, 3, 114),
};
const Set<String> _currentOnly = {'B', 'D', 'F', '0B', '2B', '2D', '2F', '3B'};

/// An indexed signature.
class Siger {
  Siger(this.code, this.index, this.ondex, this.raw);
  final String code;
  final int index;

  /// The prior-next index; null for current-only codes.
  final int? ondex;
  final Uint8List raw;
}

/// Read one indexed signature at the head of [text] (affinidi-keri-core
/// `parser::parse_indexed_sig`, `Indexer::from_qb64`, `Indexer::new`).
(Siger, int) readIndexedSig(String text) {
  if (text.isEmpty) fail('empty data for indexed sig');
  final c = text[0];
  final cu = c.codeUnitAt(0);
  final hs = _isLetter(c)
      ? 1
      : (cu >= 0x30 && cu <= 0x34)
      ? 2
      : null;
  if (hs == null) fail("unknown hardage for char '$c' in indexed sig");
  if (hs > text.length) fail('truncated indexer code');
  final code = text.substring(0, hs);
  final s = _indexer[code];
  if (s == null) fail('unknown indexer code: $code');
  if (s.fs > text.length) {
    fail('truncated indexed sig: need ${s.fs}, have ${text.length}');
  }
  final qb64 = text.substring(0, s.fs);
  final ms = s.ss - s.os;
  final index = b64ToInt(qb64.substring(hs, hs + ms)).toInt();
  final ondexChars = qb64.substring(hs + ms, hs + s.ss);
  int? ondex;
  if (_currentOnly.contains(code)) {
    if (s.os > 0 && b64ToInt(ondexChars) != BigInt.zero) {
      fail(
        'failed to parse indexer: current-only code $code carries a non-zero ondex',
      );
    }
    ondex = null;
  } else if (s.os > 0) {
    ondex = b64ToInt(ondexChars).toInt();
  } else {
    ondex = index;
  }
  final cs = s.hs + s.ss;
  final all = b64Decode('A' * cs + qb64.substring(cs, s.fs));
  if (all.length < s.rs) fail('failed to parse indexer: invalid raw size');
  final raw = Uint8List.fromList(all.sublist(all.length - s.rs));
  return (Siger(code, index, ondex, raw), s.fs);
}

// ─── Counters (affinidi-keri-core `counter_table.rs`) ───────────────────

/// A CESR counter.
class Counter {
  Counter(this.code, this.count, this.size);
  final String code;
  final int count;
  final int size;
}

/// Read the counter at the head of [text].
Counter readCounter(String text) {
  if (text.isEmpty || text[0] != '-') fail("a counter starts with '-'");
  if (text.length < 2) fail('truncated counter');
  final second = text[1];
  int hs;
  int ss;
  if (second == '-' || second == '0') {
    (hs, ss) = (3, 5);
  } else if (second == '_') {
    (hs, ss) = (5, 3);
  } else if (_isLetter(second)) {
    (hs, ss) = (2, 2);
  } else {
    fail("no counter code starts with '-$second'");
  }
  final fs = hs + ss;
  if (text.length < fs) {
    fail('truncated counter: need $fs characters, have ${text.length}');
  }
  final head = text.substring(0, fs);
  if (!isAscii(head)) fail('counter is not ASCII');
  int count;
  try {
    count = b64ToInt(head.substring(hs)).toInt();
  } on KeriError catch (e) {
    fail('counter ${jsonQuote(head)}: ${e.message}');
  }
  return Counter(head.substring(0, hs), count, fs);
}

/// The (major, minor) a genus-version counter names, or null.
(int, int)? genusVersion(Counter counter) {
  if (counter.code != '-_AAA') return null;
  final major = counter.count ~/ 4096;
  final minor = counter.count % 4096;
  if (major > 255 || minor > 255) return null;
  return (major, minor);
}

/// The counter table a genus selects (`CounterTable::for_genus`).
String tableForGenus(int major) {
  if (major == 1) return 'V1';
  if (major == 2) return 'V2';
  fail('CESR genus version $major', 'unsupported');
}

const Map<String, Map<String, String>> _groups = {
  'V1': {
    'A': 'ControllerIdxSigs',
    'B': 'WitnessIdxSigs',
    'C': 'NonTransReceiptCouples',
    'D': 'TransReceiptQuadruples',
    'E': 'FirstSeenReplayCouples',
    'F': 'TransIdxSigGroups',
    'G': 'SealSourceCouples',
    'V': 'AttachedMaterialQuadlets',
  },
  'V2': {
    'C': 'AttachedMaterialQuadlets',
    'K': 'ControllerIdxSigs',
    'L': 'WitnessIdxSigs',
    'M': 'NonTransReceiptCouples',
    'O': 'FirstSeenReplayCouples',
    'S': 'SealSourceCouples',
    'X': 'TransIdxSigGroups',
    'a': 'BlindedStateQuadruples',
  },
};

/// What a counter code means in a table (`GroupKind::classify`), or null.
String? classify(String code, String table) {
  String base;
  if (code.startsWith('--')) {
    base = code.substring(2);
  } else if (code.startsWith('-0') && table == 'V1') {
    base = code.substring(2);
  } else if (code.startsWith('-')) {
    base = code.substring(1);
  } else {
    return null;
  }
  return _groups[table]![base];
}

bool _countsQuadlets(String table, String kind) =>
    table == 'V2' || kind == 'AttachedMaterialQuadlets';

String _stripDashes(String code) => code.replaceFirst(RegExp(r'^-+'), '');

// ─── Native CESR bodies (affinidi-keri-core `native.rs`) ─────────────────

Never _nerr(String m) => fail('native CESR body: $m');

class _Sz {
  const _Sz(this.hs, this.ss, this.xs, this.fs, this.ls);
  final int hs;
  final int ss;
  final int xs;

  /// Null for a variable-size code.
  final int? fs;
  final int ls;
}

const Map<String, _Sz> _nativeSizes = {
  'K': _Sz(1, 0, 0, 76, 0),
  'L': _Sz(1, 0, 0, 76, 0),
  'M': _Sz(1, 0, 0, 4, 0),
  'N': _Sz(1, 0, 0, 12, 0),
  'P': _Sz(1, 0, 0, 124, 0),
  'R': _Sz(1, 0, 0, 8, 0),
  'S': _Sz(1, 0, 0, 16, 0),
  'T': _Sz(1, 0, 0, 20, 0),
  'U': _Sz(1, 0, 0, 24, 0),
  'V': _Sz(1, 0, 0, 4, 1),
  'W': _Sz(1, 0, 0, 4, 0),
  'X': _Sz(1, 3, 0, 4, 0),
  'Y': _Sz(1, 7, 0, 8, 0),
  'Z': _Sz(1, 11, 0, 12, 0),
  'b': _Sz(1, 3, 0, 8, 0),
  '0A': _Sz(2, 0, 0, 24, 0),
  '0H': _Sz(2, 0, 0, 8, 0),
  '0J': _Sz(2, 2, 1, 4, 0),
  '0K': _Sz(2, 2, 0, 4, 0),
  '0L': _Sz(2, 6, 1, 8, 0),
  '0M': _Sz(2, 6, 0, 8, 0),
  '0N': _Sz(2, 10, 1, 12, 0),
  '0O': _Sz(2, 10, 0, 12, 0),
  '1AAC': _Sz(4, 0, 0, 80, 0),
  '1AAD': _Sz(4, 0, 0, 80, 0),
  '1AAE': _Sz(4, 0, 0, 156, 0),
  '1AAF': _Sz(4, 4, 0, 8, 0),
  '1AAG': _Sz(4, 0, 0, 36, 0),
  '1AAH': _Sz(4, 0, 0, 100, 0),
  '1AAN': _Sz(4, 8, 0, 12, 0),
  '1__-': _Sz(4, 2, 0, 12, 0),
  '1___': _Sz(4, 0, 0, 8, 0),
  '2__-': _Sz(4, 2, 1, 12, 1),
  '2___': _Sz(4, 0, 0, 8, 1),
  '3__-': _Sz(4, 2, 0, 12, 2),
  '3___': _Sz(4, 0, 0, 8, 2),
};

const List<String> _sz44 = [
  'A',
  'B',
  'C',
  'D',
  'E',
  'F',
  'G',
  'H',
  'I',
  'J',
  'O',
  'Q',
  'a',
];
const List<String> _sz88 = ['0B', '0C', '0D', '0E', '0F', '0G', '0I'];
const List<String> _sz48 = ['1AAA', '1AAB', '1AAI', '1AAJ'];
const List<String> _sz4 = ['1AAK', '1AAL', '1AAM', '1AAO', '1AAP'];

bool _family(String c) => RegExp(r'^[A-FH]$').hasMatch(c);

/// keripy's `Matter.Sizes`.
_Sz? _sizes(String code) {
  if (_sz44.contains(code)) return const _Sz(1, 0, 0, 44, 0);
  final n = _nativeSizes[code];
  if (n != null) return n;
  if (_sz88.contains(code)) return const _Sz(2, 0, 0, 88, 0);
  if (_sz48.contains(code)) return const _Sz(4, 0, 0, 48, 0);
  if (_sz4.contains(code)) return const _Sz(4, 0, 0, 4, 0);
  if (code.length == 2) {
    final c0 = code.codeUnitAt(0);
    if (c0 >= 0x34 && c0 <= 0x36 && _family(code[1])) {
      return _Sz(2, 2, 0, null, c0 - 0x34);
    }
  }
  if (code.length == 4) {
    final c0 = code.codeUnitAt(0);
    if (c0 >= 0x37 &&
        c0 <= 0x39 &&
        code[1] == 'A' &&
        code[2] == 'A' &&
        _family(code[3])) {
      return _Sz(4, 4, 0, null, c0 - 0x37);
    }
  }
  return null;
}

int? _hardSize(String c) {
  if (_isLetter(c)) return 1;
  if (c == '0' || c == '4' || c == '5' || c == '6') return 2;
  if (c == '1' || c == '2' || c == '3' || c == '7' || c == '8' || c == '9') {
    return 4;
  }
  return null;
}

class _NMatter {
  _NMatter(this.code, this.soft, this.raw, this.qb64);
  final String code;
  final String soft;
  final Uint8List raw;
  final String qb64;
}

/// Read the primitive at the head of [buf], as keripy's `Matter._exfil`.
(_NMatter, int) _readMatter(String buf) {
  if (buf.isEmpty) _nerr('a primitive was expected');
  if (buf[0] == '-') _nerr('a counter where a primitive was expected');
  final hs = _hardSize(buf[0]);
  if (hs == null) _nerr('no primitive code starts with ${jsonQuote(buf[0])}');
  if (buf.length < hs) _nerr('truncated primitive');
  final hard = buf.substring(0, hs);
  final s = _sizes(hard);
  if (s == null) _nerr('unknown primitive code ${jsonQuote(hard)}');
  final cs = s.hs + s.ss;
  if (buf.length < cs) _nerr('truncated primitive');
  final softAll = buf.substring(s.hs, cs);
  if (!isB64(softAll)) _nerr('primitive soft part is not Base64');
  final xtra = softAll.substring(0, s.xs);
  final soft = softAll.substring(s.xs);
  if (xtra.split('').any((c) => c != '_')) {
    _nerr('invalid prepad on ${jsonQuote(hard)}');
  }
  final fs = s.fs ?? b64ToInt(soft).toInt() * 4 + cs;
  if (buf.length < fs) _nerr('truncated primitive');
  final full = buf.substring(0, fs);
  if (!isB64(full.substring(cs))) {
    _nerr('${jsonQuote(hard)} material is not Base64');
  }
  final ps = cs % 4;
  Uint8List paw;
  try {
    paw = b64Decode('A' * ps + full.substring(cs));
  } on KeriError catch (e) {
    _nerr('${jsonQuote(hard)}: ${e.message}');
  }
  final lead = ps + s.ls;
  if (paw.length < lead || paw.sublist(0, lead).any((b) => b != 0)) {
    _nerr('${jsonQuote(hard)} has nonzero pad bits');
  }
  final raw = Uint8List.fromList(paw.sublist(lead));
  if (raw.length + s.ls != ((fs - cs) * 3) ~/ 4) {
    _nerr('${jsonQuote(hard)} is improperly qualified');
  }
  return (_NMatter(hard, soft, raw, full), fs);
}

/// Encode a primitive, as keripy's `Matter(raw=, code=, soft=).qb64`.
String _encodeMatter(String code, String soft, List<int> raw) {
  final s = _sizes(code);
  if (s == null) _nerr('unknown primitive code ${jsonQuote(code)}');
  if (s.fs == null) {
    final family = code[code.length - 1];
    final ls = (3 - (raw.length % 3)) % 3;
    final size = (raw.length + ls) ~/ 3;
    String head;
    int ss;
    if (size < 64 * 64) {
      (head, ss) = ('${'456'[ls]}$family', 2);
    } else if (size < 64 * 64 * 64 * 64) {
      (head, ss) = ('${'789'[ls]}AA$family', 4);
    } else {
      _nerr('primitive too large');
    }
    final padded = Uint8List(ls + raw.length)
      ..setRange(ls, ls + raw.length, raw);
    return '$head${intToB64(size, ss)}${b64Encode(padded)}';
  }
  if (soft.length != s.ss - s.xs || !isB64(soft)) {
    _nerr('invalid soft part ${jsonQuote(soft)} for ${jsonQuote(code)}');
  }
  final cs = s.hs + s.ss;
  final ps = (3 - ((raw.length + s.ls) % 3)) % 3;
  if (ps != cs % 4) {
    _nerr('raw size ${raw.length} does not fit ${jsonQuote(code)}');
  }
  final off = ps + s.ls;
  final padded = Uint8List(off + raw.length)
    ..setRange(off, off + raw.length, raw);
  final out = '$code${'_' * s.xs}$soft${b64Encode(padded).substring(ps)}';
  if (out.length != s.fs) {
    _nerr('raw size ${raw.length} does not fit ${jsonQuote(code)}');
  }
  return out;
}

_NMatter? _isWholePrimitive(String text) {
  try {
    final (m, n) = _readMatter(text);
    return n == text.length ? m : null;
  } on KeriError {
    return null;
  }
}

const List<String> _dig = ['E', 'F', 'G', 'H', 'I', '0D', '0E', '0F', '0G'];
const List<String> _pre = [
  'B', 'D', 'E', 'F', 'G', 'H', 'I', '0D', '0E', '0F', '0G', //
  '1AAA', '1AAB', '1AAC', '1AAD', '1AAE', '1AAI', '1AAJ',
];
const List<String> _nonce = [
  '1AAP',
  '0A',
  'a',
  'E',
  'F',
  'G',
  'H',
  'I',
  '0D',
  '0E',
  '0F',
  '0G',
];
const List<String> _num = ['M', '0H', 'R', 'N', 'S', 'T', '0A', 'U'];
const List<String> _tag = [
  '0J',
  '0K',
  'X',
  '1AAF',
  '0L',
  '0M',
  'Y',
  '1AAN',
  '0N',
  '0O',
  'Z',
];
const List<String> _traits = ['EO', 'DND', 'RB', 'NB', 'NRB', 'DID'];
const String _empty = '1AAP';
const String _escape = '1AAO';
const String _null = '1AAK';
const String _no = '1AAL';
const String _yes = '1AAM';

bool _isVariable(String code) {
  final s = _sizes(code);
  return s != null && s.fs == null;
}

bool _isBext(String code) => _isVariable(code) && code.endsWith('A');
bool _isTexter(String code) => _isVariable(code) && code.endsWith('B');
bool _isDecimal(String code) => _isVariable(code) && code.endsWith('H');
bool _isLabel(String code) =>
    code == _empty ||
    _tag.contains(code) ||
    _isBext(code) ||
    _isTexter(code) ||
    code == 'V' ||
    code == 'W';
bool _isEscaped(String code) =>
    _isLabel(code) ||
    [_escape, _null, _no, _yes].contains(code) ||
    _isDecimal(code);

(_NMatter, String) _readClass(String buf, List<String> cls, String what) {
  final (m, n) = _readMatter(buf);
  if (!cls.contains(m.code)) {
    _nerr('${jsonQuote(m.code)} is not a valid $what code');
  }
  return (m, buf.substring(n));
}

String _verbatimClass(String qb64, List<String> cls, String what) {
  final m = _isWholePrimitive(qb64);
  if (m != null && cls.contains(m.code)) return qb64;
  _nerr('${jsonQuote(qb64)} is not a valid $what');
}

String _numh(List<int> raw) {
  final hex = raw.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  final trimmed = hex.replaceFirst(RegExp('^0+'), '');
  return trimmed.isEmpty ? '0' : trimmed;
}

String _encodeNumber(String hex) {
  if (!RegExp(r'^[0-9a-fA-F]*$').hasMatch(hex)) {
    _nerr('${jsonQuote(hex)} is not a hex number');
  }
  final digits = hex.replaceFirst(RegExp('^0+'), '');
  final padded = digits.length.isOdd ? '0$digits' : digits;
  final bytes = <int>[
    for (var i = 0; i < padded.length; i += 2)
      int.parse(padded.substring(i, i + 2), radix: 16),
  ];
  const picks = [('M', 2), ('R', 5), ('N', 8), ('S', 11), ('T', 14), ('U', 17)];
  final pick = picks.where((p) => bytes.length <= p.$2).firstOrNull;
  if (pick == null) _nerr('${jsonQuote(hex)} is too large for a Number');
  final raw = Uint8List(pick.$2)
    ..setRange(pick.$2 - bytes.length, pick.$2, bytes);
  return _encodeMatter(pick.$1, '', raw);
}

(String, String) _readNumber(String buf) {
  final (m, rest) = _readClass(buf, _num, 'Number');
  return (_numh(m.raw), rest);
}

/// The raw bytes of a whole CESR number primitive (`native::number_raw`): a
/// 1.x `Seqner` (`0A`) or a 2.x `Number`.
Uint8List numberRaw(String qb64) {
  final m = _isWholePrimitive(qb64);
  if (m != null && _num.contains(m.code)) return m.raw;
  _nerr('${jsonQuote(qb64)} is not a CESR number');
}

Uint8List _bextRawify(String bext, bool escapive) {
  if (!isB64(bext)) _nerr('${jsonQuote(bext)} is not Base64');
  var text = bext;
  var ws = (4 - (text.length % 4)) % 4;
  if (escapive && ((text.startsWith('A') && ws <= 1) || text.startsWith('-'))) {
    text = '-$text';
    ws = (4 - (text.length % 4)) % 4;
  }
  final base = 'A' * ws + text;
  final ls = (3 - (text.length % 4)) % 3;
  return Uint8List.fromList(b64Decode(base).sublist(ls));
}

String _bextDerawify(List<int> raw, String code, bool escapive) {
  final ls = _sizes(code)?.ls ?? 0;
  final lead = Uint8List(ls + raw.length)..setRange(ls, ls + raw.length, raw);
  final bext = b64Encode(lead);
  final ws = ls == 0 ? (bext.startsWith('A') ? 1 : 0) : (ls + 1) % 4;
  var out = bext.substring(ws);
  if (escapive && out.startsWith('-')) out = out.substring(1);
  return out;
}

String _encodeText(String text) {
  final bytes = utf8Bytes(text);
  if (isB64(text)) {
    if (text.isEmpty) return _encodeMatter(_empty, '', const []);
    if (text.length <= _tag.length) {
      return _encodeMatter(_tag[text.length - 1], text, const []);
    }
    return _encodeMatter('4A', '', _bextRawify(text, true));
  }
  if (bytes.length == 1) return _encodeMatter('V', '', bytes);
  if (bytes.length == 2) return _encodeMatter('W', '', bytes);
  return _encodeMatter('4B', '', bytes);
}

String _labelText(_NMatter m) {
  if (!_isLabel(m.code)) _nerr('${jsonQuote(m.code)} is not a label code');
  if (_tag.contains(m.code)) return m.soft;
  if (_isBext(m.code)) return _bextDerawify(m.raw, m.code, true);
  try {
    return fromUtf8(m.raw);
  } on FormatException {
    _nerr('label is not UTF-8');
  }
}

bool _isAttributeLabel(String label) =>
    RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$').hasMatch(label);

(String, String) _readLabel(String buf, bool strict) {
  final (m, n) = _readMatter(buf);
  final text = _labelText(m);
  if (strict && !_isAttributeLabel(text)) {
    _nerr('invalid field label ${jsonQuote(text)}');
  }
  return (text, buf.substring(n));
}

(String, String) _readDater(String buf) {
  final (m, n) = _readMatter(buf);
  if (m.code != '1AAG') _nerr('${jsonQuote(m.code)} is not a date-time code');
  final dts = m.qb64
      .substring(4)
      .replaceAllMapped(
        RegExp('[cdp]'),
        (x) => const {'c': ':', 'd': '.', 'p': '+'}[x[0]]!,
      );
  return (dts, buf.substring(n));
}

String _encodeDater(String dts) {
  final qb64 =
      '1AAG${dts.replaceAllMapped(RegExp(r'[:.+]'), (x) => const {':': 'c', '.': 'd', '+': 'p'}[x[0]]!)}';
  final m = _isWholePrimitive(qb64);
  if (m != null && m.code == '1AAG') return qb64;
  _nerr('${jsonQuote(dts)} is not a CESR date-time');
}

(String, String) _readPather(String buf) {
  final (m, n) = _readMatter(buf);
  String path;
  if (_isBext(m.code)) {
    var p = _bextDerawify(m.raw, m.code, false);
    if (p.startsWith('--')) p = p.substring(2);
    path = p.split('-').join('/');
  } else if (_isTexter(m.code)) {
    try {
      path = fromUtf8(m.raw);
    } on FormatException {
      _nerr('path is not UTF-8');
    }
  } else {
    _nerr('${jsonQuote(m.code)} is not a path code');
  }
  return (path, buf.substring(n));
}

String _encodePather(String path) {
  final parts = path.contains('/') ? path.split('/') : path.split('-');
  final bextable = parts.every((p) => RegExp(r'^[A-Za-z0-9_]*$').hasMatch(p));
  if (bextable) {
    var joined = parts.join('-');
    if (joined.contains('--')) _nerr('path ${jsonQuote(path)} has empty parts');
    final ws = (4 - (joined.length % 4)) % 4;
    if (joined.startsWith('A') && ws <= 1) joined = '--$joined';
    return _encodeMatter('4A', '', _bextRawify(joined, false));
  }
  final joined = parts.join('/');
  if (joined.contains('//')) _nerr('path ${jsonQuote(path)} has empty parts');
  return _encodeMatter('4B', '', utf8Bytes(joined));
}

class _Verser {
  _Verser(this.protocol, this.major, this.minor, this.genus);
  final String protocol;
  final int major;
  final int minor;
  final (int, int)? genus;
}

(_Verser, String) _readVerser(String buf) {
  final (m, n) = _readMatter(buf);
  if (m.code != 'Y' && m.code != '0O') {
    _nerr('${jsonQuote(m.code)} is not a version code');
  }
  final tag = m.soft;
  (int, int) ver(String b) {
    final major = b64ToInt(b.substring(0, 1)).toInt();
    final minor = b64ToInt(b.substring(1, 3)).toInt();
    if (minor > 255) _nerr('a minor version above 255');
    return (major, minor);
  }

  final protocol = tag.substring(0, 4);
  final (major, minor) = ver(tag.substring(4, 7));
  final genus = tag.length == 10 ? ver(tag.substring(7, 10)) : null;
  return (_Verser(protocol, major, minor, genus), buf.substring(n));
}

String _encodeVerser(Version v) {
  String ver(int major, int minor) =>
      '${intToB64(major, 1)}${intToB64(minor, 2)}';
  var tag = '${v.protocol}${ver(v.major, v.minor)}';
  final g = v.genus;
  if (g != null) tag += ver(g.$1, g.$2);
  if (tag.length == 7) return _encodeMatter('Y', tag, const []);
  if (tag.length == 10) return _encodeMatter('0O', tag, const []);
  _nerr('protocol ${jsonQuote(v.protocol)} is not four characters');
}

(String, String) _readTag(String buf) {
  final (m, n) = _readMatter(buf);
  if (!_tag.contains(m.code)) _nerr('${jsonQuote(m.code)} is not a tag code');
  return (m.soft, buf.substring(n));
}

String _encodeTag(String tag) {
  if (tag.isEmpty || tag.length > _tag.length) {
    _nerr('${jsonQuote(tag)} cannot be a tag');
  }
  return _encodeMatter(_tag[tag.length - 1], tag, const []);
}

(String, String) _readNonce(String buf) {
  final (m, rest) = _readClass(buf, _nonce, 'nonce');
  return (m.qb64, rest);
}

(String, String) _readAcdcNonce(String buf) {
  final (m, rest) = _readClass(buf, _nonce, 'nonce');
  return (m.code == _empty ? '' : m.qb64, rest);
}

String _encodeAcdcNonce(String nonce) => nonce.isEmpty
    ? _encodeMatter(_empty, '', const [])
    : _verbatimClass(nonce, _nonce, 'nonce');

// Thresholds (keripy `Tholder`).

class _Weight {
  _Weight(this.num, this.den);
  final BigInt num;
  final BigInt den;
}

class _WEntry {
  _WEntry(this.weight, [this.nested]);
  final _Weight weight;
  final List<_Weight>? nested;
}

BigInt _gcd(BigInt a, BigInt b) => b == BigInt.zero ? a : _gcd(b, a % b);

final BigInt _two128 = BigInt.two.pow(128);

_Weight _weightParse(String w) {
  Never bad() => _nerr('invalid weight ${jsonQuote(w)}');
  final slash = w.indexOf('/');
  final n = slash < 0 ? w : w.substring(0, slash);
  final d = slash < 0 ? '1' : w.substring(slash + 1);
  final digits = RegExp(r'^[0-9]+$');
  if (n.isEmpty || d.isEmpty || !digits.hasMatch(n) || !digits.hasMatch(d)) {
    bad();
  }
  final numv = BigInt.parse(n);
  final den = BigInt.parse(d);
  if (numv >= _two128 || den >= _two128) bad();
  if (den == BigInt.zero || numv > den) bad();
  var g = _gcd(numv, den);
  if (g < BigInt.one) g = BigInt.one;
  return _Weight(numv ~/ g, den ~/ g);
}

String _weightRender(_Weight w, String sep) =>
    w.num > BigInt.zero && w.num < w.den
    ? '${w.num}$sep${w.den}'
    : '${w.num ~/ w.den}';

bool _atLeastOne(List<_Weight> sum) {
  final den = sum.fold<BigInt>(
    BigInt.one,
    (l, w) => (l ~/ _gcd(l, w.den)) * w.den,
  );
  final numv = sum.fold<BigInt>(
    BigInt.zero,
    (acc, w) => acc + w.num * (den ~/ w.den),
  );
  return numv >= den;
}

void _checkClauses(List<List<_WEntry>> clauses) {
  for (final clause in clauses) {
    final top = <_Weight>[];
    for (final e in clause) {
      final nested = e.nested;
      if (nested != null && !_atLeastOne(nested)) {
        _nerr('a nested threshold clause sums to less than 1');
      }
      top.add(e.weight);
    }
    if (!_atLeastOne(top)) _nerr('a threshold clause sums to less than 1');
  }
}

(Object, String) _readTholder(String buf) {
  final (m, n) = _readMatter(buf);
  final rest = buf.substring(n);
  if (_num.contains(m.code)) return (_numh(m.raw), rest);
  if (!_isBext(m.code)) _nerr('${jsonQuote(m.code)} is not a threshold code');
  final bext = _bextDerawify(m.raw, m.code, true).replaceAll('s', '/');
  final clauses = bext
      .split('a')
      .map(
        (c) => c.split('c').map((e) {
          final k = e.indexOf('k');
          if (k < 0) return _WEntry(_weightParse(e));
          return _WEntry(
            _weightParse(e.substring(0, k)),
            e.substring(k + 1).split('v').map(_weightParse).toList(),
          );
        }).toList(),
      )
      .toList();
  _checkClauses(clauses);
  final sith = clauses
      .map(
        (clause) => clause.map<Object?>((e) {
          final nested = e.nested;
          if (nested == null) return _weightRender(e.weight, '/');
          return <String, Object?>{
            _weightRender(e.weight, '/'): nested
                .map((x) => _weightRender(x, '/'))
                .toList(),
          };
        }).toList(),
      )
      .toList();
  return (sith.length == 1 ? sith[0] : sith, rest);
}

String _encodeTholder(Object? sith) {
  if (sith is String) return _encodeNumber(sith);
  if (sith is! List) _nerr('a threshold is a hex number or a list of weights');
  final nested = sith.map((x) => x is List).toList();
  List<Object?> clauses;
  if (nested.every((x) => x)) {
    clauses = sith;
  } else if (nested.any((x) => x)) {
    _nerr('a threshold mixes clauses and weights');
  } else {
    clauses = [sith];
  }
  final parsed = clauses.map((clause) {
    return (clause! as List).map((e) {
      if (e is String) return _WEntry(_weightParse(e));
      if (e is Map && e.length == 1) {
        final entry = e.entries.first;
        final v = entry.value;
        if (v is! List) _nerr('a nested threshold clause is a list');
        return _WEntry(
          _weightParse(entry.key as String),
          v
              .map(
                (w) => w is String
                    ? _weightParse(w)
                    : _nerr('weights are strings'),
              )
              .toList(),
        );
      }
      _nerr('invalid threshold element');
    }).toList();
  }).toList();
  _checkClauses(parsed);
  final bext = parsed
      .map(
        (clause) => clause
            .map((e) {
              final nested = e.nested;
              return nested != null
                  ? '${_weightRender(e.weight, 's')}k${nested.map((x) => _weightRender(x, 's')).join('v')}'
                  : _weightRender(e.weight, 's');
            })
            .join('c'),
      )
      .join('a');
  return _encodeMatter('4A', '', _bextRawify(bext, true));
}

// Groups: lists, field maps (keripy `Mapper`) and seals (keripy `Sealer`).

String _enclose(String selector, String body) {
  if (body.length % 4 != 0) _nerr("a group's content is not quadlet aligned");
  final count = body.length ~/ 4;
  if (count < 64 * 64) return '-$selector${intToB64(count, 2)}$body';
  if (count < 64 * 64 * 64 * 64 * 64) {
    return '--$selector${intToB64(count, 5)}$body';
  }
  _nerr('a group too large to count');
}

(String, String, String) _readGroup(String buf, List<String> selectors) {
  Counter counter;
  try {
    counter = readCounter(buf);
  } on KeriError catch (e) {
    _nerr(e.message);
  }
  final selector = _stripDashes(counter.code);
  if (selector.length != 1 || !selectors.contains(selector)) {
    _nerr(
      'expected a ${jsonEncode(selectors)} group, found ${jsonQuote(counter.code)}',
    );
  }
  final len = counter.count * 4;
  if (buf.length < counter.size + len) _nerr('truncated group');
  return (
    selector,
    buf.substring(counter.size, counter.size + len),
    buf.substring(counter.size + len),
  );
}

const String _genericMap = 'I';
const String _genericList = 'J';
const int _maxNativeDepth = 128;

(Object?, String) _readValue(String buf, bool strict, int depth) {
  if (buf.isNotEmpty && buf[0] == '-') {
    if (depth >= _maxNativeDepth) {
      _nerr('field maps and lists nest deeper than $_maxNativeDepth');
    }
    final (selector, content, rest) = _readGroup(buf, [
      _genericMap,
      _genericList,
    ]);
    if (selector == _genericList) {
      final items = <Object?>[];
      var c = content;
      while (c.isNotEmpty) {
        final (v, r) = _readValue(c, strict, depth + 1);
        items.add(v);
        c = r;
      }
      return (items, rest);
    }
    return (_readMapContent(content, strict, depth + 1), rest);
  }
  final (m, n) = _readMatter(buf);
  final rest = buf.substring(n);
  if (m.code == _escape) {
    final (inner, n2) = _readMatter(rest);
    return (inner.qb64, rest.substring(n2));
  }
  if (m.code == _null) return (null, rest);
  if (m.code == _yes) return (true, rest);
  if (m.code == _no) return (false, rest);
  if (_isDecimal(m.code)) {
    return (
      _decimalValue(_bextDerawify(m.raw, m.code, false).replaceAll('p', '.')),
      rest,
    );
  }
  if (_isLabel(m.code)) return (_labelText(m), rest);
  return (m.qb64, rest);
}

Map<String, Object?> _readMapContent(String content, bool strict, int depth) {
  final map = <String, Object?>{};
  var c = content;
  while (c.isNotEmpty) {
    final (label, r1) = _readLabel(c, strict);
    final (value, r2) = _readValue(r1, strict, depth);
    // keripy's dict keeps the last of a repeated label, as IndexMap does.
    map[label] = value;
    c = r2;
  }
  return map;
}

(Map<String, Object?>, String) _readMap(String buf, bool strict) {
  final (_, content, rest) = _readGroup(buf, [_genericMap]);
  return (_readMapContent(content, strict, 1), rest);
}

SadNumber _decimalValue(String dns) {
  // Rust `str::parse::<i64>` / `<u64>`: an optional sign, then digits.
  if (RegExp(r'^[+-]?[0-9]+$').hasMatch(dns)) {
    final big = BigInt.parse(dns.startsWith('+') ? dns.substring(1) : dns);
    if (big >= i64Min && big <= u64Max) return SadNumber(big.toString());
  }
  _nerr('${jsonQuote(dns)} is not a decimal this implementation supports');
}

String _encodeDecimal(SadNumber n) {
  final text = n.text.replaceAll('.', 'p');
  final ts = text.length % 4;
  final ws = (4 - ts) % 4;
  final ls = (3 - ts) % 3;
  final decoded = b64Decode('A' * ws + text);
  return _encodeMatter('4H', '', decoded.sublist(ls));
}

String _writeValue(Object? value) {
  if (value == null) return _encodeMatter(_null, '', const []);
  if (value == true) return _encodeMatter(_yes, '', const []);
  if (value == false) return _encodeMatter(_no, '', const []);
  if (value is SadNumber) return _encodeDecimal(value);
  if (value is String) {
    final m = _isWholePrimitive(value);
    if (m != null) {
      return (_isEscaped(m.code) ? _encodeMatter(_escape, '', const []) : '') +
          value;
    }
    return _encodeText(value);
  }
  if (value is Map<String, Object?>) return _writeMap(value, const []);
  if (value is List) {
    return _enclose(_genericList, value.map(_writeValue).join());
  }
  _nerr('not a SAD value');
}

String _writeMap(Map<String, Object?> map, List<String> verbatim) {
  final body = StringBuffer();
  for (final e in map.entries) {
    body.write(_encodeText(e.key));
    final v = e.value;
    body.write(v is String && verbatim.contains(e.key) ? v : _writeValue(v));
  }
  return _enclose(_genericMap, body.toString());
}

const List<(String, List<String>)> _seals = [
  ('Q', ['d']),
  ('R', ['rd']),
  ('S', ['s', 'd']),
  ('T', ['i', 's', 'd']),
  ('U', ['i']),
  ('V', ['bi', 'd']),
  ('W', ['t', 'd']),
];

(String, String) _readSealField(String buf, String selector, String field) {
  if (field == 's') return _readNumber(buf);
  if (selector == 'W' && field == 't') {
    _readVerser(buf);
    final (m, n) = _readMatter(buf);
    return (m.qb64, buf.substring(n));
  }
  if (selector == 'W' && field == 'd') {
    final (m, r) = _readClass(buf, _nonce, 'nonce');
    return (m.qb64, r);
  }
  if (field == 'i' || field == 'bi') {
    final (m, r) = _readClass(buf, _pre, 'prefix');
    return (m.qb64, r);
  }
  final (m, r) = _readClass(buf, _dig, 'digest');
  return (m.qb64, r);
}

String _writeSealField(String selector, String field, Object? value) {
  if (value is! String) _nerr('seal field ${jsonQuote(field)} is not a string');
  if (field == 's') return _encodeNumber(value);
  if (selector == 'W' && field == 't') {
    final (_, rest) = _readVerser(value);
    if (rest.isNotEmpty) _nerr('invalid seal version');
    return value;
  }
  if (selector == 'W' && field == 'd') {
    return _verbatimClass(value, _nonce, 'nonce');
  }
  if (field == 'i' || field == 'bi') {
    return _verbatimClass(value, _pre, 'prefix');
  }
  return _verbatimClass(value, _dig, 'digest');
}

List<Object?> _readSealsContent(String content) {
  final selectors = [for (final s in _seals) s.$1];
  final seals = <Object?>[];
  var frame = content;
  while (frame.isNotEmpty) {
    final (selector, group0, rest) = _readGroup(frame, selectors);
    final fields = _seals.firstWhere((s) => s.$1 == selector).$2;
    var group = group0;
    while (group.isNotEmpty) {
      final seal = <String, Object?>{};
      for (final field in fields) {
        final (value, r) = _readSealField(group, selector, field);
        seal[field] = value;
        group = r;
      }
      seals.add(seal);
    }
    frame = rest;
  }
  return seals;
}

String _writeSeals(List<Object?> seals) {
  final frame = StringBuffer();
  String? current;
  var group = StringBuffer();
  for (final seal in seals) {
    if (seal is! Map<String, Object?>) _nerr('a seal is a field map');
    final keys = seal.keys.toList();
    final found = _seals
        .where(
          (s) =>
              s.$2.length == keys.length &&
              [
                for (var i = 0; i < keys.length; i++) s.$2[i] == keys[i],
              ].every((x) => x),
        )
        .firstOrNull;
    if (found == null) {
      _nerr('no native seal has the fields ${jsonEncode(keys)}');
    }
    final (selector, fields) = found;
    if (current != selector) {
      if (current != null) {
        frame.write(_enclose(current, group.toString()));
        group = StringBuffer();
      }
      current = selector;
    }
    for (final field in fields) {
      group.write(_writeSealField(selector, field, seal[field]));
    }
  }
  if (current != null) frame.write(_enclose(current, group.toString()));
  return _enclose(_genericList, frame.toString());
}

const Map<String, List<String>> _keriV1Fields = {
  'icp': ['v', 't', 'd', 'i', 's', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'c', 'a'],
  'rot': [
    'v',
    't',
    'd',
    'i',
    's',
    'p',
    'kt',
    'k',
    'nt',
    'n',
    'bt',
    'br',
    'ba',
    'a',
  ],
  'ixn': ['v', 't', 'd', 'i', 's', 'p', 'a'],
  'dip': [
    'v',
    't',
    'd',
    'i',
    's',
    'kt',
    'k',
    'nt',
    'n',
    'bt',
    'b',
    'c',
    'a',
    'di',
  ],
  'drt': [
    'v',
    't',
    'd',
    'i',
    's',
    'p',
    'kt',
    'k',
    'nt',
    'n',
    'bt',
    'br',
    'ba',
    'a',
  ],
  'rct': ['v', 't', 'd', 'i', 's'],
  'qry': ['v', 't', 'd', 'dt', 'r', 'rr', 'q'],
  'rpy': ['v', 't', 'd', 'dt', 'r', 'a'],
  'pro': ['v', 't', 'd', 'dt', 'r', 'rr', 'q'],
  'bar': ['v', 't', 'd', 'dt', 'r', 'a'],
  'exn': ['v', 't', 'd', 'i', 'rp', 'p', 'dt', 'r', 'q', 'a', 'e'],
  'vcp': ['v', 't', 'd', 'i', 'ii', 's', 'c', 'bt', 'b', 'n'],
  'vrt': ['v', 't', 'd', 'i', 'p', 's', 'bt', 'br', 'ba'],
  'iss': ['v', 't', 'd', 'i', 's', 'ri', 'dt'],
  'rev': ['v', 't', 'd', 'i', 's', 'ri', 'p', 'dt'],
  'bis': ['v', 't', 'd', 'i', 'ii', 's', 'ra', 'dt'],
  'brv': ['v', 't', 'd', 'i', 's', 'p', 'ra', 'dt'],
};

const Map<String, List<String>> _keriV2Fields = {
  'icp': ['v', 't', 'd', 'i', 's', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'c', 'a'],
  'rot': [
    'v',
    't',
    'd',
    'i',
    's',
    'p',
    'kt',
    'k',
    'nt',
    'n',
    'bt',
    'br',
    'ba',
    'c',
    'a',
  ],
  'ixn': ['v', 't', 'd', 'i', 's', 'p', 'a'],
  'dip': [
    'v',
    't',
    'd',
    'i',
    's',
    'kt',
    'k',
    'nt',
    'n',
    'bt',
    'b',
    'c',
    'a',
    'di',
  ],
  'drt': [
    'v',
    't',
    'd',
    'i',
    's',
    'p',
    'kt',
    'k',
    'nt',
    'n',
    'bt',
    'br',
    'ba',
    'c',
    'a',
  ],
  'rct': ['v', 't', 'd', 'i', 's'],
  'qry': ['v', 't', 'd', 'i', 'dt', 'r', 'rr', 'q'],
  'rpy': ['v', 't', 'd', 'i', 'dt', 'r', 'a'],
  'pro': ['v', 't', 'd', 'i', 'dt', 'r', 'rr', 'q'],
  'bar': ['v', 't', 'd', 'i', 'dt', 'r', 'a'],
  'xip': ['v', 't', 'd', 'u', 'i', 'ri', 'dt', 'r', 'q', 'a'],
  'exn': ['v', 't', 'd', 'i', 'ri', 'x', 'p', 'dt', 'r', 'q', 'a'],
};

/// The top-level fields of a KERI message type (`fields::keri_fields`).
List<String>? keriFields(int major, String ilk) {
  final table = major == 1
      ? _keriV1Fields
      : major == 2
      ? _keriV2Fields
      : null;
  return table?[ilk];
}

/// Check a KERI message's fields are exactly its type's, in order.
void checkKeriFields(Object? sad, int major, String ilk) {
  final expected = keriFields(major, ilk);
  if (expected == null) {
    fail("KERI $major.x defines no '$ilk' message", 'unsupported');
  }
  if (sad is! Map<String, Object?>) {
    fail('a KERI message is a field map', 'validation');
  }
  final got = sad.keys.toList();
  var same = got.length == expected.length;
  for (var i = 0; same && i < got.length; i++) {
    if (got[i] != expected[i]) same = false;
  }
  if (!same) {
    fail(
      "a KERI $major.x '$ilk' has the fields ${jsonEncode(expected)}, in that order; this one has ${jsonEncode(got)}",
      'validation',
    );
  }
}

class _AcdcShape {
  const _AcdcShape(this.alls, this.opts);
  final List<String> alls;
  final List<String> opts;
}

const List<(int, String?, _AcdcShape)> _acdcFields = [
  (
    1,
    null,
    _AcdcShape(
      ['v', 'd', 'u', 'i', 'ri', 's', 'a', 'A', 'e', 'r'],
      ['u', 'ri', 'a', 'A', 'e', 'r'],
    ),
  ),
  (
    2,
    null,
    _AcdcShape(
      ['v', 'd', 'u', 'i', 'rd', 's', 'a', 'A', 'e', 'r'],
      ['u', 'rd', 'a', 'A', 'e', 'r'],
    ),
  ),
  (
    2,
    'acm',
    _AcdcShape(
      ['v', 't', 'd', 'u', 'i', 'rd', 's', 'a', 'A', 'e', 'r'],
      ['t', 'u', 'rd', 'a', 'A', 'e', 'r'],
    ),
  ),
  (2, 'rip', _AcdcShape(['v', 't', 'd', 'u', 'i', 'n', 'dt'], [])),
  (2, 'bup', _AcdcShape(['v', 't', 'd', 'rd', 'n', 'p', 'dt', 'b'], [])),
];

/// Check an ACDC message's fields (`fields::check_acdc_fields`).
void checkAcdcFields(Object? sad, int major, String? ilk) {
  final name = ilk ?? 'bare ACDC';
  final entry = _acdcFields
      .where((e) => e.$1 == major && e.$2 == ilk)
      .firstOrNull;
  if (entry == null) {
    fail("ACDC $major.x '$name' messages are not supported", 'unsupported');
  }
  final alls = entry.$3.alls;
  final opts = entry.$3.opts;
  if (sad is! Map<String, Object?>) {
    fail('an ACDC message is a field map', 'validation');
  }
  final got = sad.keys.toList();
  var cursor = 0;
  for (final label in got) {
    var found = false;
    while (cursor < alls.length) {
      if (alls[cursor++] == label) {
        found = true;
        break;
      }
    }
    if (!found) {
      fail(
        "an ACDC $major.x '$name' has the fields ${jsonEncode(alls)}, in that order; this one has ${jsonEncode(got)}",
        'validation',
      );
    }
  }
  for (final required in alls.where((f) => !opts.contains(f))) {
    if (!got.contains(required)) {
      fail("an ACDC $major.x '$name' must carry '$required'", 'validation');
    }
  }
  if (got.contains('a') && got.contains('A')) {
    fail(
      "an ACDC $major.x '$name' carries both an attribute and an aggregate section",
      'validation',
    );
  }
}

const Map<String, List<String>> _acdcFixed = {
  'act': ['v', 't', 'd', 'u', 'i', 'rd', 's', 'a', 'e', 'r'],
  'acg': ['v', 't', 'd', 'u', 'i', 'rd', 's', 'A', 'e', 'r'],
  'sch': ['v', 't', 'd', 's'],
  'att': ['v', 't', 'd', 'a'],
  'agg': ['v', 't', 'd', 'A'],
  'edg': ['v', 't', 'd', 'e'],
  'rul': ['v', 't', 'd', 'r'],
  'rip': ['v', 't', 'd', 'u', 'i', 'n', 'dt'],
  'bup': ['v', 't', 'd', 'rd', 'n', 'p', 'dt', 'b'],
  'upd': ['v', 't', 'd', 'rd', 'n', 'p', 'dt', 'td', 'ts'],
};

const String _fixBody = 'F';
const String _mapBody = 'G';

/// The size of the native body at the head of [buf] (`native::body_size`).
int _bodySize(String buf) {
  final counter = readCounter(buf);
  final selector = _stripDashes(counter.code);
  if (selector != 'F' && selector != 'G') {
    _nerr('${jsonQuote(counter.code)} is not a message body group');
  }
  return counter.size + counter.count * 4;
}

/// Read the native body at the head of [buf] (`native::load`). The body is
/// accepted only if writing it back gives the same text.
(Map<String, Object?>, Version, int) _nativeLoad(String buf) {
  final size = _bodySize(buf);
  if (buf.length < size) {
    _nerr('the body needs $size bytes, the stream has ${buf.length}');
  }
  final raw = buf.substring(0, size);
  if (!isAscii(raw)) _nerr('a native body is CESR text, which is ASCII');
  final (selector, content, _) = _readGroup(raw, [_fixBody, _mapBody]);
  final isFixed = selector == _fixBody;
  var rest = content;
  if (!isFixed) {
    final (label, r) = _readLabel(rest, true);
    if (label != 'v') _nerr('a field map body starts with its version');
    rest = r;
  }
  final (ver, r0) = _readVerser(rest);
  rest = r0;
  final vg = ver.genus;
  if (ver.major < 2 || (vg != null && vg.$1 < 2)) {
    _nerr('native CESR serialization exists only in version 2');
  }
  final version = Version(
    protocol: ver.protocol,
    major: ver.major,
    minor: ver.minor,
    kind: 'CESR',
    size: size,
    genus: vg ?? (ver.major, ver.minor),
  );
  final vs = versionString(version);
  final sad = <String, Object?>{};
  if (ver.protocol == 'KERI') {
    if (!isFixed) _nerr('a KERI message body has fixed fields');
    final (ilk, r) = _readTag(rest);
    rest = r;
    final fields = ilk.length == 3 ? keriFields(2, ilk) : null;
    if (fields == null) _nerr('unexpected KERI message type ${jsonQuote(ilk)}');
    for (final label in fields) {
      Object? value;
      if (label == 'v') {
        value = vs;
      } else if (label == 't') {
        value = ilk;
      } else {
        (value, rest) = _readKeriField(rest, label, ilk);
      }
      sad[label] = value;
    }
  } else if (ver.protocol == 'ACDC') {
    String? ilk;
    var fields = <String>[];
    if (isFixed) {
      final (t, r) = _readTag(rest);
      rest = r;
      ilk = t;
      final f = _acdcFixed[ilk];
      if (f == null) {
        _nerr('unexpected fixed-field ACDC type ${jsonQuote(ilk)}');
      }
      fields = f;
    } else {
      sad['v'] = vs;
      String? label;
      String? r;
      try {
        (label, r) = _readLabel(rest, true);
      } on KeriError {
        label = null;
      }
      if (label == 't') {
        final (t, r2) = _readTag(r!);
        rest = r2;
        sad['t'] = t;
        ilk = t;
      }
      if (!(ilk == null || ilk == 'acm' || ilk == 'ace')) {
        _nerr('unexpected field-map ACDC type ${jsonQuote(ilk)}');
      }
    }
    var k = 0;
    for (;;) {
      String label;
      if (isFixed) {
        if (k >= fields.length) break;
        label = fields[k++];
      } else {
        if (rest.isEmpty) break;
        (label, rest) = _readLabel(rest, true);
      }
      Object? value;
      if (label == 'v' && isFixed) {
        value = vs;
      } else if (label == 't' && isFixed) {
        value = ilk ?? '';
      } else {
        (value, rest) = _readAcdcField(rest, label);
      }
      if (sad.containsKey(label)) {
        _nerr('field ${jsonQuote(label)} appears twice');
      }
      sad[label] = value;
    }
  } else {
    _nerr('unsupported protocol ${jsonQuote(ver.protocol)}');
  }
  if (rest.isNotEmpty) _nerr('the body has bytes after its last field');
  if (nativeDump(sad, const []) != raw) {
    _nerr('the body is not in its canonical encoding');
  }
  return (sad, version, size);
}

(Object?, String) _readKeriField(String buf, String label, String ilk) {
  switch (label) {
    case 'd':
    case 'p':
    case 'x':
      final (m, r) = _readClass(buf, _dig, 'digest');
      return (m.qb64, r);
    case 'u':
      return _readNonce(buf);
    case 'i':
    case 'di':
    case 'ri':
      final (m, r) = _readClass(buf, _pre, 'prefix');
      return (m.qb64, r);
    case 's':
    case 'bt':
      return _readNumber(buf);
    case 'kt':
    case 'nt':
      return _readTholder(buf);
    case 'k':
    case 'n':
    case 'b':
    case 'ba':
    case 'br':
      final (_, content, rest) = _readGroup(buf, [_genericList]);
      final items = <Object?>[];
      var c = content;
      while (c.isNotEmpty) {
        final (m, n) = _readMatter(c);
        items.add(m.qb64);
        c = c.substring(n);
      }
      return (items, rest);
    case 'dt':
      return _readDater(buf);
    case 'r':
    case 'rr':
      return _readPather(buf);
    case 'c':
      final (_, content, rest) = _readGroup(buf, [_genericList]);
      final traits = <Object?>[];
      var c = content;
      while (c.isNotEmpty) {
        final (t, r) = _readTag(c);
        if (!_traits.contains(t)) {
          _nerr('unknown configuration trait ${jsonQuote(t)}');
        }
        traits.add(t);
        c = r;
      }
      return (traits, rest);
    case 'a':
      Counter counter;
      try {
        counter = readCounter(buf);
      } on KeriError catch (e) {
        _nerr(e.message);
      }
      final sel = _stripDashes(counter.code);
      if (sel == 'I') return _readMap(buf, true);
      if (sel == 'J') {
        if (!['icp', 'ixn', 'rot', 'dip', 'drt'].contains(ilk)) {
          _nerr("a '$ilk' carries no seal list");
        }
        final (_, content, rest) = _readGroup(buf, [_genericList]);
        return (_readSealsContent(content), rest);
      }
      _nerr('`a` is a map or a list, not ${jsonQuote(sel)}');
    case 'q':
      return _readMap(buf, true);
    default:
      _nerr('unsupported KERI field ${jsonQuote(label)}');
  }
}

(Object?, String) _readAcdcField(String buf, String label) {
  (Object?, String) section(String b, bool strict) {
    if (b.isNotEmpty && b[0] == '-') return _readMap(b, strict);
    final (m, r) = _readClass(b, _dig, 'digest');
    return (m.qb64, r);
  }

  switch (label) {
    case 'd':
    case 'p':
    case 'b':
      final (m, r) = _readClass(buf, _dig, 'digest');
      return (m.qb64, r);
    case 'u':
    case 'rd':
    case 'td':
      return _readAcdcNonce(buf);
    case 'i':
      final (m, r) = _readClass(buf, _pre, 'prefix');
      return (m.qb64, r);
    case 'n':
      return _readNumber(buf);
    case 'dt':
      return _readDater(buf);
    case 'ts':
      final (m, n) = _readMatter(buf);
      return (_labelText(m), buf.substring(n));
    case 's':
      return section(buf, false);
    case 'a':
    case 'e':
    case 'r':
      return section(buf, true);
    case 'A':
      if (buf.isNotEmpty && buf[0] == '-') {
        fail(
          'an expanded aggregate section (`A`) is not supported',
          'unsupported',
        );
      }
      final (m, r) = _readClass(buf, _dig, 'digest');
      return (m.qb64, r);
    default:
      _nerr('unsupported ACDC field ${jsonQuote(label)}');
  }
}

/// Write a SAD natively (`native::dump`): a message by its type's codec, any
/// other field map generically. Values of [verbatim] labels are written as
/// their text (a SAID filled with `#`).
String nativeDump(Object? sad, List<String> verbatim) {
  if (sad is! Map<String, Object?>) _nerr('only a field map has a native form');
  Version? version;
  final vs = sadStr(sad['v']);
  if (vs != null) {
    try {
      version = parseVersionString(vs);
    } on KeriError {
      version = null;
    }
  }
  if (version == null) return _writeMap(sad, verbatim);
  if (version.kind != 'CESR') {
    _nerr("the message's version string does not name CESR");
  }
  final ilk = sadStr(sad['t']);
  final body = StringBuffer();
  if (version.protocol == 'KERI') {
    if (ilk == null) _nerr('a KERI message has a type');
    if (keriFields(2, ilk) == null) {
      _nerr('unexpected KERI message type ${jsonQuote(ilk)}');
    }
    for (final e in sad.entries) {
      body.write(_writeKeriField(e.key, e.value, ilk, version));
    }
    return _enclose(_fixBody, body.toString());
  }
  if (version.protocol == 'ACDC') {
    final mapBody = ilk == null || ilk == 'acm' || ilk == 'ace';
    if (!mapBody && _acdcFixed[ilk] == null) {
      _nerr('unexpected ACDC message type ${jsonQuote(ilk)}');
    }
    for (final e in sad.entries) {
      if (mapBody) body.write(_encodeText(e.key));
      body.write(_writeAcdcField(e.key, e.value, version));
    }
    return _enclose(mapBody ? _mapBody : _fixBody, body.toString());
  }
  _nerr('unsupported protocol ${jsonQuote(version.protocol)}');
}

String _textOf(String label, Object? value) {
  if (value is! String) _nerr('field ${jsonQuote(label)} is not a string');
  return value;
}

String _writeKeriField(
  String label,
  Object? value,
  String ilk,
  Version version,
) {
  switch (label) {
    case 'v':
      return _encodeVerser(version);
    case 't':
      return _encodeTag(_textOf(label, value));
    case 'd':
    case 'i':
    case 'p':
    case 'u':
    case 'di':
    case 'ri':
    case 'x':
      return _textOf(label, value);
    case 's':
    case 'bt':
      return _encodeNumber(_textOf(label, value));
    case 'kt':
    case 'nt':
      return _encodeTholder(value);
    case 'k':
    case 'n':
    case 'b':
    case 'ba':
    case 'br':
      if (value is! List) _nerr('field ${jsonQuote(label)} is a list');
      return _enclose(
        _genericList,
        value.map((item) => _textOf(label, item)).join(),
      );
    case 'dt':
      return _encodeDater(_textOf(label, value));
    case 'r':
    case 'rr':
      return _encodePather(_textOf(label, value));
    case 'c':
      if (value is! List) _nerr('field "c" is a list');
      return _enclose(
        _genericList,
        value.map((item) => _encodeTag(_textOf(label, item))).join(),
      );
    case 'a':
      if (value is Map<String, Object?>) return _writeMap(value, const []);
      if (value is List) {
        if (!['icp', 'ixn', 'rot', 'dip', 'drt'].contains(ilk)) {
          _nerr("a '$ilk' carries no seal list");
        }
        return _writeSeals(value);
      }
      _nerr('`a` is a map or a list');
    case 'q':
      if (value is Map<String, Object?>) return _writeMap(value, const []);
      _nerr('`q` is a map');
    default:
      _nerr('unsupported KERI field ${jsonQuote(label)}');
  }
}

String _writeAcdcField(String label, Object? value, Version version) {
  String section() {
    if (value is Map<String, Object?>) return _writeMap(value, const []);
    if (value is String && value.isNotEmpty) {
      return _verbatimClass(value, _dig, 'digest');
    }
    _nerr('section ${jsonQuote(label)} is a block or a SAID');
  }

  switch (label) {
    case 'v':
      return _encodeVerser(version);
    case 't':
      return _encodeTag(_textOf(label, value));
    case 'd':
    case 'i':
    case 'p':
    case 'b':
      return _textOf(label, value);
    case 'u':
    case 'rd':
    case 'td':
      return _encodeAcdcNonce(_textOf(label, value));
    case 'n':
      return _encodeNumber(_textOf(label, value));
    case 'dt':
      return _encodeDater(_textOf(label, value));
    case 'ts':
      return _encodeText(_textOf(label, value));
    case 's':
    case 'a':
    case 'e':
    case 'r':
      return section();
    case 'A':
      if (value is String && value.isNotEmpty) {
        return _verbatimClass(value, _dig, 'digest');
      }
      fail(
        'an expanded aggregate section (`A`) is not supported',
        'unsupported',
      );
    default:
      _nerr('unsupported ACDC field ${jsonQuote(label)}');
  }
}
