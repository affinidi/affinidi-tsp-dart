// ignore_for_file: public_member_api_docs

part of 'cesr.dart';

// SAIDs, message bodies and the attachment stream. Port of the matching
// sections of vti-didcomm-js `src/did-webs-cesr.js`.

// ─── SAIDs (affinidi-keri-core `said.rs`) ───────────────────────────────

/// The SAID [label] would have over [sad], serialized as [kind]
/// (`said::compute_said` on a copy). For an inception whose `i` equals its
/// `d`, `i` is dummied too.
String computeSaid(Object? sad, String label, String code, String kind) {
  if (sad is! Map<String, Object?>) {
    fail('SAD must be a JSON object', 'validation');
  }
  final s = matterSizage(code);
  if (s == null) fail('unknown digest code: $code', 'validation');
  if (s.fs == 0) {
    fail(
      'digest code $code has variable length, cannot compute SAID',
      'validation',
    );
  }
  final dummy = '#' * s.fs;
  if (!sad.containsKey(label)) fail('missing field $label', 'validation');
  final selfAddressing =
      label == 'd' && sad.containsKey('i') && sadEqual(sad['d'], sad['i']);
  final copy = Map<String, Object?>.of(sad);
  copy[label] = dummy;
  if (selfAddressing) copy['i'] = dummy;
  List<int> serialized;
  if (kind == 'CESR') {
    serialized = utf8Bytes(
      nativeDump(copy, selfAddressing ? [label, 'i'] : [label]),
    );
  } else if (kind == 'JSON') {
    serialized = utf8Bytes(serializeJson(copy));
  } else {
    fail('$kind serialization is not supported', 'unsupported');
  }
  return digest(code, serialized);
}

/// Verify a message's SAID (`Serder::verify_said`).
void verifySaid(Object? sad, String label, String code, String kind) {
  final current = sadStr(sadGet(sad, label));
  if (current == null) fail('missing field $label', 'validation');
  if (computeSaid(sad, label, code, kind) != current) {
    fail('SAID mismatch', 'said');
  }
}

// ─── Serder and the stream (affinidi-keri-core `serder.rs`, `parser.rs`) ─

const int _versionSearchWindow = 32;

/// A message body: its exact bytes, version, serialization kind and content.
class Serder {
  Serder(this.raw, this.version, this.kind, this.sad);

  /// The message body's exact bytes.
  final Uint8List raw;
  final Version? version;

  /// `JSON` or `CESR`.
  final String kind;
  final Map<String, Object?> sad;
}

bool _isCborStart(int b) =>
    (b >= 0xa0 && b <= 0xb7) ||
    b == 0xb8 ||
    b == 0xb9 ||
    b == 0xba ||
    b == 0xbb ||
    b == 0xbf;

bool _isMsgpackStart(int b) =>
    (b >= 0x80 && b <= 0x8f) || b == 0xde || b == 0xdf;

Version? _extractVersion(Uint8List data) {
  final window = data.sublist(
    0,
    data.length < _versionSearchWindow ? data.length : _versionSearchWindow,
  );
  var pos = -1;
  for (final proto in ['KERI', 'ACDC', 'SAID']) {
    final p = proto.codeUnits;
    for (var k = 0; k + 4 <= window.length; k++) {
      if (window[k] == p[0] &&
          window[k + 1] == p[1] &&
          window[k + 2] == p[2] &&
          window[k + 3] == p[3]) {
        if (pos < 0 || k < pos) pos = k;
        break;
      }
    }
  }
  if (pos < 0 || pos + keriVerFullsize > data.length) return null;
  try {
    return parseVersionBytes(Uint8List.sublistView(data, pos));
  } on KeriError {
    return null;
  }
}

/// Read the message body at the head of [bytes] (`Serder::from_raw`).
Serder serderFromRaw(Uint8List bytes) {
  if (bytes.isEmpty) fail('empty input');
  final first = bytes[0];
  if (first == 0x2d) {
    final end = _bodySizeOrAll(bytes);
    final text = asciiText(
      bytes.sublist(0, bytes.length < end ? bytes.length : end),
    );
    if (text == null) _nerr('a native body is CESR text, which is ASCII');
    final (sad, version, size) = _nativeLoad(text);
    return Serder(
      Uint8List.fromList(bytes.sublist(0, size)),
      version,
      'CESR',
      sad,
    );
  }
  if (first != 0x7b) {
    if (_isCborStart(first) || _isMsgpackStart(first)) {
      fail(
        '${_isCborStart(first) ? 'CBOR' : 'MessagePack'} message bodies are not supported',
        'unsupported',
      );
    }
    fail(
      'cannot detect serialization kind from first byte: 0x${first.toRadixString(16).padLeft(2, '0')}',
    );
  }
  var version = _extractVersion(bytes);
  final msgLen = version != null ? version.size : bytes.length;
  if (bytes.length < msgLen) {
    fail('raw data too short: ${bytes.length} bytes but version says $msgLen');
  }
  final raw = Uint8List.fromList(bytes.sublist(0, msgLen));
  final sad = parseJson(raw);
  if (sad is! Map<String, Object?>) {
    fail('a message body is a JSON object', 'json');
  }
  if (version == null) {
    final vs = sadStr(sad['v']);
    if (vs != null) {
      try {
        version = parseVersionString(vs);
      } on KeriError {
        version = null;
      }
    }
  }
  return Serder(raw, version, 'JSON', sad);
}

// A native body's text: read just its counter's span, so a non-ASCII byte in
// a later message does not fail this one.
int _bodySizeOrAll(Uint8List bytes) {
  final head = asciiText(bytes.sublist(0, bytes.length < 8 ? bytes.length : 8));
  if (head == null) return bytes.length;
  try {
    return _bodySize(head);
  } on KeriError {
    return bytes.length;
  }
}

/// A transferable indexed signature group.
class TransIdxSigGroup {
  TransIdxSigGroup(this.prefix, this.sn, this.said, this.sigs);
  final String prefix;
  final String sn;
  final String said;
  final List<Siger> sigs;
}

/// A blinded state quadruple.
class BlindedState {
  BlindedState(this.blid, this.uuid, this.acdc, this.state);
  final String blid;
  final String uuid;
  final String acdc;
  final String state;
}

/// An attachment group of a message.
sealed class Attachment {
  const Attachment();
}

class ControllerSigs extends Attachment {
  const ControllerSigs(this.sigs);
  final List<Siger> sigs;
}

class WitnessSigs extends Attachment {
  const WitnessSigs(this.sigs);
  final List<Siger> sigs;
}

class ReceiptCouples extends Attachment {
  const ReceiptCouples(this.couples);
  final List<(String, Uint8List)> couples;
}

class FirstSeenReplayCouples extends Attachment {
  const FirstSeenReplayCouples(this.couples);
  final List<(String, String)> couples;
}

class SealSourceCouples extends Attachment {
  const SealSourceCouples(this.couples);
  final List<(String, String)> couples;
}

class TransIdxSigGroups extends Attachment {
  const TransIdxSigGroups(this.groups);
  final List<TransIdxSigGroup> groups;
}

class BlindedStates extends Attachment {
  const BlindedStates(this.states);
  final List<BlindedState> states;
}

/// A message of a stream with its attachments.
class ParsedMessage {
  ParsedMessage(this.serder, this.attachments);
  final Serder serder;
  final List<Attachment> attachments;
}

const int _maxAttachmentCount = 4096;
const int _minPrimitiveSize = 4;

(List<T>, int) _take<T>(
  String text,
  String table,
  String kind,
  int count,
  (T, int) Function(String) item,
) {
  final items = <T>[];
  var offset = 0;
  if (_countsQuadlets(table, kind)) {
    final span = _quadletSpan(text, count);
    while (offset < span) {
      if (items.length >= _maxAttachmentCount) {
        fail('$kind holds more than $_maxAttachmentCount items');
      }
      final (it, n) = item(text.substring(offset, span));
      items.add(it);
      offset += n;
    }
    if (offset != span) {
      fail('$kind declared $span bytes but its items accounted for $offset');
    }
  } else {
    if (count > _maxAttachmentCount) {
      fail('$kind count $count exceeds maximum of $_maxAttachmentCount');
    }
    if (count * _minPrimitiveSize > text.length) {
      fail(
        '$kind count $count requires at least ${count * _minPrimitiveSize} bytes, but only ${text.length} available',
      );
    }
    for (var k = 0; k < count; k++) {
      final (it, n) = item(text.substring(offset));
      items.add(it);
      offset += n;
    }
  }
  return (items, offset);
}

int _quadletSpan(String text, int count) {
  final span = count * 4;
  if (span > text.length) {
    fail(
      'attachment group of $span bytes extends past the stream (${text.length} bytes available)',
    );
  }
  return span;
}

((String, String), int) _parseQb64Pair(String text) {
  final (first, a) = readAttachmentMatter(text, 'couple first member');
  final (second, b) = readAttachmentMatter(
    text.substring(a),
    'couple second member',
  );
  return ((first, second), a + b);
}

(BlindedState, int) _parseBlindedState(String text) {
  final (blid, a) = readAttachmentMatter(text, 'blinded state BLID');
  final (uuid, b) = readAttachmentMatter(
    text.substring(a),
    'blinded state UUID',
  );
  final (acdc, c) = readAttachmentMatter(
    text.substring(a + b),
    'blinded state ACDC',
  );
  final (state, d) = readAttachmentMatter(
    text.substring(a + b + c),
    'blinded state state',
  );
  return (BlindedState(blid, uuid, acdc, state), a + b + c + d);
}

((String, Uint8List), int) _parseReceiptCouple(String text) {
  final (prefix, a) = readAttachmentMatter(text, 'prefix');
  final (sig, b) = readAttachmentMatter(text.substring(a), 'signature');
  MatterValue m;
  try {
    m = matterFromQb64(sig);
  } on KeriError catch (e) {
    fail('failed to parse sig matter: ${e.message}');
  }
  return ((prefix, m.raw), a + b);
}

(TransIdxSigGroup, int) _parseTransIdxSigGroup(String text, String table) {
  var offset = 0;
  final (prefix, a) = readAttachmentMatter(
    text,
    'transferable sig group prefix',
  );
  offset += a;
  final (sn, b) = readAttachmentMatter(
    text.substring(offset),
    'transferable sig group sn',
  );
  offset += b;
  final (said, c) = readAttachmentMatter(
    text.substring(offset),
    'transferable sig group said',
  );
  offset += c;
  final counter = readCounter(text.substring(offset));
  if (classify(counter.code, table) != 'ControllerIdxSigs') {
    fail(
      'transferable sig group has ${jsonQuote(counter.code)} where indexed signatures were expected',
    );
  }
  offset += counter.size;
  final (sigs, n) = _take<Siger>(
    text.substring(offset),
    table,
    'ControllerIdxSigs',
    counter.count,
    readIndexedSig,
  );
  offset += n;
  if (sigs.isEmpty) fail('transferable sig group carries no signatures');
  return (TransIdxSigGroup(prefix, sn, said, sigs), offset);
}

(List<Attachment>, int) _parseGroup(String text, String table) {
  final counter = readCounter(text);
  final offset = counter.size;
  final kind = classify(counter.code, table);
  if (kind == null) {
    fail(
      'unrecognised attachment counter code ${jsonQuote(counter.code)} for $table; refusing to guess its length',
    );
  }
  final body = text.substring(offset);
  final count = counter.count;
  if (kind == 'AttachedMaterialQuadlets') {
    final span = _quadletSpan(body, count);
    final (inner, consumed) = _parseAttachments(body.substring(0, span), table);
    if (consumed != span) {
      fail(
        'attachment group declared $span bytes but its contents accounted for $consumed',
      );
    }
    return (inner, offset + span);
  }
  Attachment attachment;
  int n;
  switch (kind) {
    case 'ControllerIdxSigs':
    case 'WitnessIdxSigs':
      final List<Siger> sigs;
      (sigs, n) = _take<Siger>(body, table, kind, count, readIndexedSig);
      attachment = kind == 'ControllerIdxSigs'
          ? ControllerSigs(sigs)
          : WitnessSigs(sigs);
    case 'NonTransReceiptCouples':
      final List<(String, Uint8List)> couples;
      (couples, n) = _take(body, table, kind, count, _parseReceiptCouple);
      attachment = ReceiptCouples(couples);
    case 'FirstSeenReplayCouples':
    case 'SealSourceCouples':
      final List<(String, String)> couples;
      (couples, n) = _take(body, table, kind, count, _parseQb64Pair);
      attachment = kind == 'SealSourceCouples'
          ? SealSourceCouples(couples)
          : FirstSeenReplayCouples(couples);
    case 'BlindedStateQuadruples':
      final List<BlindedState> states;
      (states, n) = _take(body, table, kind, count, _parseBlindedState);
      attachment = BlindedStates(states);
    case 'TransIdxSigGroups':
      final List<TransIdxSigGroup> groups;
      (groups, n) = _take(
        body,
        table,
        kind,
        count,
        (t) => _parseTransIdxSigGroup(t, table),
      );
      attachment = TransIdxSigGroups(groups);
    default:
      fail(
        'attachment group ${jsonQuote(counter.code)} ($kind) is not yet supported; refusing to guess its length',
      );
  }
  return ([attachment], offset + n);
}

(List<Attachment>, int) _parseAttachments(String text, String table) {
  final attachments = <Attachment>[];
  var offset = 0;
  while (offset < text.length &&
      text[offset] == '-' &&
      !text.startsWith('-_', offset)) {
    if (table == 'V2') {
      Counter? next;
      try {
        next = readCounter(text.substring(offset));
      } on KeriError {
        next = null;
      }
      final sel = next == null ? null : _stripDashes(next.code);
      if (sel == 'F' || sel == 'G') break;
    }
    final (group, consumed) = _parseGroup(text.substring(offset), table);
    offset += consumed;
    attachments.addAll(group);
  }
  return (attachments, offset);
}

String _headText(Uint8List stream, int offset) {
  final end = offset + 8 < stream.length ? offset + 8 : stream.length;
  final text = asciiText(stream.sublist(offset, end));
  if (text == null) fail('counter is not ASCII');
  return text;
}

/// Parse every message of a stream (`parser::parse_all`, strict). The stream
/// starts in CESR genus 1.x; a genus-version counter switches it.
List<ParsedMessage> parseAll(Uint8List stream, {int? maxMessages}) {
  final messages = <ParsedMessage>[];
  var offset = 0;
  var table = 'V1';
  var lastNonAscii = -1;
  for (var k = stream.length - 1; k >= 0; k--) {
    if (stream[k] > 0x7f) {
      lastNonAscii = k;
      break;
    }
  }
  final asciiFrom = lastNonAscii + 1;
  String? tailText;
  String tail() => tailText ??= asciiText(stream.sublist(asciiFrom))!;
  bool isWs(int b) =>
      b == 0x20 || b == 0x09 || b == 0x0a || b == 0x0c || b == 0x0d;
  bool isGenusCounterAt(int o) =>
      o + 1 < stream.length && stream[o] == 0x2d && stream[o + 1] == 0x5f;
  while (offset < stream.length) {
    while (offset < stream.length && isWs(stream[offset])) {
      offset++;
    }
    if (offset >= stream.length) break;
    if (isGenusCounterAt(offset)) {
      final counter = readCounter(_headText(stream, offset));
      if (offset + counter.size == stream.length) break;
    }
    if (maxMessages != null && messages.length >= maxMessages) {
      fail('the stream holds more than $maxMessages messages', 'unsupported');
    }
    // Genus-version counters before the message switch the genus.
    while (offset < stream.length && isGenusCounterAt(offset)) {
      final counter = readCounter(_headText(stream, offset));
      final gv = genusVersion(counter);
      if (gv == null) {
        fail(
          '${jsonQuote(counter.code)} is not a genus-version counter this parser knows',
        );
      }
      table = tableForGenus(gv.$1);
      offset += counter.size;
    }
    if (offset >= stream.length) fail('empty stream');
    final first = stream[offset];
    var isBody = first == 0x7b || _isCborStart(first) || _isMsgpackStart(first);
    if (!isBody && first == 0x2d) {
      final counter = readCounter(_headText(stream, offset));
      final base = _stripDashes(counter.code);
      if (table == 'V2' && (base == 'F' || base == 'G')) {
        isBody = true;
      } else if ((table == 'V2' && (base == 'B' || base == 'H')) ||
          (table == 'V1' && (base == 'U' || base == 'W'))) {
        fail(
          'enclosed message group ${jsonQuote(counter.code)} in a $table stream',
          'unsupported',
        );
      } else {
        fail(
          'a $table stream has counter ${jsonQuote(counter.code)} where a message was expected',
        );
      }
    }
    if (!isBody) {
      fail(
        'unrecognized stream start byte: 0x${first.toRadixString(16).padLeft(2, '0')}',
      );
    }
    final serder = serderFromRaw(Uint8List.sublistView(stream, offset));
    final v = serder.version;
    if (v != null && v.major >= 2 && table == 'V1') {
      fail(
        'a version ${v.major}.${v.minor} message in a CESR 1.x stream: a 2.x stream opens with the genus-version counter -_AAACAA',
      );
    }
    offset += serder.raw.length;
    // CESR text is Base64, so attachments are ASCII; affinidi-keri-core
    // checks that everything from an attachment group to the end of the
    // stream is (`parse_attachments`), so one non-ASCII byte anywhere later
    // fails the stream there too.
    var restText = '';
    if (offset < stream.length &&
        stream[offset] == 0x2d &&
        !isGenusCounterAt(offset)) {
      if (offset < asciiFrom) fail('attachment data contains non-ASCII bytes');
      restText = tail().substring(offset - asciiFrom);
    }
    final (attachments, consumed) = _parseAttachments(restText, table);
    if (serder.raw.length + consumed == 0) {
      fail('parse_next consumed zero bytes');
    }
    messages.add(ParsedMessage(serder, attachments));
    offset += consumed;
  }
  return messages;
}

/// The controller signatures of a message.
List<Siger> controllerSigs(ParsedMessage msg) =>
    msg.attachments.whereType<ControllerSigs>().firstOrNull?.sigs ?? const [];

/// The seal source couples of a message.
List<(String, String)> sealSourceCouples(ParsedMessage msg) =>
    msg.attachments.whereType<SealSourceCouples>().firstOrNull?.couples ??
    const [];

/// The transferable indexed signature groups of a message.
List<TransIdxSigGroup> transIdxSigGroups(ParsedMessage msg) =>
    msg.attachments.whereType<TransIdxSigGroups>().firstOrNull?.groups ??
    const [];

/// The value of a sequence number as an attachment carries it
/// (`parser::number_value`): a 1.x `Seqner` (`0A`) or a 2.x `Number`.
BigInt numberValue(String qb64) {
  int hs;
  int fs;
  int rawLen;
  if (qb64.startsWith('0A')) {
    (hs, fs, rawLen) = (2, 24, 16);
  } else if (qb64.startsWith('0H')) {
    (hs, fs, rawLen) = (2, 8, 4);
  } else if (qb64.startsWith('M')) {
    (hs, fs, rawLen) = (1, 4, 2);
  } else if (qb64.startsWith('R')) {
    (hs, fs, rawLen) = (1, 8, 5);
  } else if (qb64.startsWith('N')) {
    (hs, fs, rawLen) = (1, 12, 8);
  } else {
    fail('${jsonQuote(qb64)} is not a sequence number');
  }
  if (qb64.length != fs) {
    fail('sequence number ${jsonQuote(qb64)} is not $fs characters');
  }
  Uint8List bytes;
  try {
    bytes = b64Decode('A' * hs + qb64.substring(hs));
  } on KeriError catch (e) {
    fail('sequence number ${jsonQuote(qb64)}: ${e.message}');
  }
  final raw = bytes.sublist(bytes.length - rawLen);
  final highLen = raw.length - 8 > 0 ? raw.length - 8 : 0;
  if (raw.sublist(0, highLen).any((b) => b != 0) ||
      bytes.sublist(0, bytes.length - rawLen).any((b) => b != 0)) {
    fail('sequence number ${jsonQuote(qb64)} does not fit 64 bits');
  }
  var n = BigInt.zero;
  for (final b in raw.sublist(highLen)) {
    n = (n << 8) | BigInt.from(b);
  }
  return n;
}
