// Key event log verification for the did:webs resolver.
//
// A port of OpenVTC/vti-didcomm-js `src/did-webs-kel.js`, itself a port of
// `affinidi-keri-core` 0.8.1 (`kever.rs`, `key_state.rs`, `threshold.rs`,
// `delegation.rs`) and of `affinidi-did-webs` 0.13 `kel.rs`: every key event
// of every identifier in a `keri.cesr` stream is verified against the key
// state its own log establishes — SAID, field list, signatures against the
// signing threshold, prior-event digest, pre-rotation commitment (`nt` over
// the exposed digests), witness receipts against the witness threshold,
// delegation anchored in the delegator's verified log — and a rotation may
// supersede interaction events after the last establishment event (recovery),
// taking what they anchored with them.
//
// Verification results are remembered per stream, and so is the key state at
// an establishment event: the same answer as a replay from the start of the
// log for every signature, computed once.
//
// Numbers follow the JS port: a sequence number is an [int] only while it is
// exactly representable on every platform (2^53; it is refused above that, as
// the JS refuses it), and thresholds, weights and seal sequence numbers are
// [BigInt]s, so the web build answers as the native one does.

// ignore_for_file: public_member_api_docs

import 'dart:typed_data';

import 'cesr.dart';
import 'signatures.dart';

Never _fail(String message, [String type = 'validation']) =>
    throw KeriError(message, type);

/// Delegation steps followed before giving up (`kel::MAX_DELEGATION_DEPTH`).
const int _maxDelegationDepth = 8;

/// Most messages a stream may hold (`kel::MAX_STREAM_MESSAGES`).
const int maxStreamMessages = 10000;

/// Most signatures, receipt couples and group signatures in a stream.
const int maxStreamSignatures = 16384;

/// Most witness entries (`b`, `ba`) across a stream's key events.
const int maxStreamBackers = 1024;

/// Most seals (`a`) across a stream's key events.
const int maxStreamSeals = 16384;

// ─── Signature verification (affinidi-keri-crypto `Verfer`) ─────────────

const Set<String> _verferCodes = {'B', 'D', '1AAA', '1AAB', '1AAI', '1AAJ'};

/// A verification key.
class Verfer {
  Verfer(this.code, this.raw, this.qb64);
  final String code;
  final Uint8List raw;
  final String qb64;
}

/// A verification key from its qb64 (`Verfer::from_qb64`).
Verfer verfer(Object? qb64) {
  final m = matterFromQb64(qb64);
  if (!_verferCodes.contains(m.code)) {
    _fail('unsupported verfer code: ${m.code}', 'crypto');
  }
  return Verfer(m.code, m.raw, matterQb64(m.code, m.raw));
}

/// Verify [signature] over [message] (`Verfer::verify`). False for a
/// signature that does not verify; throws for a key or a signature that
/// cannot be read, as the Rust does.
bool verifySignature(Verfer v, Uint8List message, Uint8List signature) {
  // A replay verifies the same signature over the same message every time a
  // key state is read; the answer is kept with the message's bytes.
  final cache = _verified[message] ??= <String, bool>{};
  final key = '${v.qb64}.${b64Encode(signature)}';
  final hit = cache[key];
  if (hit != null) return hit;
  final valid = _verifyUncached(v, message, signature);
  cache[key] = valid;
  return valid;
}

final Expando<Map<String, bool>> _verified = Expando('kel.verified');

BigInt _bigOf(List<int> bytes) {
  var n = BigInt.zero;
  for (final b in bytes) {
    n = (n << 8) | BigInt.from(b);
  }
  return n;
}

bool _verifyUncached(Verfer v, Uint8List message, Uint8List signature) {
  if (v.code == 'B' || v.code == 'D') {
    // ed25519-dalek accepts any encoding that decompresses.
    if (!ed25519KeyDecodes(v.raw)) {
      _fail('invalid Ed25519 public key', 'crypto');
    }
    if (signature.length != 64) {
      _fail('invalid Ed25519 signature length', 'crypto');
    }
    return ed25519Verify(v.raw, message, signature);
  }
  final k1 = v.code == '1AAA' || v.code == '1AAB';
  final curve = k1 ? EcdsaCurve.secp256k1 : EcdsaCurve.p256;
  final q = ecdsaPoint(curve, v.raw);
  if (q == null) _fail('invalid ECDSA public key', 'crypto');
  // `Signature::from_slice`: r || s, each in [1, n).
  if (signature.length != 64) _fail('invalid ECDSA signature', 'crypto');
  final n = ecdsaOrder(curve);
  final r = _bigOf(Uint8List.sublistView(signature, 0, 32));
  final s = _bigOf(Uint8List.sublistView(signature, 32));
  if (r == BigInt.zero || s == BigInt.zero || r >= n || s >= n) {
    _fail('invalid ECDSA signature', 'crypto');
  }
  // k256 refuses a high-S signature; p256 does not.
  return ecdsaVerify(curve, q, message, r, s, lowS: k1);
}

// ─── Thresholds (affinidi-keri-core `threshold.rs`) ─────────────────────

final BigInt _u32Max = BigInt.from(0xffffffff);
final BigInt _u64Limit = BigInt.one << 64;

/// A weight `num/den` of a weighted threshold clause.
class Weight {
  const Weight(this.num, this.den);
  final BigInt num;
  final BigInt den;
}

/// A signing threshold: simple (`n` of the keys) or weighted (every clause's
/// weights of the signing keys sum to at least one).
sealed class Threshold {
  const Threshold();
}

class SimpleThreshold extends Threshold {
  const SimpleThreshold(this.n);
  final BigInt n;
}

class WeightedThreshold extends Threshold {
  const WeightedThreshold(this.clauses);
  final List<List<Weight>> clauses;
}

Weight _weight(String s) {
  final slash = s.indexOf('/');
  final n = slash < 0 ? s : s.substring(0, slash);
  final d = slash < 0 ? null : s.substring(slash + 1);
  final num = parseUnsigned(n, 10, _u32Max);
  if (num == null) _fail('invalid weight numerator: $n');
  final den = d == null ? BigInt.one : parseUnsigned(d, 10, _u32Max);
  if (den == null) _fail('invalid weight denominator: $d');
  if (den == BigInt.zero) _fail('weight denominator cannot be zero');
  return Weight(num, den);
}

/// Read a threshold from its field (`Threshold::from_json_value`).
Threshold parseThreshold(Object? value) {
  if (value is String) {
    // keripy reads a simple threshold as hex.
    final n = parseUnsigned(value, 16);
    if (n == null) _fail('invalid threshold string: $value');
    return SimpleThreshold(n);
  }
  if (value is SadNumber) {
    final n = value.big;
    if (n < BigInt.zero) _fail('invalid threshold number: ${value.text}');
    return SimpleThreshold(n);
  }
  if (value is List) {
    if (value.isEmpty) {
      _fail('weighted threshold must have at least one clause');
    }
    final List<List<Object?>> clauses;
    if (value.every((i) => i is String)) {
      clauses = [value.cast<Object?>()];
    } else if (value.every((i) => i is List)) {
      clauses = [for (final c in value) (c as List).cast<Object?>()];
    } else {
      _fail('weighted threshold mixes weights and clauses');
    }
    return WeightedThreshold([
      for (final clause in clauses)
        () {
          if (clause.isEmpty) {
            _fail('weighted threshold clause must have at least one weight');
          }
          return [
            for (final w in clause)
              w is String
                  ? _weight(w)
                  : _fail('weighted threshold weight must be a string'),
          ];
        }(),
    ]);
  }
  _fail('invalid threshold value');
}

bool _isZero(Threshold t) => t is SimpleThreshold && t.n == BigInt.zero;

/// Whether [indices] (valid signers, by key position) meet the threshold.
bool thresholdSatisfied(Threshold t, List<int> indices, int totalKeys) {
  switch (t) {
    case SimpleThreshold(:final n):
      return n > BigInt.zero && BigInt.from(indices.length) >= n;
    case WeightedThreshold(:final clauses):
      if (clauses.isEmpty) return false;
      final has = indices.toSet();
      var keyIdx = 0;
      for (final clause in clauses) {
        var num = BigInt.zero;
        var den = BigInt.one;
        for (final w in clause) {
          if (keyIdx < totalKeys && has.contains(keyIdx)) {
            // u64 checked arithmetic, as the Rust: an overflow is not met.
            final a = num * w.den;
            final b = w.num * den;
            final nn = a + b;
            final nd = den * w.den;
            if (a >= _u64Limit ||
                b >= _u64Limit ||
                nn >= _u64Limit ||
                nd >= _u64Limit) {
              return false;
            }
            num = nn;
            den = nd;
          }
          keyIdx++;
        }
        if (num < den) return false;
      }
      return true;
  }
}

void _checkSatisfiable(Threshold t, int keys, String what) {
  final bool ok;
  switch (t) {
    case SimpleThreshold(:final n):
      ok = n >= BigInt.one && n <= BigInt.from(keys);
    case WeightedThreshold(:final clauses):
      final size = clauses.fold<int>(0, (n, c) => n + c.length);
      ok =
          size <= keys &&
          thresholdSatisfied(t, List<int>.generate(keys, (i) => i), keys);
  }
  if (!ok) _fail('$what cannot be met by $keys key(s)');
}

/// The threshold as its KERI field value (`Threshold::to_json_value`).
Object thresholdJson(Threshold t) => switch (t) {
  SimpleThreshold(:final n) => n.toRadixString(16),
  WeightedThreshold(:final clauses) => [
    for (final clause in clauses)
      [
        for (final w in clause)
          w.den == BigInt.one ? '${w.num}' : '${w.num}/${w.den}',
      ],
  ],
};

// ─── Events (affinidi-keri-core `event.rs`) ─────────────────────────────

const Map<String, String> _fieldTypes = {
  'v': 'string',
  't': 'string',
  'd': 'string',
  'i': 'string',
  's': 'string',
  'p': 'string',
  'bt': 'string',
  'di': 'string',
  'kt': 'threshold',
  'nt': 'threshold',
  'k': 'strings',
  'n': 'strings',
  'b': 'strings',
  'br': 'strings',
  'ba': 'strings',
  'c': 'strings',
  'a': 'array',
};

final Map<String, List<String>> _eventFields = {
  'icp': 'v t d i s kt k nt n bt b c a'.split(' '),
  'rot': 'v t d i s p kt k nt n bt br ba c? a'.split(' '),
  'ixn': 'v t d i s p a'.split(' '),
  'dip': 'v t d i s kt k nt n bt b c a di'.split(' '),
  'drt': 'v t d i s p kt k nt n bt br ba c? a'.split(' '),
};

/// The typed fields of a key event, as serde would deserialize them.
class _Event {
  _Event(this._f);
  final Map<String, Object?> _f;

  String get v => _f['v']! as String;
  String get d => _f['d']! as String;
  String get i => _f['i']! as String;
  String get s => _f['s']! as String;
  String get p => _f['p']! as String;
  String get bt => _f['bt']! as String;
  String get di => _f['di']! as String;
  Threshold get kt => _f['kt']! as Threshold;
  Threshold get nt => _f['nt']! as Threshold;
  List<String> get k => _f['k']! as List<String>;
  List<String> get n => _f['n']! as List<String>;
  List<String> get b => _f['b']! as List<String>;
  List<String> get br => _f['br']! as List<String>;
  List<String> get ba => _f['ba']! as List<String>;
  List<String> get c => _f['c']! as List<String>;
}

_Event _eventOf(Object? sad, String ilk) {
  final out = <String, Object?>{};
  for (final spec in _eventFields[ilk]!) {
    final optional = spec.endsWith('?');
    final label = optional ? spec.substring(0, spec.length - 1) : spec;
    // A member that is present but `null` is a type error, not a missing
    // field (serde), so presence is asked of the map.
    if (sad is! Map<String, Object?> || !sad.containsKey(label)) {
      if (optional) {
        out[label] = <String>[];
        continue;
      }
      _fail('missing field `$label`', 'json');
    }
    final value = sad[label];
    switch (_fieldTypes[label]) {
      case 'string':
        if (value is! String) {
          _fail('invalid type for `$label`: expected a string', 'json');
        }
        out[label] = value;
      case 'strings':
        if (value is! List || !value.every((x) => x is String)) {
          _fail(
            'invalid type for `$label`: expected a sequence of strings',
            'json',
          );
        }
        out[label] = value.cast<String>();
      case 'array':
        if (value is! List) {
          _fail('invalid type for `$label`: expected a sequence', 'json');
        }
        out[label] = value;
      case 'threshold':
        out[label] = parseThreshold(value);
    }
  }
  return _Event(out);
}

void _checkShape(Object? sad, String ilk) =>
    checkKeriFields(sad, protocolMajor(sad), ilk);

/// A KERI sequence number (`u64::from_str_radix(s, 16)`) while it is a safe
/// integer, else null.
int? parseSn(Object? text) => toSafeNumber(parseUnsigned(text, 16));

int _snOf(String text) {
  final sn = parseSn(text);
  if (sn == null) _fail('invalid sequence number: $text');
  return sn;
}

// ─── Key state (affinidi-keri-core `key_state.rs`) ──────────────────────

/// An identifier's key state after its latest accepted event.
class KeyState {
  KeyState({
    required this.prefix,
    required this.sn,
    required this.said,
    required this.threshold,
    required this.keys,
    required this.nextKeys,
    required this.nextThreshold,
    required this.backerThreshold,
    required this.backers,
    required this.config,
    required this.lastEventDigest,
    required this.delegated,
    required this.delegator,
    required this.protocolMajor,
  });

  final String prefix;
  final int sn;

  /// The latest establishment event's SAID.
  final String said;
  final Threshold threshold;
  final List<String> keys;
  final List<String> nextKeys;
  final Threshold nextThreshold;
  final int backerThreshold;
  final List<String> backers;
  final List<String> config;
  final String lastEventDigest;
  final bool delegated;
  final String? delegator;
  final int protocolMajor;

  KeyState copyWith({int? sn, String? lastEventDigest, int? protocolMajor}) =>
      KeyState(
        prefix: prefix,
        sn: sn ?? this.sn,
        said: said,
        threshold: threshold,
        keys: keys,
        nextKeys: nextKeys,
        nextThreshold: nextThreshold,
        backerThreshold: backerThreshold,
        backers: backers,
        config: config,
        lastEventDigest: lastEventDigest ?? this.lastEventDigest,
        delegated: delegated,
        delegator: delegator,
        protocolMajor: protocolMajor ?? this.protocolMajor,
      );
}

const String establishmentOnly = 'EO';
const String doNotDelegate = 'DND';
const List<String> _inceptionOnlyTraits = [
  establishmentOnly,
  doNotDelegate,
  'DID',
];

int _eventMajor(String version) => parseVersionString(version).major;

void _checkKeyThresholds(
  Threshold kt,
  List<String> keys,
  Threshold nt,
  List<String> nextKeys,
) {
  _checkSatisfiable(kt, keys.length, 'kt');
  if (_isZero(nt)) {
    if (nextKeys.isNotEmpty) {
      _fail('nt is 0 but n commits to ${nextKeys.length} next key(s)');
    }
    return;
  }
  _checkSatisfiable(nt, nextKeys.length, 'nt');
}

int _backerThreshold(String bt) {
  final n = toSafeNumber(parseUnsigned(bt, 16));
  if (n == null) _fail('invalid backer threshold: $bt');
  return n;
}

KeyState _fromInception(_Event e, bool delegated) {
  if (_snOf(e.s) != 0) {
    _fail(
      '${delegated ? 'delegated ' : ''}inception event must have sn=0, '
      'got ${e.s}',
    );
  }
  if (delegated && e.di == '') {
    _fail('delegated inception names no delegator (empty `di`)');
  }
  _checkKeyThresholds(e.kt, e.k, e.nt, e.n);
  final bt = _backerThreshold(e.bt);
  if (bt > e.b.length) {
    _fail('backer threshold ($bt) exceeds backer count (${e.b.length})');
  }
  return KeyState(
    prefix: e.i,
    sn: 0,
    said: e.d,
    threshold: e.kt,
    keys: e.k,
    nextKeys: e.n,
    nextThreshold: e.nt,
    backerThreshold: bt,
    backers: e.b,
    config: e.c,
    lastEventDigest: e.d,
    delegated: delegated,
    delegator: delegated ? e.di : null,
    protocolMajor: _eventMajor(e.v),
  );
}

bool _isAbandoned(KeyState state) => state.nextKeys.isEmpty;

void _rejectIfAbandoned(KeyState state) {
  if (_isAbandoned(state)) {
    _fail(
      'identifier ${state.prefix} is abandoned: its establishment event at '
      'sn ${state.sn} committed to no next keys, so no event may follow',
    );
  }
}

int _checkVersion(KeyState state, String version) {
  final major = _eventMajor(version);
  if (major < state.protocolMajor) {
    _fail(
      'event for ${state.prefix} at sn ${state.sn + 1} names KERI $major.x, '
      'but its KEL has reached ${state.protocolMajor}.x: a KEL never moves '
      'to a lower protocol version',
    );
  }
  return major;
}

List<String> _rotatedConfig(List<String> prior, int major, List<String> added) {
  final config = [...prior];
  if (major >= 2) {
    for (final t in added) {
      if (_inceptionOnlyTraits.contains(t)) continue;
      if (!config.contains(t)) config.add(t);
    }
  }
  return config;
}

KeyState _applyRotation(KeyState state, _Event e) {
  _rejectIfAbandoned(state);
  final major = _checkVersion(state, e.v);
  final sn = _snOf(e.s);
  if (sn != state.sn + 1) {
    _fail('out of order: expected sn ${state.sn + 1}, got $sn');
  }
  if (e.i != state.prefix) {
    _fail(
      "rotation prefix '${e.i}' does not match state prefix "
      "'${state.prefix}'",
    );
  }
  if (e.p != state.lastEventDigest) {
    _fail(
      "prior SAID mismatch: expected '${state.lastEventDigest}', "
      "got '${e.p}'",
    );
  }
  _checkKeyThresholds(e.kt, e.k, e.nt, e.n);
  final bt = _backerThreshold(e.bt);
  final backers = state.backers.where((b) => !e.br.contains(b)).toList();
  for (final b in e.ba) {
    if (!backers.contains(b)) backers.add(b);
  }
  if (bt > backers.length) {
    _fail('backer threshold ($bt) exceeds backer count (${backers.length})');
  }
  return KeyState(
    prefix: state.prefix,
    sn: sn,
    said: e.d,
    threshold: e.kt,
    keys: e.k,
    nextKeys: e.n,
    nextThreshold: e.nt,
    backerThreshold: bt,
    backers: backers,
    config: _rotatedConfig(state.config, major, e.c),
    lastEventDigest: e.d,
    delegated: state.delegated,
    delegator: state.delegator,
    protocolMajor: major,
  );
}

KeyState _applyInteraction(KeyState state, _Event e) {
  _rejectIfAbandoned(state);
  if (state.config.contains(establishmentOnly)) {
    _fail(
      'the identifier is establishment-only (EO): interaction events are '
      'not allowed',
    );
  }
  final major = _checkVersion(state, e.v);
  final sn = _snOf(e.s);
  if (sn != state.sn + 1) {
    _fail('out of order: expected sn ${state.sn + 1}, got $sn');
  }
  if (e.i != state.prefix) {
    _fail(
      "interaction prefix '${e.i}' does not match state prefix "
      "'${state.prefix}'",
    );
  }
  if (e.p != state.lastEventDigest) {
    _fail(
      "prior SAID mismatch: expected '${state.lastEventDigest}', "
      "got '${e.p}'",
    );
  }
  return state.copyWith(sn: sn, lastEventDigest: e.d, protocolMajor: major);
}

// ─── Delegation (affinidi-keri-core `delegation.rs`) ────────────────────

/// Where a delegated event says its delegator anchored it.
class DelegationProof {
  DelegationProof(this.sn, this.said);
  final BigInt sn;
  final String said;
}

DelegationProof _delegationProofOf(String snQb64, String saidQb64) {
  Uint8List raw;
  try {
    raw = numberRaw(snQb64);
  } on KeriError catch (e) {
    _fail('invalid seal source sequence number: ${e.message}', 'parse');
  }
  final highLen = raw.length - 8 > 0 ? raw.length - 8 : 0;
  if (raw.sublist(0, highLen).any((b) => b != 0)) {
    _fail('seal source sequence number exceeds u64', 'parse');
  }
  var sn = BigInt.zero;
  for (final b in raw.sublist(highLen)) {
    sn = (sn << 8) | BigInt.from(b);
  }
  try {
    matterFromQb64(saidQb64);
  } on KeriError catch (e) {
    _fail('invalid seal source SAID: ${e.message}', 'parse');
  }
  return DelegationProof(sn, saidQb64);
}

void _verifyDelegation(
  String delegatee,
  BigInt sn,
  String said,
  String delegator,
  DelegationProof proof,
  Kels source,
) {
  if (delegator == '') {
    _fail('delegated event names no delegator (empty `di`)');
  }
  if (delegator == delegatee) {
    _fail('delegated event names itself as its own delegator');
  }
  final anchors = source._anchorsAt(delegator, proof.sn, proof.said);
  if (anchors == null) {
    _fail(
      "delegator '$delegator' has no verified event at sn ${proof.sn} with "
      "SAID '${proof.said}' to anchor the delegation of '$delegatee'",
    );
  }
  final traits = source._delegatorTraits(delegator);
  if (traits == null) {
    _fail(
      "delegator '$delegator' has no verified key state to authorise the "
      "delegation of '$delegatee'",
    );
  }
  if (traits.contains(doNotDelegate)) {
    _fail(
      "delegator '$delegator' does not delegate (DND): '$delegatee' is "
      'refused',
    );
  }
  final expected = sn.toRadixString(16);
  final matched = anchors.any((a) {
    // serde `SealEvent`: i, s and d strings; other members ignored.
    final i = sadGet(a, 'i');
    final s = sadGet(a, 's');
    final d = sadGet(a, 'd');
    return i is String &&
        s is String &&
        d is String &&
        i == delegatee &&
        d == said &&
        s == expected;
  });
  if (!matched) {
    _fail(
      "delegator '$delegator' event at sn ${proof.sn} anchors no seal for "
      "'$delegatee' at sn $sn with SAID '$said'",
    );
  }
}

// ─── Kever (affinidi-keri-core `kever.rs`) ──────────────────────────────

void _verifySigsStatic(
  Uint8List message,
  List<Siger> sigs,
  List<Verfer> verfers,
  Threshold threshold,
) {
  final satisfied = <int>[];
  for (final sig in sigs) {
    if (sig.index >= verfers.length) continue;
    final valid = verifySignature(verfers[sig.index], message, sig.raw);
    if (valid && !satisfied.contains(sig.index)) satisfied.add(sig.index);
  }
  if (!thresholdSatisfied(threshold, satisfied, verfers.length)) {
    _fail('threshold not met', 'threshold');
  }
}

void _compareKeys(List<String> eventKeys, List<Verfer> verfers) {
  if (eventKeys.length != verfers.length) {
    _fail(
      'key count mismatch: event has ${eventKeys.length} keys, '
      '${verfers.length} verfers provided',
    );
  }
  for (var i = 0; i < eventKeys.length; i++) {
    if (eventKeys[i] != verfers[i].qb64) {
      _fail(
        "key[$i] mismatch: event key '${eventKeys[i]}' != verfer "
        "'${verfers[i].qb64}'",
      );
    }
  }
}

void _validatePrefixDerivation(_Event e) {
  var digest = false;
  try {
    digest = isDigestCode(matterFromQb64(e.i).code);
  } on KeriError {
    digest = false;
  }
  if (digest) {
    if (e.i != e.d) {
      _fail('self-addressing prefix does not match event SAID (i != d)');
    }
    return;
  }
  var basic = false;
  try {
    verfer(e.i);
    basic = true;
  } on KeriError {
    basic = false;
  }
  if (basic) {
    if (e.k.isEmpty || e.i != e.k[0]) {
      _fail('basic prefix does not match first public key');
    }
    return;
  }
  _fail('prefix is neither a valid digest code nor a valid key code');
}

/// Verifies one identifier's KEL event by event.
class _Kever {
  _Kever(this.state, this.est, this.since);

  KeyState state;
  KeyState est;

  /// (digest, protocol major) of each interaction since [est].
  List<(String, int)> since;

  static _Kever incept(Serder serder, List<Siger> sigs, List<Verfer> verfers) {
    final ilk = sadStr(sadGet(serder.sad, 't'));
    if (ilk == null) _fail('missing field t');
    if (ilk == 'dip') {
      _fail(
        "'dip' is a delegated inception; use Kever::new_delegated, which "
        "verifies the delegator's anchoring seal",
      );
    }
    if (ilk != 'icp') _fail("expected 'icp', got '$ilk'");
    verifySaid(serder.sad, 'd', 'E', serder.kind);
    _checkShape(serder.sad, 'icp');
    final e = _eventOf(serder.sad, 'icp');
    _compareKeys(e.k, verfers);
    _verifySigsStatic(serder.raw, sigs, verfers, e.kt);
    _validatePrefixDerivation(e);
    final state = _fromInception(e, false);
    return _Kever(state, state, []);
  }

  static _Kever inceptDelegated(
    Serder serder,
    List<Siger> sigs,
    List<Verfer> verfers,
    DelegationProof proof,
    Kels source,
  ) {
    final ilk = sadStr(sadGet(serder.sad, 't'));
    if (ilk == null) _fail('missing field t');
    if (ilk != 'dip') _fail("expected 'dip', got '$ilk'");
    verifySaid(serder.sad, 'd', 'E', serder.kind);
    _checkShape(serder.sad, 'dip');
    final e = _eventOf(serder.sad, 'dip');
    _compareKeys(e.k, verfers);
    _verifySigsStatic(serder.raw, sigs, verfers, e.kt);
    if (e.i != e.d) {
      _fail('delegated inception prefix does not match event SAID (i != d)');
    }
    _verifyDelegation(e.i, BigInt.zero, e.d, e.di, proof, source);
    final state = _fromInception(e, true);
    return _Kever(state, state, []);
  }

  /// Verify the next event, returning the state it would install.
  KeyState verifyUpdate(Serder serder, List<Siger> sigs) {
    verifySaid(serder.sad, 'd', 'E', serder.kind);
    final ilk = sadStr(sadGet(serder.sad, 't'));
    if (ilk == null) _fail('missing field t');
    final sn = parseSn(sadStr(sadGet(serder.sad, 's')));
    if (sn == null) _fail('missing field s');
    if (ilk == 'rot' && sn <= state.sn) {
      return _recoveryBase(sn).verifyUpdate(serder, sigs);
    }
    if (sn != state.sn + 1) {
      _fail('out of order: expected sn ${state.sn + 1}, got $sn');
    }
    if (ilk == 'rot') {
      if (state.delegated) {
        _fail("identifier is delegated and must rotate with 'drt', not 'rot'");
      }
      _checkShape(serder.sad, 'rot');
      final e = _eventOf(serder.sad, 'rot');
      _verifyRotationSigs(serder.raw, sigs, e.k, e.kt);
      return _applyRotation(state, e);
    }
    if (ilk == 'ixn') {
      final verfers = state.keys.map(verfer).toList();
      _verifySigsStatic(serder.raw, sigs, verfers, state.threshold);
      _checkShape(serder.sad, 'ixn');
      return _applyInteraction(state, _eventOf(serder.sad, 'ixn'));
    }
    if (ilk == 'drt') {
      _fail(
        "'drt' is a delegated rotation; use Kever::verify_update_delegated, "
        "which verifies the delegator's anchoring seal",
      );
    }
    _fail("expected 'rot' or 'ixn' for update, got '$ilk'");
  }

  KeyState verifyUpdateDelegated(
    Serder serder,
    List<Siger> sigs,
    DelegationProof proof,
    Kels source,
  ) {
    verifySaid(serder.sad, 'd', 'E', serder.kind);
    final ilk = sadStr(sadGet(serder.sad, 't'));
    if (ilk == null) _fail('missing field t');
    if (ilk != 'drt') _fail("expected 'drt', got '$ilk'");
    final sn = parseSn(sadStr(sadGet(serder.sad, 's')));
    if (sn == null) _fail('missing field s');
    if (sn <= state.sn) {
      _fail(
        'a delegated rotation at sn $sn would supersede the event there: '
            'superseding delegated rotations (KERI recovery rule B) are not '
            'supported',
        'unsupported',
      );
    }
    if (sn != state.sn + 1) {
      _fail('out of order: expected sn ${state.sn + 1}, got $sn');
    }
    _checkShape(serder.sad, 'drt');
    final e = _eventOf(serder.sad, 'drt');
    final delegator = state.delegator;
    if (delegator == null || delegator.isEmpty) {
      _fail('delegated identifier has no recorded delegator');
    }
    _verifyRotationSigs(serder.raw, sigs, e.k, e.kt);
    _verifyDelegation(e.i, BigInt.from(sn), e.d, delegator, proof, source);
    if (!state.delegated) {
      _fail(
        'delegated rotation applied to an identifier that was not delegated',
      );
    }
    return _applyRotation(state, e);
  }

  void applyVerifiedUpdate(KeyState next) {
    if (next.said == next.lastEventDigest) {
      est = next;
      since = [];
    } else {
      since.add((next.lastEventDigest, next.protocolMajor));
    }
    state = next;
  }

  /// The log as it stood at `sn - 1`, for a superseding rotation at `sn`.
  _Kever _recoveryBase(int sn) {
    if (sn <= est.sn) {
      _fail(
        'stale rotation at sn $sn: the last establishment event is at sn '
        '${est.sn}, and a rotation supersedes only interaction events after '
        'it',
      );
    }
    final kept = sn - 1 - est.sn;
    var base = est.copyWith(sn: sn - 1);
    if (kept >= 1 && kept - 1 < since.length) {
      base = base.copyWith(
        lastEventDigest: since[kept - 1].$1,
        protocolMajor: since[kept - 1].$2,
      );
    }
    return _Kever(
      base,
      est,
      since.sublist(0, kept < since.length ? kept : since.length),
    );
  }

  /// A rotation is signed by the keys it installs and must meet its own `kt`
  /// over them, and the prior `nt` over the committed digests its signatures
  /// expose (keripy `Kever.exposeds`).
  void _verifyRotationSigs(
    Uint8List raw,
    List<Siger> sigs,
    List<String> keys,
    Threshold kt,
  ) {
    if (_isAbandoned(state)) {
      _fail(
        'identifier ${state.prefix} is abandoned: its last establishment '
        'event committed to no next keys, so it cannot rotate',
      );
    }
    final verfers = keys.map(verfer).toList();
    _verifySigsStatic(raw, sigs, verfers, kt);
    final prior = state.nextKeys;
    final exposed = <int>[];
    for (final sig in sigs) {
      final ondex = sig.ondex;
      if (ondex == null || sig.index >= keys.length) continue;
      if (ondex >= prior.length) continue;
      final digestQb64 = prior[ondex];
      if (exposed.contains(ondex) ||
          !verifySignature(verfers[sig.index], raw, sig.raw)) {
        continue;
      }
      bool matches;
      try {
        matches = digestMatches(digestQb64, utf8Bytes(keys[sig.index]));
      } on KeriError catch (e) {
        _fail('invalid prior next-key digest at $ondex: ${e.message}');
      }
      if (matches) exposed.add(ondex);
    }
    if (!thresholdSatisfied(state.nextThreshold, exposed, prior.length)) {
      _fail('threshold not met', 'threshold');
    }
  }
}

void _verifyWitnessReceipts(
  Uint8List message,
  List<(String, Uint8List)> couples,
  List<String> backers,
  int threshold,
) {
  if (threshold == 0) return;
  final valid = <String>[];
  for (final (prefix, sig) in couples) {
    if (!backers.contains(prefix) || valid.contains(prefix)) continue;
    if (verifySignature(verfer(prefix), message, sig)) valid.add(prefix);
  }
  if (valid.length < threshold) {
    _fail(
      'witness receipt threshold not met: need $threshold, got '
      '${valid.length}',
    );
  }
}

// ─── Kels (affinidi-did-webs `kel.rs`) ──────────────────────────────────

const Set<String> _keyEventIlks = {'icp', 'rot', 'ixn', 'dip', 'drt'};
const Set<String> _establishmentIlks = {'icp', 'rot', 'dip', 'drt'};

/// A key event log that does not verify (`DidWebsError::Kel`).
class KelError implements Exception {
  KelError(this.message);
  final String message;

  @override
  String toString() => 'KelError: $message';
}

/// A stream that cannot be parsed (`DidWebsError::Stream`).
class StreamError implements Exception {
  StreamError(this.message);
  final String message;

  @override
  String toString() => 'StreamError: $message';
}

Never _kelFail(String message) => throw KelError(message);

String? _ilkOf(ParsedMessage msg) => sadStr(sadGet(msg.serder.sad, 't'));
String? _saidOf(ParsedMessage msg) => sadStr(sadGet(msg.serder.sad, 'd'));
String? _prefixOf(ParsedMessage msg) => sadStr(sadGet(msg.serder.sad, 'i'));
int? _snOfMsg(ParsedMessage msg) =>
    parseSn(sadStr(sadGet(msg.serder.sad, 's')));

/// An accepted event as the registry reader takes it (`LoggedEvent`).
class LoggedEvent {
  LoggedEvent(this.sn, this.said, this.seals, this.establishment);
  final int sn;
  final String said;
  final List<Object?> seals;

  /// The key state the event installed, when it is an establishment event.
  final KeyState? establishment;
}

/// An identifier's verified KEL as the registry reader takes it.
class IssuerLog {
  IssuerLog(this.prefix, this.events, this.superseded, this.limit);
  final String prefix;
  final List<LoggedEvent> events;
  final List<LoggedEvent> superseded;

  /// The last sequence number this read may see (`versionId`), if limited.
  final int? limit;
}

LoggedEvent _logged(ParsedMessage msg, KeyState state, bool establishment) {
  final said = _saidOf(msg);
  if (said == null) _kelFail('key event has no SAID: missing field d');
  final a = sadGet(msg.serder.sad, 'a');
  return LoggedEvent(
    state.sn,
    said,
    a is List ? a.cast<Object?>() : const [],
    establishment ? state : null,
  );
}

class _Recorded {
  List<LoggedEvent> events = [];
  final List<LoggedEvent> superseded = [];
}

class _AtResult {
  _AtResult.state(this.state) : error = null;
  _AtResult.error(Exception this.error) : state = null;
  final KeyState? state;
  final Exception? error;
}

/// The key event logs of a `keri.cesr` stream, grouped by identifier, with
/// verification results remembered as they are computed.
class Kels {
  Kels._(this.messages, this._byPrefix, this._fullByPrefix, this._limits);

  final List<ParsedMessage> messages;
  final Map<String, List<int>> _byPrefix;
  final Map<String, List<int>> _fullByPrefix;
  final Map<String, int> _limits;
  final Map<String, KeyState> _verified = {};
  final List<String> _inProgress = [];
  final Map<String, List<int>> _superseded = {};
  final Map<String, _AtResult> _atCache = {};
  final Map<String, IssuerLog> _issuerLogs = {};
  Map<String, List<(String, Uint8List)>>? _receipts;

  /// The identifiers with key events in this read, in stream order.
  Iterable<String> get prefixes => _byPrefix.keys;

  /// Parse a stream and group its key events by identifier (`Kels::parse`).
  /// [maxMessages] null means no limit on the message count.
  static Kels parse(Uint8List stream, {int? maxMessages = maxStreamMessages}) {
    List<ParsedMessage> messages;
    try {
      messages = parseAll(stream, maxMessages: maxMessages);
    } on KeriError catch (e) {
      throw StreamError('could not parse keri.cesr: ${e.message}');
    }
    // Bounds checked before anything is verified (`kel::MAX_STREAM_*`).
    var signatures = 0;
    var backers = 0;
    var seals = 0;
    for (final msg in messages) {
      for (final a in msg.attachments) {
        switch (a) {
          case ControllerSigs(:final sigs):
          case WitnessSigs(:final sigs):
            signatures += sigs.length;
          case ReceiptCouples(:final couples):
            signatures += couples.length;
          case TransIdxSigGroups(:final groups):
            signatures += groups.fold<int>(0, (n, g) => n + g.sigs.length);
          default:
            break;
        }
      }
      if (!_keyEventIlks.contains(_ilkOf(msg))) continue;
      int entries(String label) {
        final v = sadGet(msg.serder.sad, label);
        return v is List ? v.length : 0;
      }

      backers += entries('b') + entries('ba');
      seals += entries('a');
    }
    if (signatures > maxStreamSignatures) {
      throw StreamError(
        'keri.cesr carries more than the $maxStreamSignatures signatures '
        'this resolver checks',
      );
    }
    if (backers > maxStreamBackers) {
      throw StreamError(
        "keri.cesr's key events name $backers witnesses, more than the "
        '$maxStreamBackers this resolver reads',
      );
    }
    if (seals > maxStreamSeals) {
      throw StreamError(
        "keri.cesr's key events anchor $seals seals, more than the "
        '$maxStreamSeals this resolver reads',
      );
    }
    final byPrefix = <String, List<int>>{};
    for (var i = 0; i < messages.length; i++) {
      final msg = messages[i];
      if (!_keyEventIlks.contains(_ilkOf(msg))) continue;
      final prefix = _prefixOf(msg);
      if (prefix == null) continue;
      (byPrefix[prefix] ??= []).add(i);
    }
    final full = {
      for (final e in byPrefix.entries) e.key: [...e.value],
    };
    return Kels._(messages, byPrefix, full, {});
  }

  /// The SAID of [prefix]'s first key event.
  String? inceptionSaid(String prefix) {
    final indices = _byPrefix[prefix];
    if (indices == null || indices.isEmpty) return null;
    return _saidOf(messages[indices.first]);
  }

  /// The sequence numbers of [prefix]'s key events, in stream order.
  List<int> sequenceNumbers(String prefix) => [
    for (final i in _byPrefix[prefix] ?? const <int>[]) ?_snOfMsg(messages[i]),
  ];

  /// This stream with [prefix]'s events after [sn] set aside (`versionId`).
  Kels asOf(String prefix, int sn) {
    if (!sequenceNumbers(prefix).contains(sn)) {
      _kelFail('$prefix has no key event at sequence number $sn');
    }
    final byPrefix = {
      for (final e in _byPrefix.entries) e.key: [...e.value],
    };
    final own = byPrefix[prefix];
    if (own != null) {
      byPrefix[prefix] = own.where((i) {
        final s = _snOfMsg(messages[i]);
        return s != null && s <= sn;
      }).toList();
    }
    final limits = {..._limits, prefix: sn};
    return Kels._(messages, byPrefix, _fullByPrefix, limits);
  }

  /// Whether [prefix]'s latest establishment event is a rotation to no next
  /// keys.
  bool isDeactivated(String prefix) {
    final est = [
      for (final i in _byPrefix[prefix] ?? const <int>[])
        if (_establishmentIlks.contains(_ilkOf(messages[i]))) messages[i],
    ];
    if (est.isEmpty) return false;
    final last = est.last;
    final ilk = _ilkOf(last);
    final n = sadGet(last.serder.sad, 'n');
    return (ilk == 'rot' || ilk == 'drt') && n is List && n.isEmpty;
  }

  /// Verify [prefix]'s key event log and return its key state.
  KeyState keyState(String prefix) {
    final cached = _verified[prefix];
    if (cached != null) return cached;
    if (_inProgress.contains(prefix)) {
      _kelFail(
        'delegation cycle: $prefix is its own delegator, directly or through '
        '${_inProgress.length - 1} intermediate identifiers',
      );
    }
    if (_inProgress.length >= _maxDelegationDepth) {
      _kelFail('delegation chain deeper than $_maxDelegationDepth');
    }
    _inProgress.add(prefix);
    KeyState state;
    try {
      state = _replay(prefix, null);
    } finally {
      _inProgress.removeLast();
    }
    _verified[prefix] = state;
    return state;
  }

  /// The digests (`d`) of every seal [aid]'s verified key events anchor, as
  /// far as this read sees, superseded events included (`anchored_digests`).
  Set<String> anchoredDigests(String aid) {
    keyState(aid);
    final out = <String>{};
    for (final i in _byPrefix[aid] ?? const <int>[]) {
      final a = sadGet(messages[i].serder.sad, 'a');
      if (a is! List) continue;
      for (final seal in a) {
        final d = sadStr(sadGet(seal, 'd'));
        if (d != null) out.add(d);
      }
    }
    return out;
  }

  /// Every message whose `t` is [ilk].
  List<ParsedMessage> messagesWithIlk(String ilk) =>
      messages.where((m) => _ilkOf(m) == ilk).toList();

  /// The key state at a named establishment event (`Kels::key_state_at`).
  KeyState keyStateAt(String aid, String said) {
    keyState(aid);
    final key = '$aid\u0000$said';
    final hit = _atCache[key];
    if (hit != null) {
      if (hit.error != null) throw hit.error!;
      return hit.state!;
    }
    try {
      ParsedMessage? named;
      for (final i in _byPrefix[aid] ?? const <int>[]) {
        if (_saidOf(messages[i]) == said) {
          named = messages[i];
          break;
        }
      }
      if (named == null) {
        _kelFail('$aid has no event with SAID $said to sign under');
      }
      final ilk = _ilkOf(named) ?? '';
      if (!_establishmentIlks.contains(ilk)) {
        _kelFail(
          '$said is a ${jsonQuote(ilk)} event, not an establishment event, '
          'so it names no key state',
        );
      }
      final state = _replay(aid, said);
      _atCache[key] = _AtResult.state(state);
      return state;
    } on Exception catch (error) {
      _atCache[key] = _AtResult.error(error);
      rethrow;
    }
  }

  /// Verify a transferable signature group from [signer] over [raw], under
  /// the key state of the establishment event it names, meeting that state's
  /// threshold (`Kels::verify_signature_group`).
  KeyState verifySignatureGroup(
    String signer,
    Uint8List raw,
    TransIdxSigGroup group,
  ) {
    if (group.prefix != signer) {
      _kelFail('signature group is from ${group.prefix}, not $signer');
    }
    final state = keyStateAt(signer, group.said);
    BigInt sn;
    try {
      sn = numberValue(group.sn);
    } on KeriError catch (e) {
      _kelFail('signature group from $signer: ${e.message}');
    }
    if (sn != BigInt.from(state.sn)) {
      _kelFail(
        'signature group from $signer names establishment event '
        '${group.said} at sn $sn, but it is at sn ${state.sn}',
      );
    }
    final verified = <int>[];
    for (final sig in group.sigs) {
      if (verified.contains(sig.index)) continue;
      if (sig.index >= state.keys.length) continue;
      final key = state.keys[sig.index];
      Verfer v;
      try {
        v = verfer(key);
      } on KeriError catch (e) {
        _kelFail('$signer key state has an unusable key: ${e.message}');
      }
      var ok = false;
      try {
        ok = verifySignature(v, raw, sig.raw);
      } on Exception {
        ok = false;
      }
      if (ok) verified.add(sig.index);
    }
    if (!thresholdSatisfied(state.threshold, verified, state.keys.length)) {
      _kelFail(
        '${verified.length} valid signature(s) from $signer do not meet its '
        'signing threshold at sn ${state.sn}',
      );
    }
    return state;
  }

  /// [aid]'s verified KEL as the registry reader takes it: every event of the
  /// whole stream, limited to what this read may see (`Kels::issuer_log`).
  IssuerLog issuerLog(String aid) {
    keyState(aid);
    final cached = _issuerLogs[aid];
    if (cached != null) return cached;
    final indices = _fullByPrefix[aid];
    if (indices == null) _kelFail('keri.cesr carries no key events for $aid');
    final recorded = _Recorded();
    _replayOver(aid, indices, null, recorded);
    final log = IssuerLog(
      aid,
      recorded.events,
      recorded.superseded,
      _limits[aid],
    );
    _issuerLogs[aid] = log;
    return log;
  }

  KeyState _replay(String prefix, String? stopAfter) {
    final indices = _byPrefix[prefix];
    if (indices == null) {
      _kelFail('keri.cesr carries no key events for $prefix');
    }
    return _replayOver(prefix, indices, stopAfter, null);
  }

  KeyState _replayOver(
    String prefix,
    List<int> indices,
    String? stopAfter,
    _Recorded? log,
  ) {
    if (indices.isEmpty) _kelFail('keri.cesr carries no events for $prefix');
    final firstIndex = indices.first;
    final first = messages[firstIndex];
    final kever = _incept(prefix, first);
    _requireWitnessReceipts(prefix, first, kever.state);
    log?.events.add(_logged(first, kever.state, true));
    var accepted = <(int, int)>[(firstIndex, 0)];
    final superseded = <int>[];
    if (stopAfter != null && _saidOf(first) == stopAfter) return kever.state;
    var reached = false;
    for (var n = 0; n < indices.length - 1; n++) {
      final index = indices[n + 1];
      final msg = messages[index];
      final ilk = _ilkOf(msg);
      if (ilk == null) _kelFail('event ${n + 1} has no ilk: missing field t');
      final sigs = controllerSigs(msg);
      KeyState state;
      if (ilk == 'drt') {
        final proof = _delegationProof(msg);
        try {
          state = kever.verifyUpdateDelegated(msg.serder, sigs, proof, this);
        } on KeriError catch (e) {
          _kelFail('$prefix delegated rotation ${n + 1}: ${e.message}');
        }
      } else {
        try {
          state = kever.verifyUpdate(msg.serder, sigs);
        } on KeriError catch (e) {
          _kelFail('$prefix event ${n + 1}: ${e.message}');
        }
      }
      _requireWitnessReceipts(prefix, msg, state);
      final before = kever.state.sn;
      kever.applyVerifiedUpdate(state);
      final sn = kever.state.sn;
      if (sn <= before) {
        // A superseding rotation: what it superseded leaves the log.
        superseded.addAll([
          for (final (i, s) in accepted)
            if (s >= sn) i,
        ]);
        accepted = [
          for (final a in accepted)
            if (a.$2 < sn) a,
        ];
        if (log != null) {
          log.superseded.addAll(log.events.where((e) => e.sn >= sn));
          log.events = log.events.where((e) => e.sn < sn).toList();
        }
      }
      accepted.add((index, sn));
      log?.events.add(_logged(msg, kever.state, ilk != 'ixn'));
      if (stopAfter != null && _saidOf(msg) == stopAfter) {
        reached = true;
        break;
      }
    }
    if (stopAfter == null && log == null) _superseded[prefix] = superseded;
    if (stopAfter != null && !reached) {
      _kelFail(
        '$prefix has no event with SAID $stopAfter to verify a signature '
        'against',
      );
    }
    return kever.state;
  }

  void _requireWitnessReceipts(
    String prefix,
    ParsedMessage msg,
    KeyState state,
  ) {
    if (state.backerThreshold == 0) return;
    try {
      _verifyWitnessReceipts(
        msg.serder.raw,
        _receiptCouplesFor(msg),
        state.backers,
        state.backerThreshold,
      );
    } on KeriError catch (e) {
      _kelFail(
        '$prefix event at sn ${state.sn} declares ${state.backerThreshold} of '
        '${state.backers.length} witnesses but ${e.message}',
      );
    }
  }

  /// Receipt couples attached to [msg], and those of every `rct` naming it.
  List<(String, Uint8List)> _receiptCouplesFor(ParsedMessage msg) {
    final couples = [
      for (final a in msg.attachments.whereType<ReceiptCouples>()) ...a.couples,
    ];
    final said = _saidOf(msg);
    final prefix = _prefixOf(msg);
    final sn = _snOfMsg(msg);
    if (said == null || prefix == null || sn == null) return couples;
    final receipts = _receipts ??= () {
      final out = <String, List<(String, Uint8List)>>{};
      for (final rct in messagesWithIlk('rct')) {
        final sad = rct.serder.sad;
        // JS `[undefined].join()` writes an absent member as "".
        final key = [
          sadStr(sadGet(sad, 'd')) ?? '',
          sadStr(sadGet(sad, 'i')) ?? '',
          sadStr(sadGet(sad, 's')) ?? '',
        ].join('\u0000');
        (out[key] ??= []).addAll([
          for (final a in rct.attachments.whereType<ReceiptCouples>())
            ...a.couples,
        ]);
      }
      return out;
    }();
    return [
      ...couples,
      ...?receipts[[said, prefix, sn.toRadixString(16)].join('\u0000')],
    ];
  }

  _Kever _incept(String prefix, ParsedMessage msg) {
    final ilk = _ilkOf(msg);
    if (ilk == null) {
      _kelFail('$prefix first event has no ilk: missing field t');
    }
    final verfers = _verfersFromEvent(msg.serder.sad);
    final sigs = controllerSigs(msg);
    if (ilk == 'icp') {
      try {
        return _Kever.incept(msg.serder, sigs, verfers);
      } on KeriError catch (e) {
        _kelFail('$prefix inception: ${e.message}');
      }
    }
    if (ilk == 'dip') {
      final proof = _delegationProof(msg);
      try {
        return _Kever.inceptDelegated(msg.serder, sigs, verfers, proof, this);
      } on KeriError catch (e) {
        _kelFail('$prefix delegated inception: ${e.message}');
      }
    }
    _kelFail(
      "$prefix's key event log starts with a ${jsonQuote(ilk)} event, not an "
      'inception',
    );
  }

  DelegationProof _delegationProof(ParsedMessage msg) {
    final couples = sealSourceCouples(msg);
    if (couples.isEmpty) {
      _kelFail(
        'delegated event carries no seal source couple, so there is nothing '
        "pointing at the delegator's authorisation",
      );
    }
    try {
      return _delegationProofOf(couples[0].$1, couples[0].$2);
    } on KeriError catch (e) {
      _kelFail('unreadable seal source couple: ${e.message}');
    }
  }

  // The delegator lookup (`DelegatorAnchors`): only ever answers from a KEL
  // this stream has verified.

  List<Object?>? _anchorsAt(String delegator, BigInt sn, String said) {
    try {
      keyState(delegator);
    } on Exception {
      return null;
    }
    final indices = _byPrefix[delegator];
    if (indices == null) return null;
    final superseded = _superseded[delegator] ?? const <int>[];
    for (final i in indices) {
      if (superseded.contains(i)) continue;
      final msg = messages[i];
      final msn = _snOfMsg(msg);
      if (msn == null || BigInt.from(msn) != sn) continue;
      if (_saidOf(msg) != said) continue;
      final a = sadGet(msg.serder.sad, 'a');
      return a is List ? a.cast<Object?>() : const [];
    }
    return null;
  }

  List<String>? _delegatorTraits(String delegator) {
    try {
      return keyState(delegator).config;
    } on Exception {
      return null;
    }
  }
}

List<Verfer> _verfersFromEvent(Object? sad) {
  final keys = sadGet(sad, 'k');
  if (keys is! List) _kelFail('establishment event has no key list');
  return [
    for (final k in keys)
      if (k is! String)
        _kelFail('key list contains a non-string')
      else
        () {
          try {
            return verfer(k);
          } on KeriError catch (e) {
            _kelFail('key ${jsonQuote(k)} is not usable: ${e.message}');
          }
        }(),
  ];
}
