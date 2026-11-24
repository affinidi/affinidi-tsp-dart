// Designations for the did:webs resolver: credentials an AID issues to
// itself to say something about its own DID document, and the registries
// that say whether each still stands.
//
// A port of OpenVTC/vti-didcomm-js `src/did-webs-designations.js`, itself a
// port of `affinidi-keri-core` 0.8.1 `registry.rs` (both registry versions:
// ACDC 1.x credentials in `vcp`/`iss`/`rev` TELs, ACDC 2.x credentials bound
// to `rip`/`bup` blindable registries) and of `affinidi-did-webs` 0.13.1
// `designation.rs`, `aliases.rs`, `key_agreement.rs`,
// `designated_services.rs` and `key_roles.rs`.
//
// Every link is checked. A credential that does not verify contributes
// nothing and is reported as rejected. A fault that makes a registry
// meaningless — above all a registry event the issuer's KEL anchors that the
// stream leaves out, which would let a host withhold a revocation — fails
// resolution ([RegistryError]).
//
// Where the JS throws a plain `Error` this throws a [DesignationError]; the
// messages are the JS port's, word for word.

// ignore_for_file: public_member_api_docs

import 'dart:typed_data';

import 'cesr.dart';
import 'kel.dart';
import 'signatures.dart';

/// A designation registry is broken, or withheld (`DidWebsError::Registry`).
class RegistryError implements Exception {
  RegistryError(this.message);
  final String message;

  @override
  String toString() => 'RegistryError: $message';
}

/// A key a designation names cannot be published
/// (`DidWebsError::InvalidKey`).
class InvalidKeyError implements Exception {
  InvalidKeyError(this.message);
  final String message;

  @override
  String toString() => 'InvalidKeyError: $message';
}

/// A designation that does not hold (the JS port's plain `Error`).
class DesignationError implements Exception {
  DesignationError(this.message);
  final String message;

  @override
  String toString() => 'DesignationError: $message';
}

/// The message of an exception this layer reports as a reason.
String reasonOf(Exception e) => switch (e) {
  KeriError(:final message) => message,
  KelError(:final message) => message,
  StreamError(:final message) => message,
  RegistryError(:final message) => message,
  InvalidKeyError(:final message) => message,
  DesignationError(:final message) => message,
  PointError(:final message) => message,
  _ => '$e',
};

Never _registryFail(String message) => throw RegistryError(message);
Never _plain(String message) => throw DesignationError(message);

bool _isKeri(ParsedMessage m) => m.serder.version?.protocol == 'KERI';
bool _isAcdc(ParsedMessage m) => m.serder.version?.protocol == 'ACDC';
String? _ilkOf(ParsedMessage m) => sadStr(sadGet(m.serder.sad, 't'));
String? _saidOf(ParsedMessage m) => sadStr(sadGet(m.serder.sad, 'd'));
String? _field(ParsedMessage m, String label) =>
    sadStr(sadGet(m.serder.sad, label));

// ─── Registries (affinidi-keri-core `registry.rs`) ──────────────────────

List<LoggedEvent> _visible(IssuerLog log) => [
  for (final e in log.events)
    if (log.limit == null || e.sn <= log.limit!) e,
];

/// Where a seal is anchored: within the read (at [sn], [said]), later than
/// it, or nowhere.
class _Anchor {
  const _Anchor.within(int this.sn, String this.said) : later = false;
  const _Anchor.later() : sn = null, said = null, later = true;
  const _Anchor.absent() : sn = null, said = null, later = false;

  final int? sn;
  final String? said;
  final bool later;

  bool get within => sn != null;
  bool get absent => sn == null && !later;
}

/// Where the first seal matching [matches] is anchored.
_Anchor _anchoring(IssuerLog log, bool Function(Object? seal) matches) {
  for (final e in log.events) {
    if (e.seals.any(matches)) {
      return log.limit == null || e.sn <= log.limit!
          ? _Anchor.within(e.sn, e.said)
          : const _Anchor.later();
    }
  }
  if (log.superseded.any((e) => e.seals.any(matches))) {
    return const _Anchor.later();
  }
  return const _Anchor.absent();
}

KeyState? _keyStateAt(IssuerLog log, String said) {
  for (final e in log.events) {
    if (e.said == said) return e.establishment;
  }
  return null;
}

String? _schemaSaid(Map<String, Object?> sad) {
  final s = sad['s'];
  if (s is String) return s;
  if (s is Map) return sadStr(s[r'$id']);
  return null;
}

bool _isCredential(ParsedMessage m) {
  if (!_isAcdc(m)) return false;
  final t = _ilkOf(m);
  return t == null || t == 'acm';
}

/// Every registry event the issuer's KEL anchors must be in the stream.
void _checkAnchoredEventsPresent(
  List<ParsedMessage> stream,
  IssuerLog log,
  Set<String> saids,
) {
  final subjects = <String>{};
  for (final m in stream) {
    if (!_isKeri(m) || !const ['vcp', 'iss', 'bis'].contains(_ilkOf(m))) {
      continue;
    }
    final d = _saidOf(m);
    final i = _field(m, 'i');
    if (d != null) subjects.add(d);
    if (i != null) subjects.add(i);
  }
  for (final event in _visible(log)) {
    for (final seal in event.seals) {
      if (seal is! Map<String, Object?>) continue;
      final d = sadStr(seal['d']);
      if (d == null) continue;
      final keys = seal.keys.toList();
      var attributable = false;
      if (keys.length == 2 && keys[0] == 's' && keys[1] == 'd') {
        attributable = true;
      } else if (keys.length == 3 &&
          keys[0] == 'i' &&
          keys[1] == 's' &&
          keys[2] == 'd') {
        final i = sadStr(seal['i']);
        attributable = i != null && subjects.contains(i);
      }
      if (attributable && !saids.contains(d)) {
        _registryFail(
          "the issuer's KEL anchors registry event $d at sn ${event.sn}, but "
          'the stream does not carry it',
        );
      }
    }
  }
}

String _digestCode(String said) {
  if (said.startsWith('E')) return 'E';
  _plain('$said is not a Blake3-256 SAID');
}

String _recompute(Object? sad, String label, String code, String kind) {
  try {
    return computeSaid(sad, label, code, kind);
  } on Exception catch (e) {
    _plain('cannot compute the SAID: ${reasonOf(e)}');
  }
}

String _verifyPlainSaid(ParsedMessage m) {
  final said = _saidOf(m);
  if (said == null) _plain('the message has no SAID');
  final computed = _recompute(
    m.serder.sad,
    'd',
    _digestCode(said),
    m.serder.kind,
  );
  if (computed != said) {
    _plain("the message's SAID is $said, but its content gives $computed");
  }
  return said;
}

/// A credential a registry vouches for.
class _Credential {
  _Credential(
    this.said,
    this.version,
    this.registry,
    this.event,
    this.revoked,
    this.sad,
  );
  final String said;
  final int version;
  final String registry;
  final String event;
  final bool revoked;
  final Map<String, Object?> sad;
}

/// What reading one credential gave: a credential, a rejection, or nothing.
class _Found {
  const _Found.credential(_Credential this.credential) : rejected = null;
  const _Found.rejected(String this.rejected) : credential = null;
  final _Credential? credential;
  final String? rejected;
}

/// ACDC 1.x: a signed credential in a 1.x TEL.
_Found? _credentialV1(
  List<ParsedMessage> stream,
  IssuerLog log,
  ParsedMessage m,
) {
  final sad = m.serder.sad;
  String said;
  try {
    checkAcdcFields(sad, 1, null);
    said = _verifyPlainSaid(m);
    _verifySignedBy(log, m);
  } on Exception catch (e) {
    return _Found.rejected(reasonOf(e));
  }
  final registry = _field(m, 'ri');
  if (registry == null) {
    return const _Found.rejected('the credential names no registry (`ri`)');
  }
  final vcp = stream
      .where((x) => _isKeri(x) && _ilkOf(x) == 'vcp' && _saidOf(x) == registry)
      .firstOrNull;
  if (vcp == null) {
    return _Found.rejected(
      'registry $registry has no inception event in the stream',
    );
  }
  if (_field(vcp, 'ii') != log.prefix) {
    return _Found.rejected(
      'registry $registry was not incepted by ${log.prefix}',
    );
  }
  final inception = _anchoredV1(log, registry, BigInt.zero, registry);
  if (inception.later) return null;
  if (inception.absent) {
    _registryFail(
      "registry event $registry is not anchored in the issuer's KEL",
    );
  }

  final iss = stream
      .where((x) => _isKeri(x) && _ilkOf(x) == 'iss' && _field(x, 'i') == said)
      .firstOrNull;
  if (iss == null) {
    return _Found.rejected('no issuance event for credential $said');
  }
  if (_field(iss, 'ri') != registry) {
    return _Found.rejected(
      'credential $said was issued in another registry than it names',
    );
  }
  final issSaid = _saidOf(iss) ?? '';
  final issued = _anchoredV1(log, said, BigInt.zero, issSaid);
  if (issued.later) return null;
  if (issued.absent) {
    _registryFail(
      "registry event $issSaid is not anchored in the issuer's KEL",
    );
  }

  for (final rev in stream.where(
    (x) =>
        _isKeri(x) &&
        const ['rev', 'brv'].contains(_ilkOf(x)) &&
        _field(x, 'i') == said,
  )) {
    final revSaid = _saidOf(rev) ?? '';
    // A sequence number that does not parse is taken as 1, as the Rust does.
    final sn = parseUnsigned(_field(rev, 's'), 16) ?? BigInt.one;
    final revoked = _anchoredV1(log, said, sn, revSaid);
    if (revoked.within) {
      return _Found.credential(
        _Credential(said, 1, registry, revSaid, true, sad),
      );
    }
    if (revoked.absent) {
      _registryFail(
        "registry event $revSaid is not anchored in the issuer's KEL",
      );
    }
  }
  return _Found.credential(_Credential(said, 1, registry, issSaid, false, sad));
}

_Anchor _anchoredV1(IssuerLog log, String i, BigInt sn, String d) {
  final s = sn.toRadixString(16);
  return _anchoring(
    log,
    (seal) =>
        sadStr(sadGet(seal, 'i')) == i &&
        sadStr(sadGet(seal, 's')) == s &&
        sadStr(sadGet(seal, 'd')) == d,
  );
}

/// The credential carries the issuer's signatures, meeting its threshold
/// then.
void _verifySignedBy(IssuerLog log, ParsedMessage m) {
  TransIdxSigGroup? group;
  for (final a in m.attachments) {
    if (a is! TransIdxSigGroups) continue;
    group = a.groups.where((g) => g.prefix == log.prefix).firstOrNull;
    if (group != null) break;
  }
  if (group == null) {
    _plain('the credential carries no signature group from ${log.prefix}');
  }
  final state = _keyStateAt(log, group.said);
  if (state == null) {
    _plain(
      'the signature group names establishment event ${group.said}, which '
      'the KEL does not hold',
    );
  }
  final sn = numberValue(group.sn);
  if (sn != BigInt.from(state.sn)) {
    _plain(
      'the signature group names establishment event ${group.said} at sn '
      '$sn, but it is at sn ${state.sn}',
    );
  }
  final indices = <int>[];
  for (final sig in group.sigs) {
    if (sig.index >= state.keys.length) {
      _plain('signature index ${sig.index} is out of range');
    }
    final key = state.keys[sig.index];
    if (verifySignature(verfer(key), m.serder.raw, sig.raw) &&
        !indices.contains(sig.index)) {
      indices.add(sig.index);
    }
  }
  if (!thresholdSatisfied(state.threshold, indices, state.keys.length)) {
    _plain("the credential's signatures do not meet the signing threshold");
  }
}

/// ACDC 2.x: an unsigned credential bound to a `rip` + `bup` registry.
_Found? _credentialV2(
  List<ParsedMessage> stream,
  IssuerLog log,
  ParsedMessage m,
) {
  final sad = m.serder.sad;
  String said;
  try {
    checkAcdcFields(sad, 2, _ilkOf(m));
    said = _verifyCompactSaid(sad, m.serder.kind);
  } on Exception catch (e) {
    return _Found.rejected(reasonOf(e));
  }
  final registry = _field(m, 'rd');
  if (registry == null) {
    return const _Found.rejected('the credential names no registry (`rd`)');
  }
  final rip = stream
      .where((x) => _isAcdc(x) && _ilkOf(x) == 'rip' && _saidOf(x) == registry)
      .firstOrNull;
  if (rip == null) {
    return _Found.rejected(
      'registry $registry has no inception event in the stream',
    );
  }
  try {
    _registryEvent(rip, 'rip');
  } on Exception catch (e) {
    return _Found.rejected(reasonOf(e));
  }
  if (_field(rip, 'i') != log.prefix) {
    return _Found.rejected(
      'registry $registry was not incepted by ${log.prefix}',
    );
  }
  if (_field(rip, 'n') != '0') {
    _registryFail('registry $registry is broken: its inception is not at n 0');
  }
  final inception = _anchoredV2(log, registry);
  if (inception.later) return null;
  if (inception.absent) {
    _registryFail(
      "registry event $registry is not anchored in the issuer's KEL",
    );
  }

  final updates = _chain(stream, log, registry);
  for (var k = updates.length - 1; k >= 0; k--) {
    final update = updates[k];
    final b = _field(update, 'b') ?? '';
    final updateSaid = _saidOf(update) ?? '';
    final disclosed = [
      for (final a in update.attachments.whereType<BlindedStates>())
        for (final s in a.states)
          if (s.blid == b) s,
    ];
    if (disclosed.length != 1) {
      _registryFail(
        'registry update $updateSaid carries no disclosure of its state',
      );
    }
    final state = disclosed.single;
    try {
      _verifyBlid(state);
    } on Exception catch (e) {
      _registryFail(
        'registry $registry is broken: update $updateSaid: ${reasonOf(e)}',
      );
    }
    final td = state.acdc == '1AAP' ? null : state.acdc;
    final ts = _labelText(state.state);
    if (td == null && ts == '') continue; // vacuous: a placeholder
    bool revoked;
    if (ts == 'issued') {
      revoked = false;
    } else if (ts == 'revoked') {
      revoked = true;
    } else {
      _registryFail(
        'registry update $updateSaid discloses state '
        '${jsonQuote(state.state)}, which is neither issued nor revoked',
      );
    }
    if (td != said) {
      return _Found.rejected(
        "registry $registry's latest state binds ${td ?? ''}, not this "
        'credential',
      );
    }
    return _Found.credential(
      _Credential(said, 2, registry, updateSaid, revoked, sad),
    );
  }
  return null;
}

void _registryEvent(ParsedMessage m, String ilk) {
  checkAcdcFields(m.serder.sad, 2, ilk);
  _verifyPlainSaid(m);
}

/// A 2.x registry event is anchored by any seal carrying its SAID, or its
/// SAID alone.
_Anchor _anchoredV2(IssuerLog log, String said) => _anchoring(
  log,
  (seal) => seal is String ? seal == said : sadStr(sadGet(seal, 'd')) == said,
);

/// The registry's updates the read may see, in order.
List<ParsedMessage> _chain(
  List<ParsedMessage> stream,
  IssuerLog log,
  String registry,
) {
  Never broken(String reason) =>
      _registryFail('registry $registry is broken: $reason');
  final seen = <(int, ParsedMessage)>[];
  for (final m in stream) {
    if (!(_isAcdc(m) && _ilkOf(m) == 'bup' && _field(m, 'rd') == registry)) {
      continue;
    }
    try {
      _registryEvent(m, 'bup');
    } on Exception catch (e) {
      broken(reasonOf(e));
    }
    final said = _saidOf(m) ?? '';
    final n = toSafeNumber(parseUnsigned(_field(m, 'n'), 16));
    if (n == null) broken('update $said has no hex sequence number');
    if (n == 0) broken("update $said is at n 0, which is the inception's");
    final a = _anchoredV2(log, said);
    if (a.within) {
      seen.add((n, m));
    } else if (a.absent) {
      _registryFail("registry event $said is not anchored in the issuer's KEL");
    }
  }
  // A stable sort by n, as the JS `Array.prototype.sort`.
  final order = List<int>.generate(seen.length, (i) => i)
    ..sort((x, y) {
      final c = seen[x].$1.compareTo(seen[y].$1);
      return c != 0 ? c : x.compareTo(y);
    });
  final sorted = [for (final i in order) seen[i]];
  final out = <ParsedMessage>[];
  var prior = registry;
  var expect = 1;
  for (var k = 0; k < sorted.length;) {
    final n = sorted[k].$1;
    var end = k;
    while (end < sorted.length && sorted[end].$1 == n) {
      end++;
    }
    if (n != expect) broken('no update at n $expect, but one at n $n');
    final saids = [
      for (final (_, m) in sorted.sublist(k, end))
        if (_saidOf(m) != null) _saidOf(m)!,
    ];
    if (saids.any((s) => s != saids[0])) {
      _registryFail(
        'registry $registry has more than one anchored event at n $n',
      );
    }
    final m = sorted[k].$2;
    if (_field(m, 'p') != prior) {
      broken('the update at n $n does not name the one before it');
    }
    prior = _saidOf(m) ?? '';
    out.add(m);
    expect++;
    k = end;
  }
  return out;
}

void _verifyBlid(BlindedState state) {
  final code = _digestCode(state.blid);
  final text = '#' * state.blid.length + state.uuid + state.acdc + state.state;
  if (digest(code, utf8Bytes(text)) != state.blid) {
    _plain('its disclosed state does not reproduce its BLID ${state.blid}');
  }
}

/// The text of a CESR label: empty, or a fixed-size tag.
String? _labelText(String qb64) {
  if (qb64 == '1AAP') return '';
  int start;
  if (qb64.startsWith('0J') || qb64.startsWith('0L')) {
    start = 3;
  } else if (qb64.startsWith('0K') || qb64.startsWith('0M')) {
    start = 2;
  } else if (qb64.startsWith('X') || qb64.startsWith('Y')) {
    start = 1;
  } else if (qb64.startsWith('1AAF') || qb64.startsWith('1AAN')) {
    start = 4;
  } else {
    return null;
  }
  return qb64.length >= start ? qb64.substring(start) : null;
}

/// An ACDC 2.x SAID is computed over its most compact form: each expanded
/// section replaced by its own SAID, the version string sized for that form.
String _verifyCompactSaid(Map<String, Object?> sad, String kind) {
  final said = sadStr(sad['d']);
  if (said == null) _plain('the credential has no SAID');
  final code = _digestCode(said);
  final compact = Map<String, Object?>.of(sad);
  for (final label in const ['s', 'a', 'e', 'r']) {
    final section = compact[label];
    if (section is! Map<String, Object?>) continue;
    compact[label] = label == 's'
        ? _recompute(section, r'$id', code, kind)
        : _compactSection(section, code, kind);
  }
  if (compact.containsKey('A') && compact['A'] is! String) {
    _plain('an expanded aggregate section (`A`) is not supported');
  }
  if (kind != 'CESR') {
    compact['d'] = '#' * said.length;
    final size = utf8Bytes(serializeJson(compact)).length;
    final vs = sadStr(compact['v']);
    if (vs == null) _plain('the credential has no version');
    final version = parseVersionString(vs);
    compact['v'] = versionString(version.copyWith(size: size));
  }
  final computed = _recompute(compact, 'd', code, kind);
  if (computed != said) {
    _plain(
      "the credential's SAID is $said, but its compact form gives $computed",
    );
  }
  return said;
}

String _compactSection(Map<String, Object?> section, String code, String kind) {
  final copy = Map<String, Object?>.of(section);
  for (final k in copy.keys.toList()) {
    final v = copy[k];
    if (v is Map<String, Object?> && v.containsKey('d')) {
      copy[k] = _compactSection(v, code, kind);
    }
  }
  return _recompute(copy, 'd', code, kind);
}

class _RegistryRead {
  final List<_Credential> credentials = [];
  final List<(String, String)> rejected = [];
}

/// The credentials of [schema] the log's issuer issued, each with its
/// status, as of the log's limit (`registry::designations`).
_RegistryRead _registryDesignations(
  List<ParsedMessage> stream,
  IssuerLog log,
  String schema,
  Set<String> saids,
) {
  _checkAnchoredEventsPresent(stream, log, saids);
  final out = _RegistryRead();
  for (final m in stream) {
    if (!_isCredential(m)) continue;
    final sad = m.serder.sad;
    if (sadStr(sad['i']) != log.prefix) continue;
    if (_schemaSaid(sad) != schema) continue;
    final said = sadStr(sad['d']) ?? '';
    final major = m.serder.version?.major;
    _Found? found;
    if (major == 1) {
      found = _credentialV1(stream, log, m);
    } else if (major == 2) {
      found = _credentialV2(stream, log, m);
    } else {
      found = _Found.rejected(
        'ACDC protocol version ${major ?? 'None'} is not supported',
      );
    }
    if (found?.credential != null) {
      out.credentials.add(found!.credential!);
    } else if (found?.rejected != null) {
      out.rejected.add((said, found!.rejected!));
    }
  }
  return out;
}

// ─── Designations (affinidi-did-webs `designation.rs`) ──────────────────

/// Schema SAIDs, both versions of each designation.
const String designatedAliasesSchema =
    'EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5';
const String designatedAliasesSchemaV2 =
    'EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA';
const String keyAgreementSchema =
    'EJZrf6N4vbhA1hQIujWiIiQmNi455EGS3iXdhxLSwvAi';
const String keyAgreementSchemaV2 =
    'EIW1ONwnh_dkiDZ3_xmUsBxh7X5u7luVOuCoRdCl3jPZ';
const String serviceSchema = 'ELj0Sdf2Boi7BMiIFAEJ9_MSFJU8t-LavLN-gMb8oXM8';
const String serviceSchemaV2 = 'EJVZ789syil6R--yix7j8X4g_mHZCDIaSWM15MgkFQgG';
const String keyRoleSchema = 'EPulJFl5SEb8qb3ca5teXHRGiWmTsTkylGTrS2vB4ZQx';
const String keyRoleSchemaV2 = 'EBMCaUhHZqulCtix3fzRRsdW0_gfT3bMLsrp3c3ixpxx';

/// Every designation schema this resolver implements.
const List<String> implementedSchemas = [
  designatedAliasesSchema,
  designatedAliasesSchemaV2,
  keyAgreementSchema,
  keyAgreementSchemaV2,
  serviceSchema,
  serviceSchemaV2,
  keyRoleSchema,
  keyRoleSchemaV2,
];

final Expando<Set<String>> _saidSets = Expando('did:webs stream SAIDs');

Set<String> _streamSaids(Kels kels) => _saidSets[kels] ??= {
  for (final m in kels.messages)
    if (_saidOf(m) != null) _saidOf(m)!,
};

/// The first reason a designation did not verify (`rejected.reason`).
class Rejection {
  String? reason;

  void note(String why) => reason ??= why;
}

/// A credential an AID issued to itself, that verifies.
class Designation {
  Designation(
    this.said,
    this.version,
    this.registry,
    this.event,
    this.attributes,
  );
  final String said;
  final int version;
  final String registry;

  /// The registry event that gives its status.
  final String event;

  /// Its attribute block (`a`), as a SAD map.
  final Map<String, Object?> attributes;
}

/// Every credential of one of [schemas] [aid] issued to itself that verifies,
/// each with whether it has since been revoked (`issued_designations`).
/// [rejected] keeps the first reason one did not verify.
List<(Designation, bool)> issuedDesignations(
  Kels kels,
  String aid,
  List<String> schemas,
  Rejection rejected,
) {
  kels.keyState(aid);
  final log = kels.issuerLog(aid);
  final out = <(Designation, bool)>[];
  for (final schema in schemas) {
    final found = _registryDesignations(
      kels.messages,
      log,
      schema,
      _streamSaids(kels),
    );
    if (found.rejected.isNotEmpty) {
      final (said, reason) = found.rejected.first;
      rejected.note('designation $said: $reason');
    }
    for (final credential in found.credentials) {
      final attributes = credential.sad['a'];
      if (attributes is! Map<String, Object?>) {
        rejected.note(
          'designation ${credential.said} carries no attribute block',
        );
        continue;
      }
      out.add((
        Designation(
          credential.said,
          credential.version,
          credential.registry,
          credential.event,
          attributes,
        ),
        credential.revoked,
      ));
    }
  }
  return out;
}

/// The standing (unrevoked) designations of [schemas].
List<Designation> designations(
  Kels kels,
  String aid,
  List<String> schemas,
  Rejection rejected,
) => [
  for (final (d, withdrawn) in issuedDesignations(kels, aid, schemas, rejected))
    if (!withdrawn) d,
];

/// The most schemas [unsupportedCritical] checks for a standing critical
/// designation.
const int _maxUnimplementedCriticalSchemas = 16;

/// The schema of the first standing designation [aid] issued that is marked
/// `critical` and that this resolver does not implement, or null (P6).
String? unsupportedCritical(
  Kels kels,
  String aid, [
  List<String> implemented = implementedSchemas,
]) {
  final anchored = kels.anchoredDigests(aid);
  final schemas = <String>[];
  for (final m in kels.messages) {
    if (!_isAcdc(m) || _field(m, 'i') != aid) continue;
    final sad = m.serder.sad;
    final s = sad['s'];
    String? schema;
    if (s is String) {
      schema = s;
    } else {
      schema = sadStr(sadGet(s, r'$id'));
      if (schema == null) continue;
    }
    // Only a credential marked critical, in a registry whose inception the
    // verified log anchors, can stand as a critical designation.
    final markedCritical = sadGet(sad['a'], 'critical') == true;
    final registryAnchored = const ['ri', 'rd'].any((f) {
      final r = sadStr(sad[f]);
      return r != null && anchored.contains(r);
    });
    if (markedCritical &&
        registryAnchored &&
        !implemented.contains(schema) &&
        !schemas.contains(schema)) {
      if (schemas.length == _maxUnimplementedCriticalSchemas) {
        throw StreamError(
          'keri.cesr carries credentials marked critical under more than '
          '$_maxUnimplementedCriticalSchemas schemas this resolver does not '
          'implement',
        );
      }
      schemas.add(schema);
    }
  }
  for (final schema in schemas) {
    final standing = designations(kels, aid, [schema], Rejection());
    if (standing.any((d) => d.attributes['critical'] == true)) return schema;
  }
  return null;
}

// ─── Designated aliases (affinidi-did-webs `aliases.rs`) ────────────────

/// What a designation read found, and the first reason one was rejected.
class DesignatedAliases {
  DesignatedAliases(this.aliases, this.rejected);
  final List<String> aliases;
  final String? rejected;
}

/// The aliases [aid] has designated (`a.ids` of every standing attestation).
DesignatedAliases designatedAliases(Kels kels, String aid) {
  final rejected = Rejection();
  final aliases = <String>[];
  for (final attestation in designations(kels, aid, const [
    designatedAliasesSchema,
    designatedAliasesSchemaV2,
  ], rejected)) {
    final ids = attestation.attributes['ids'];
    if (ids is! List) {
      rejected.note('attestation carries no `a.ids` list');
      continue;
    }
    for (final alias in ids) {
      if (alias is String && !aliases.contains(alias)) aliases.add(alias);
    }
  }
  return DesignatedAliases(aliases, rejected.reason);
}

// ─── Keys and JWKs ──────────────────────────────────────────────────────

/// A JWK as `affinidi-crypto` renders a public key, its CESR form as `kid`.
Map<String, Object?> _okpJwk(String crv, List<int> raw, String kid) => {
  'crv': crv,
  'kid': kid,
  'kty': 'OKP',
  'x': b64Encode(raw),
};

Map<String, Object?> _ecJwk(String code, Uint8List raw, String kid) {
  final k1 = code == '1AAA' || code == '1AAB';
  Uint8List bytes;
  try {
    bytes = ecdsaUncompressed(k1 ? EcdsaCurve.secp256k1 : EcdsaCurve.p256, raw);
  } on PointError catch (e) {
    throw InvalidKeyError('not a valid public key: ${e.message}');
  }
  return {
    'crv': k1 ? 'secp256k1' : 'P-256',
    'kid': kid,
    'kty': 'EC',
    'x': b64Encode(Uint8List.sublistView(bytes, 1, 33)),
    'y': b64Encode(Uint8List.sublistView(bytes, 33)),
  };
}

/// A key-state key as a JWK (`document::jwk_from_cesr_key`). Throws a
/// [DesignationError], which the document builder reports as a key event
/// log failure.
Map<String, Object?> jwkFromCesrKey(String qb64) {
  MatterValue m;
  try {
    m = matterFromQb64(qb64);
  } on KeriError catch (e) {
    _plain('key ${jsonQuote(qb64)} is not a CESR primitive: ${e.message}');
  }
  switch (m.code) {
    case 'B':
    case 'D':
      return _okpJwk('Ed25519', m.raw, qb64);
    case '1AAA':
    case '1AAB':
    case '1AAI':
    case '1AAJ':
      try {
        return _ecJwk(m.code, m.raw, qb64);
      } on InvalidKeyError catch (e) {
        _plain(
          'key ${jsonQuote(qb64)} is not a valid public key: ${e.message}',
        );
      }
    default:
      _plain(
        'key ${jsonQuote(qb64)} uses CESR code ${jsonQuote(m.code)}, which '
        'this implementation cannot express as a JWK',
      );
  }
}

/// A key designated for key agreement (`KeyAgreementKey`).
class KeyAgreementKey {
  KeyAgreementKey(this.code, this.raw);

  /// `C` (X25519), `1AAJ` (P-256) or `1AAB` (secp256k1).
  final String code;
  final Uint8List raw;
}

/// A key designated for key agreement (`KeyAgreementKey::from_cesr`).
KeyAgreementKey keyAgreementKey(String qb64) {
  MatterValue m;
  try {
    m = matterFromQb64(qb64);
  } on KeriError catch (e) {
    throw InvalidKeyError(
      '${jsonQuote(qb64)} is not a CESR primitive: ${e.message}',
    );
  }
  switch (m.code) {
    case 'C':
      if (m.raw.length != 32) {
        throw InvalidKeyError('${jsonQuote(qb64)} is not 32 bytes');
      }
      return KeyAgreementKey('C', m.raw);
    case '1AAI':
    case '1AAJ':
      return KeyAgreementKey('1AAJ', m.raw);
    case '1AAA':
    case '1AAB':
      return KeyAgreementKey('1AAB', m.raw);
    default:
      throw InvalidKeyError(
        '${jsonQuote(qb64)} uses CESR code ${jsonQuote(m.code)}, which is not '
        'a key agreement key type',
      );
  }
}

/// A key agreement key as a JWK, `kid` its CESR encoding (`public_jwk`).
Map<String, Object?> keyAgreementJwk(KeyAgreementKey key) {
  String kid;
  try {
    kid = matterQb64(key.code, key.raw);
  } on KeriError catch (e) {
    throw InvalidKeyError('cannot encode the key: ${e.message}');
  }
  if (key.code == 'C') return _okpJwk('X25519', key.raw, kid);
  return _ecJwk(key.code, key.raw, kid);
}

/// A key that signs (`VerificationKey::from_cesr`).
MatterValue _verificationKey(String qb64) {
  MatterValue m;
  try {
    m = matterFromQb64(qb64);
  } on KeriError catch (e) {
    throw InvalidKeyError(
      '${jsonQuote(qb64)} is not a CESR primitive: ${e.message}',
    );
  }
  if (const ['B', 'D', '1AAI', '1AAJ', '1AAA', '1AAB'].contains(m.code)) {
    return m;
  }
  throw InvalidKeyError(
    '${jsonQuote(qb64)} uses CESR code ${jsonQuote(m.code)}, which is not a '
    'verification key',
  );
}

/// The X25519 keys converted from a key state's Ed25519 keys, CESR-encoded
/// (`converted_key_agreement`). A key that does not decode to a curve point,
/// or is of small order, converts to nothing.
List<String> convertedKeyAgreement(List<String> stateKeys) {
  final out = <String>[];
  for (final key in stateKeys) {
    MatterValue m;
    try {
      m = matterFromQb64(key);
    } on KeriError {
      continue;
    }
    if (m.code != 'D' && m.code != 'B') continue;
    if (m.raw.length != 32) continue;
    final u = ed25519ToX25519(m.raw);
    if (u == null) continue;
    final qb64 = matterQb64('C', u);
    if (!out.contains(qb64)) out.add(qb64);
  }
  return out;
}

// ─── Key agreement designations (affinidi-did-webs `key_agreement.rs`) ─

/// The key agreement keys an AID designated.
class DesignatedKeyAgreement {
  DesignatedKeyAgreement(this.keys, this.rejected, this.issued);
  final List<String> keys;
  final String? rejected;

  /// Whether any key agreement designation was issued, revoked or not.
  final bool issued;
}

/// The key agreement keys [aid] has designated.
DesignatedKeyAgreement designatedKeyAgreement(Kels kels, String aid) {
  final rejected = Rejection();
  final issued = issuedDesignations(kels, aid, const [
    keyAgreementSchema,
    keyAgreementSchemaV2,
  ], rejected);
  final keys = <String>[];
  for (final (designation, withdrawn) in issued) {
    if (withdrawn) continue;
    List<String> found;
    try {
      found = _readKeys(designation.attributes);
    } on Exception catch (e) {
      rejected.note(reasonOf(e));
      continue;
    }
    for (final key in found) {
      if (!keys.contains(key)) keys.add(key);
    }
  }
  return DesignatedKeyAgreement(keys, rejected.reason, issued.isNotEmpty);
}

List<String> _readKeys(Map<String, Object?> attributes) {
  final keys = attributes['keys'];
  if (keys is! List || keys.isEmpty) {
    _plain('key agreement designation carries no `a.keys`');
  }
  final out = <String>[];
  for (final k in keys) {
    if (k is! String) _plain('a designated key is not a string');
    keyAgreementJwk(keyAgreementKey(k));
    out.add(k);
  }
  return out;
}

// ─── Designated services (affinidi-did-webs `designated_services.rs`) ───

/// The services an AID designated, as SAD maps.
class DesignatedServices {
  DesignatedServices(this.services, this.rejected);
  final List<Map<String, Object?>> services;
  final String? rejected;
}

/// The services [aid] has designated.
DesignatedServices designatedServices(Kels kels, String aid) {
  final rejected = Rejection();
  final services = <Map<String, Object?>>[];
  for (final designation in designations(kels, aid, const [
    serviceSchema,
    serviceSchemaV2,
  ], rejected)) {
    List<Map<String, Object?>> found;
    try {
      found = _readServices(designation.attributes);
    } on Exception catch (e) {
      rejected.note(reasonOf(e));
      continue;
    }
    for (final service in found) {
      if (services.any((s) => sadEqual(s['id'], service['id']))) continue;
      services.add(service);
    }
  }
  return DesignatedServices(services, rejected.reason);
}

List<Map<String, Object?>> _readServices(Map<String, Object?> attributes) {
  final services = attributes['services'];
  if (services is! List || services.isEmpty) {
    _plain('service designation carries no `a.services`');
  }
  services.forEach(checkService);
  return services.cast<Map<String, Object?>>();
}

/// Whether an entry is a service a DID document can carry (`check_service`).
void checkService(Object? service) {
  final id = sadStr(sadGet(service, 'id'));
  if (id == null) _plain('a designated service has no `id`');
  if (!id.startsWith('#') ||
      utf8Bytes(id).length < 2 ||
      id.substring(1).contains('#')) {
    _plain(
      'designated service id ${jsonQuote(id)} is not a relative DID URL '
      'fragment',
    );
  }
  final type = sadGet(service, 'type');
  final typeOk =
      (type is String && type.isNotEmpty) ||
      (type is List &&
          type.isNotEmpty &&
          type.every((t) => t is String && t.isNotEmpty));
  if (!typeOk) _plain('designated service $id has no usable `type`');
  final endpoint = sadGet(service, 'serviceEndpoint');
  if (!(endpoint is String || endpoint is Map || endpoint is List)) {
    _plain('designated service $id has no `serviceEndpoint`');
  }
}

// ─── Key roles (affinidi-did-webs `key_roles.rs`) ───────────────────────

/// A registered key role and the relationship its keys are listed under.
class KeyRole {
  const KeyRole(this.name, this.relationship);
  final String name;
  final String relationship;
}

/// The registered key roles, in the order a document lists them.
const List<KeyRole> keyRoles = [
  KeyRole('attestation', 'assertionMethod'),
  KeyRole('operational', 'authentication'),
  KeyRole('messaging', 'keyAgreement'),
];

/// The JWK of a key bound to [role], or a throw saying why it cannot be.
Map<String, Object?> roleKeyJwk(String role, String qb64) {
  if (role == 'messaging') return keyAgreementJwk(keyAgreementKey(qb64));
  _verificationKey(qb64);
  return jwkFromCesrKey(qb64);
}

/// The JWK of a revoked key, whichever kind it was.
Map<String, Object?> revokedKeyJwk(String qb64) {
  try {
    return roleKeyJwk('operational', qb64);
  } on Exception {
    return roleKeyJwk('messaging', qb64);
  }
}

Uint8List? _rawOf(String qb64) {
  try {
    return matterFromQb64(qb64).raw;
  } on KeriError {
    return null;
  }
}

bool _sameBytes(Uint8List? a, Uint8List? b) {
  if (a == null || b == null || a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

int _floorDiv(int a, int b) => (a / b).floor();

/// Parse an RFC 3339 date-time as `chrono::DateTime::parse_from_rfc3339`
/// does, to an instant (seconds since the epoch, nanoseconds), or null.
(int, int)? parseRfc3339(Object? s) {
  if (s is! String) return null;
  final bytes = utf8Bytes(s);
  if (bytes.length < 19) return null;
  int? d(int k) => k < bytes.length && bytes[k] >= 0x30 && bytes[k] <= 0x39
      ? bytes[k] - 0x30
      : null;
  int? two(int k) {
    final a = d(k);
    final b = d(k + 1);
    return a == null || b == null ? null : a * 10 + b;
  }

  final y = [
    for (final k in const [0, 1, 2, 3]) d(k),
  ];
  if (y.contains(null)) return null;
  final year = y[0]! * 1000 + y[1]! * 100 + y[2]! * 10 + y[3]!;
  if (bytes[4] != 0x2d) return null;
  final month = two(5);
  if (month == null || bytes[7] != 0x2d) return null;
  final day = two(8);
  if (day == null) return null;
  final leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
  final days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1]) {
    return null;
  }
  if (!const [0x74, 0x54, 0x20].contains(bytes[10])) return null;
  final hour = two(11);
  if (hour == null || bytes[13] != 0x3a) return null;
  final minute = two(14);
  if (minute == null || bytes[16] != 0x3a) return null;
  var sec = two(17);
  if (sec == null) return null;
  var nano = 0;
  if (sec == 60) {
    sec = 59;
    nano = 1000000000;
  }
  var k = 19;
  if (bytes.length > 19 && bytes[19] == 0x2e) {
    k = 20;
    final digits = StringBuffer();
    while (k < bytes.length && d(k) != null) {
      if (digits.length < 9) digits.write(d(k));
      k++;
    }
    if (digits.isEmpty) return null;
    nano += int.parse(digits.toString().padRight(9, '0'));
  }
  if (hour > 23 ||
      minute > 59 ||
      sec > 59 ||
      nano >= 2000000000 ||
      (nano >= 1000000000 && sec != 59)) {
    return null;
  }
  int offset;
  // The first k bytes are ASCII, so they are the first k characters.
  final rest = s.substring(k);
  if (rest == 'Z' || rest == 'z') {
    offset = 0;
  } else {
    final m = RegExp(r'^([+\-−])([0-9]{2}):([0-9]{2})$').firstMatch(rest);
    if (m == null) return null;
    final oh = int.parse(m.group(2)!);
    final om = int.parse(m.group(3)!);
    if (om > 59) return null;
    offset = (oh * 3600 + om * 60) * (m.group(1) == '+' ? 1 : -1);
    if (offset.abs() >= 86400) return null;
  }
  // Days from the civil date (proleptic Gregorian), then the instant.
  final yy = month <= 2 ? year - 1 : year;
  final era = _floorDiv(yy, 400);
  final yoe = yy - era * 400;
  final mp = (month + 9) % 12;
  final doy = _floorDiv(153 * mp + 2, 5) + day - 1;
  final doe = yoe * 365 + _floorDiv(yoe, 4) - _floorDiv(yoe, 100) + doy;
  final epochDays = era * 146097 + doe - 719468;
  return (epochDays * 86400 + hour * 3600 + minute * 60 + sec - offset, nano);
}

/// Order two instants from [parseRfc3339].
int compareInstants((int, int) a, (int, int) b) =>
    a.$1 != b.$1 ? a.$1.compareTo(b.$1) : a.$2.compareTo(b.$2);

/// A key a key role designation revokes for compromise.
class RevokedKey {
  RevokedKey(this.key, this.compromisedAt);
  final String key;

  /// When it was compromised, as written (RFC 3339).
  final String compromisedAt;
}

/// What resolution reads from an AID's key role designations.
class DesignatedKeyRoles {
  /// Whether any key role designation was issued, revoked or not.
  bool issued = false;

  /// Each role the standing designation binds, with its keys.
  List<(KeyRole, List<String>)> roles = [];
  List<RevokedKey> revoked = [];
  String? rejected;
}

/// What resolution reads from [aid]'s key role designations.
DesignatedKeyRoles designatedKeyRoles(Kels kels, String aid) {
  final state = kels.keyState(aid);
  final rejected = Rejection();
  var issued = issuedDesignations(kels, aid, const [
    keyRoleSchema,
    keyRoleSchemaV2,
  ], rejected);
  final out = DesignatedKeyRoles()..issued = issued.isNotEmpty;
  issued = issued.where((entry) {
    final (designation, _) = entry;
    final marked = designation.attributes['critical'] == true;
    if (designation.version >= 2 && !marked) {
      rejected.note(
        'key role designation ${designation.said} is not marked critical',
      );
      return false;
    }
    return true;
  }).toList();

  final revoked = <(RevokedKey, (int, int))>[];
  for (final (designation, _) in issued) {
    List<(RevokedKey, (int, int))> entries;
    try {
      entries = _readRevoked(designation.attributes);
    } on Exception catch (e) {
      rejected.note(reasonOf(e));
      continue;
    }
    for (final (entry, at) in entries) {
      final i = revoked.indexWhere((r) => r.$1.key == entry.key);
      if (i < 0) {
        revoked.add((entry, at));
      } else if (compareInstants(at, revoked[i].$2) < 0) {
        revoked[i] = (entry, at);
      }
    }
  }
  out.revoked = [for (final (r, _) in revoked) r];

  final standing = [
    for (final (d, withdrawn) in issued)
      if (!withdrawn) d,
  ];
  if (standing.length == 1) {
    try {
      out.roles = _readRoles(
        standing.single.attributes,
        state.keys,
        state.nextKeys,
        out.revoked,
      );
    } on Exception catch (e) {
      rejected.note(reasonOf(e));
    }
  } else if (standing.length > 1) {
    rejected.note('more than one key role designation stands');
  }
  out.rejected = rejected.reason;
  return out;
}

List<(RevokedKey, (int, int))> _readRevoked(Map<String, Object?> attributes) {
  if (!attributes.containsKey('revoked')) return const [];
  final entries = attributes['revoked'];
  if (entries is! List) _plain('`a.revoked` is not a list');
  final out = <(RevokedKey, (int, int))>[];
  for (final entry in entries) {
    final key = sadStr(sadGet(entry, 'key'));
    if (key == null) _plain('a revoked entry names no key');
    try {
      revokedKeyJwk(key);
    } on Exception catch (e) {
      _plain('revoked key $key: ${reasonOf(e)}');
    }
    final at = sadStr(sadGet(entry, 'compromisedAt'));
    if (at == null) _plain('revoked key $key has no compromise time');
    final parsed = parseRfc3339(at);
    if (parsed == null) {
      _plain(
        'revoked key $key: compromise time ${jsonQuote(at)} is not RFC 3339',
      );
    }
    out.add((RevokedKey(key, at), parsed));
  }
  return out;
}

List<(KeyRole, List<String>)> _readRoles(
  Map<String, Object?> attributes,
  List<String> keysInState,
  List<String> nextKeys,
  List<RevokedKey> revoked,
) {
  final roles = attributes['roles'];
  if (roles is! Map<String, Object?>) {
    _plain('key role designation carries no `a.roles`');
  }
  final seen = <Uint8List>[];
  final out = <(KeyRole, List<String>)>[];
  for (final role in keyRoles) {
    // A role the reader does not recognise is never asked for (VTI-KEY-074).
    if (!roles.containsKey(role.name)) continue;
    final keys = roles[role.name];
    if (keys is! List || keys.isEmpty) {
      _plain('role ${role.name} lists no keys');
    }
    final listed = <String>[];
    for (final key in keys) {
      if (key is! String) _plain('a ${role.name} key is not a string');
      try {
        roleKeyJwk(role.name, key);
      } on Exception catch (e) {
        _plain('${role.name} key $key: ${reasonOf(e)}');
      }
      _checkRoleKey(key, keysInState, nextKeys, revoked);
      final raw = _rawOf(key);
      if (raw == null) _plain('$key is not a CESR primitive');
      if (seen.any((s) => _sameBytes(s, raw))) {
        _plain('$key is bound to more than one role');
      }
      seen.add(raw);
      listed.add(key);
    }
    out.add((role, listed));
  }
  return out;
}

/// A role key is never a key-state key, a committed next key, or revoked.
void _checkRoleKey(
  String qb64,
  List<String> keysInState,
  List<String> nextKeys,
  List<RevokedKey> revoked,
) {
  final raw = _rawOf(qb64);
  if (raw == null) _plain('$qb64 is not a CESR primitive');
  if (keysInState.any((k) => _sameBytes(_rawOf(k), raw))) {
    _plain("$qb64 is a key of the identifier's key state");
  }
  var committed = false;
  try {
    committed = nextKeys.contains(digest('E', utf8Bytes(qb64)));
  } on Exception {
    committed = false;
  }
  if (committed) {
    _plain(
      "$qb64 is a key the identifier's key state has committed to rotate to",
    );
  }
  if (revoked.any((r) => _sameBytes(_rawOf(r.key), raw))) {
    _plain('$qb64 is revoked for compromise');
  }
}
