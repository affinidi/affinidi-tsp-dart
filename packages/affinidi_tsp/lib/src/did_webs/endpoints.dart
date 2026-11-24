// KERI endpoint services for the did:webs resolver: the role and witness
// endpoints an AID's signed replies designate, under BADA reply state, and
// the `DelegatorOOBI` service of a delegated identifier.
//
// A port of the endpoint readers of OpenVTC/vti-didcomm-js `src/did-webs.js`,
// themselves a port of `affinidi-did-webs` 0.13.1 `services.rs`.

// ignore_for_file: public_member_api_docs

import 'cesr.dart';
import 'designations.dart';
import 'kel.dart';

/// Where a reply stands in BADA order: the signer's establishment sequence
/// number, then its `dt`.
typedef _Seniority = (int, (int, int));

int _compareSeniority(_Seniority a, _Seniority b) =>
    a.$1 != b.$1 ? a.$1.compareTo(b.$1) : compareInstants(a.$2, b.$2);

/// Where a reply stands in BADA order, if [signer] signed it
/// (`reply_seniority`).
_Seniority? _replySeniority(Kels kels, ParsedMessage msg, String signer) {
  final dt = parseRfc3339(sadStr(msg.serder.sad['dt']));
  if (dt == null) return null;
  final group = transIdxSigGroups(
    msg,
  ).where((g) => g.prefix == signer).firstOrNull;
  if (group != null) {
    try {
      return (kels.verifySignatureGroup(signer, msg.serder.raw, group).sn, dt);
    } on Exception {
      return null;
    }
  }
  for (final a in msg.attachments) {
    if (a is! ReceiptCouples) continue;
    for (final (prefix, sig) in a.couples) {
      if (prefix != signer) continue;
      Verfer v;
      try {
        v = verfer(prefix);
      } on Exception {
        continue;
      }
      var ok = false;
      try {
        ok = verifySignature(v, msg.serder.raw, sig);
      } on Exception {
        ok = false;
      }
      if (ok) return (0, dt);
    }
  }
  return null;
}

final Expando<Map<String, Map<String, String>>> _locationCaches = Expando(
  'did:webs location schemes',
);

/// The verified location schemes [eid] published for itself, by scheme.
Map<String, String> locationSchemes(Kels kels, String eid) {
  final cache = _locationCaches[kels] ??= {};
  final cached = cache[eid];
  if (cached != null) return cached;
  final latest = <String, (_Seniority, String)>{};
  for (final rpy in kels.messagesWithIlk('rpy')) {
    final sad = rpy.serder.sad;
    if (sadStr(sad['r']) != '/loc/scheme') continue;
    final a = sad['a'];
    final subject = sadStr(sadGet(a, 'eid'));
    final scheme = sadStr(sadGet(a, 'scheme'));
    final url = sadStr(sadGet(a, 'url'));
    if (subject == null || scheme == null || url == null || subject != eid) {
      continue;
    }
    final seniority = _replySeniority(kels, rpy, eid);
    if (seniority == null) continue;
    final existing = latest[scheme];
    if (existing != null && _compareSeniority(existing.$1, seniority) >= 0) {
      continue;
    }
    latest[scheme] = (seniority, url);
  }
  final schemes = latest.keys.toList()..sort(compareUtf8);
  final out = {for (final s in schemes) s: latest[s]!.$2};
  cache[eid] = out;
  return out;
}

/// An endpoint an AID authorised: [eid] in [role], at [urls] by scheme.
class Endpoint {
  Endpoint(this.eid, this.role, this.urls);
  final String eid;
  final String role;
  final Map<String, String> urls;
}

/// The endpoints [aid]'s signed `/end/role` replies designate, under BADA
/// reply state (`role_endpoints`).
List<Endpoint> roleEndpoints(Kels kels, String aid) {
  kels.keyState(aid);
  final roles = <String, (String, String, bool, _Seniority)>{};
  for (final rpy in kels.messagesWithIlk('rpy')) {
    final sad = rpy.serder.sad;
    final route = sadStr(sad['r']) ?? '';
    bool added;
    if (route == '/end/role/add') {
      added = true;
    } else if (route == '/end/role/cut') {
      added = false;
    } else {
      continue;
    }
    final a = sad['a'];
    final cid = sadStr(sadGet(a, 'cid'));
    final role = sadStr(sadGet(a, 'role'));
    final eid = sadStr(sadGet(a, 'eid'));
    if (cid == null || role == null || eid == null) continue;
    // Only this AID's own authorisations.
    if (cid != aid) continue;
    final seniority = _replySeniority(kels, rpy, aid);
    if (seniority == null) continue;
    final key = '${jsonQuote(role)},${jsonQuote(eid)}';
    final existing = roles[key];
    // Equal seniority is not newer, as in keripy.
    if (existing != null && _compareSeniority(existing.$4, seniority) >= 0) {
      continue;
    }
    roles[key] = (role, eid, added, seniority);
  }
  final sorted = roles.values.toList()
    ..sort((x, y) {
      final c = compareUtf8(x.$1, y.$1);
      return c != 0 ? c : compareUtf8(x.$2, y.$2);
    });
  final endpoints = <Endpoint>[];
  for (final (role, eid, added, _) in sorted) {
    // A witness is designated by the key state, not by a reply.
    if (!added || role == 'witness') continue;
    final urls = locationSchemes(kels, eid);
    if (urls.isEmpty) continue;
    endpoints.add(Endpoint(eid, role, urls));
  }
  return endpoints;
}

/// The witnesses in [backers] that have published a location.
List<Endpoint> witnessEndpoints(Kels kels, List<String> backers) => [
  for (final eid in backers)
    if (locationSchemes(kels, eid).isNotEmpty)
      Endpoint(eid, 'witness', locationSchemes(kels, eid)),
];

/// Every endpoint [aid] authorised: role endpoints, then its witnesses.
List<Endpoint> serviceEndpoints(Kels kels, String aid) {
  final state = kels.keyState(aid);
  return [
    ...roleEndpoints(kels, aid),
    ...witnessEndpoints(kels, state.backers),
  ];
}

/// An endpoint as a DID document service.
Map<String, Object?> endpointService(Endpoint e) => {
  'id': '#${e.eid}/${e.role}',
  'type': e.role,
  'serviceEndpoint': Map<String, Object?>.of(e.urls),
};

/// The `DelegatorOOBI` service of a delegated identifier, or null.
Map<String, Object?>? delegatorService(Kels kels, String aid) {
  final state = kels.keyState(aid);
  final delegator = state.delegator;
  if (delegator == null) return null;
  final seal = kels.inceptionSaid(aid);
  if (seal == null) return null;
  final locations = locationSchemes(kels, delegator);
  final url = locations['https'] ?? locations['http'];
  if (url == null) return null;
  return {
    'id': seal,
    'type': 'DelegatorOOBI',
    'serviceEndpoint':
        '${url.replaceFirst(RegExp(r'/+$'), '')}/oobi/$delegator/controller',
  };
}
