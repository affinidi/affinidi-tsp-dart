// What the designation layer answers for a stream, in the shape
// `test/tool/did_webs_designations_golden.mjs` records the JS reference's
// answers. Free of dart:io so the same code runs compiled to JavaScript.

import 'dart:typed_data';

import 'package:affinidi_tsp/src/did_webs/cesr.dart';
import 'package:affinidi_tsp/src/did_webs/designations.dart';
import 'package:affinidi_tsp/src/did_webs/endpoints.dart';
import 'package:affinidi_tsp/src/did_webs/kel.dart';

/// Sequence numbers `asOf` is tried at, at most, per identifier.
const int maxAsOf = 24;

Map<String, Object?> _err(Object e) => switch (e) {
  RegistryError(:final message) => {'error': 'Registry', 'message': message},
  InvalidKeyError(:final message) => {
    'error': 'InvalidKey',
    'message': message,
  },
  StreamError(:final message) => {'error': 'Stream', 'message': message},
  KelError(:final message) => {'error': 'Kel', 'message': message},
  KeriError(:final type, :final message) => {
    'error': 'Keri:$type',
    'message': message,
  },
  DesignationError(:final message) => {'error': 'js', 'message': message},
  _ => {'error': 'dart', 'message': '$e'},
};

Object? _attempt(Object? Function() fn) {
  try {
    return fn();
  } on Exception catch (e) {
    return _err(e);
  }
}

Map<String, Object?> _designationsOf(Kels kels, String aid) => {
  'critical': _attempt(() => unsupportedCritical(kels, aid)),
  'issued': [
    for (final schema in implementedSchemas)
      _attempt(() {
        final rejected = Rejection();
        final issued = issuedDesignations(kels, aid, [schema], rejected);
        return {
          'credentials': [
            for (final (d, withdrawn) in issued)
              {
                'said': d.said,
                'version': d.version,
                'registry': d.registry,
                'event': d.event,
                'withdrawn': withdrawn,
                'attributes': toJson(d.attributes),
              },
          ],
          'rejected': rejected.reason,
        };
      }),
  ],
  'aliases': _attempt(() {
    final v = designatedAliases(kels, aid);
    return {'aliases': v.aliases, 'rejected': v.rejected};
  }),
  'keyAgreement': _attempt(() {
    final v = designatedKeyAgreement(kels, aid);
    return {'keys': v.keys, 'rejected': v.rejected, 'issued': v.issued};
  }),
  'services': _attempt(() {
    final v = designatedServices(kels, aid);
    return {
      'services': [for (final s in v.services) toJson(s)],
      'rejected': v.rejected,
    };
  }),
  'keyRoles': _attempt(() {
    final v = designatedKeyRoles(kels, aid);
    return {
      'issued': v.issued,
      'roles': [
        for (final (role, keys) in v.roles) [role.name, keys],
      ],
      'revoked': [
        for (final r in v.revoked)
          {'key': r.key, 'compromisedAt': r.compromisedAt},
      ],
      'rejected': v.rejected,
    };
  }),
  'endpoints': _attempt(
    () => [
      for (final e in serviceEndpoints(kels, aid))
        {
          'eid': e.eid,
          'role': e.role,
          'urls': [
            for (final u in e.urls.entries) [u.key, u.value],
          ],
        },
    ],
  ),
  'delegator': _attempt(() => delegatorService(kels, aid)),
};

/// Everything the golden file records for [bytes].
Map<String, Object?> designationOutcome(Uint8List bytes) {
  Kels kels;
  try {
    kels = Kels.parse(bytes);
  } on Exception catch (e) {
    return {'parse': _err(e)};
  }
  final ids = <Object?>[];
  for (final prefix in kels.prefixes.toList()) {
    KeyState state;
    try {
      state = kels.keyState(prefix);
    } on Exception {
      continue;
    }
    ids.add({
      'prefix': prefix,
      ..._designationsOf(kels, prefix),
      'converted': convertedKeyAgreement(state.keys),
      'jwks': [for (final k in state.keys) _attempt(() => jwkFromCesrKey(k))],
      'asOf': [
        for (final sn in kels.sequenceNumbers(prefix).toSet().take(maxAsOf))
          _attempt(() {
            final at = kels.asOf(prefix, sn)..keyState(prefix);
            return {'sn': sn, ..._designationsOf(at, prefix)};
          }),
      ],
    });
  }
  return {
    'parse': {'ok': kels.messages.length},
    'ids': ids,
  };
}
