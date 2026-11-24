// Designations for did:webs (lib/src/did_webs/designations.dart and
// endpoints.dart), checked three ways:
//
// - against the Rust reference: every `service_endpoints`,
//   `delegator_service` and `designated_*` record of the conformance vectors
//   recorded from `affinidi-did-webs` must give the same answer, or be
//   refused with the same error kind;
// - against the JS port it follows (vti-didcomm-js
//   `src/did-webs-designations.js` and the endpoint readers of
//   `src/did-webs.js`): for every fixture stream and every (stream, mutation)
//   pair the vectors name, every verified identifier's critical-designation
//   check, issued credentials under each schema, designated aliases, key
//   agreement keys, services and key roles, endpoints and delegator service —
//   as of the whole stream and as of each event — must be identical,
//   refusals and rejection reasons to the message;
// - and the cases the JS port's own tests read on their own.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:affinidi_tsp/src/did_webs/cesr.dart';
import 'package:affinidi_tsp/src/did_webs/designations.dart';
import 'package:affinidi_tsp/src/did_webs/endpoints.dart';
import 'package:affinidi_tsp/src/did_webs/kel.dart';
import 'package:test/test.dart';

import 'support/did_webs_designations_outcome.dart';
import 'support/did_webs_vectors.dart';

/// The `DidWebsError` kind the resolver reports a failure as
/// (vti-didcomm-js `did-webs.js` `kel()`).
String _kind(Object e) => switch (e) {
  StreamError() => 'Stream',
  RegistryError() => 'Registry',
  InvalidKeyError() => 'InvalidKey',
  KelError() || KeriError() => 'Kel',
  _ => throw StateError('not a KERI-layer error: $e'),
};

const _ops = {
  'service_endpoints',
  'delegator_service',
  'designated_aliases',
  'designated_key_agreement',
  'designated_services',
};

/// Run a record as vti-didcomm-js `runOp` does.
Object? _runOp(Map<String, Object?> rec) {
  final stream = mutate(
    vectorBlob(rec['keri_cesr']! as String),
    rec['mutation'] as Map<String, Object?>?,
  );
  var kels = Kels.parse(stream);
  final asOf = rec['as_of'] as List<Object?>?;
  if (asOf != null) kels = kels.asOf(asOf[0]! as String, asOf[1]! as int);
  final aid = rec['aid']! as String;
  switch (rec['op']) {
    case 'service_endpoints':
      return [
        for (final e in serviceEndpoints(kels, aid))
          {'eid': e.eid, 'role': e.role, 'urls': e.urls},
      ];
    case 'delegator_service':
      return delegatorService(kels, aid);
    case 'designated_aliases':
      final v = designatedAliases(kels, aid);
      return {'aliases': v.aliases, 'rejected': v.rejected != null};
    case 'designated_key_agreement':
      final v = designatedKeyAgreement(kels, aid);
      return {
        'keys': v.keys,
        'issued': v.issued,
        'rejected': v.rejected != null,
      };
    case 'designated_services':
      final v = designatedServices(kels, aid);
      return {
        'services': [for (final s in v.services) toJson(s)],
        'rejected': v.rejected != null,
      };
  }
  throw StateError('unknown op ${rec['op']}');
}

Map<String, Object?> _golden() {
  final bytes = File(
    '$didWebsFixtures/golden/designations-golden.json.gz',
  ).readAsBytesSync();
  return jsonDecode(utf8.decode(gzip.decode(bytes))) as Map<String, Object?>;
}

const String _aid = 'ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe';

void main() {
  group('did:webs designations: parity with the Rust reference', () {
    final records = [
      for (final e in loadVectors().entries)
        for (final r in e.value)
          if (_ops.contains(r['op'])) r,
    ];

    test('covers every endpoint and designation record', () {
      expect(records, hasLength(36));
    });

    for (final rec in records) {
      final label =
          '${rec['source']}'
          '${rec['mutation'] == null ? '' : ' ${jsonEncode(rec['mutation'])}'}'
          ' [${rec['op']}]';
      test(label, () {
        Object? got;
        Object? error;
        try {
          got = _runOp(rec);
        } on Exception catch (e) {
          error = e;
        }
        if (rec['ok'] != true) {
          final want = (rec['error']! as Map)['kind'];
          expect(error, isNotNull, reason: 'Rust refused it ($want)');
          expect(_kind(error!), want, reason: '$error');
        } else {
          expect(error, isNull, reason: 'Rust accepted it');
          expect(
            jsonDecode(jsonEncode(got)),
            rec.containsKey('result') ? rec['result'] : true,
          );
        }
      });
    }
  });

  group('did:webs designations: parity with the JavaScript port', () {
    final golden = _golden();
    final cases = (golden['cases']! as List).cast<Map<String, Object?>>();

    test('covers every fixture stream and recorded mutation', () {
      expect(cases.length, greaterThan(1300));
    });

    for (final c in cases) {
      final name = c['file'] != null
          ? 'fixture ${c['file']}'
          : 'vector ${c['blob']} ${jsonEncode(c['mutation'])}';
      test(name, () {
        final bytes = c['file'] != null
            ? didWebsFixture(c['file']! as String)
            : mutate(
                vectorBlob(c['blob']! as String),
                c['mutation'] as Map<String, Object?>?,
              );
        final want = Map.of(c)
          ..remove('file')
          ..remove('blob')
          ..remove('mutation');
        // Through JSON, so ints and lists compare as the golden's do.
        expect(jsonDecode(jsonEncode(designationOutcome(bytes))), want);
      });
    }
  });

  group('the reference identifier', () {
    final kels = Kels.parse(didWebsFixture('ENro7uf0.keri.cesr'));

    test('designates its aliases, and no key agreement', () {
      final aliases = designatedAliases(kels, _aid);
      expect(aliases.rejected, isNull);
      expect(
        aliases.aliases,
        containsAll([
          'did:webs:did-webs-service%3a7676:$_aid',
          'did:webs:foo.com:$_aid',
        ]),
      );
      final ka = designatedKeyAgreement(kels, _aid);
      expect(ka.issued, isFalse);
      expect(ka.keys, isEmpty);
      expect(designatedKeyRoles(kels, _aid).issued, isFalse);
      expect(unsupportedCritical(kels, _aid), isNull);
    });

    test(
      'its Ed25519 key converts to the X25519 key KERI practice renders',
      () {
        final state = kels.keyState(_aid);
        expect(state.keys, ['DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr']);
        expect(convertedKeyAgreement(state.keys), [
          'CPz5wadpRpL4rGHeRSLHIc-2jMndx_mYBhuPhcr7WFRg',
        ]);
        expect(jwkFromCesrKey(state.keys.single), {
          'crv': 'Ed25519',
          'kid': 'DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr',
          'kty': 'OKP',
          'x': 'evT4j6Yw3uHpwsw5NEmSR8-4x3S-BA-s6Thjd51oeOs',
        });
      },
    );

    test('as of an event before the issuance, nothing is designated', () {
      expect(designatedAliases(kels.asOf(_aid, 1), _aid).aliases, isEmpty);
    });
  });

  group('the parties (affinidi-did-webs 0.13.3)', () {
    Kels party(String name) =>
        Kels.parse(didWebsFixture('parties/$name/keri.cesr'));
    String aidOf(String name) => File(
      '$didWebsFixtures/vectors/parties/$name/did.txt',
    ).readAsStringSync().trim().split(':').last;

    test('the VTA binds a different key to each role', () {
      final aid = aidOf('vta');
      final roles = designatedKeyRoles(party('vta'), aid);
      expect(roles.issued, isTrue);
      expect(roles.rejected, isNull);
      expect(
        {for (final (r, keys) in roles.roles) r.name: keys},
        {
          'attestation': ['DF4hLAmA5LOfwJchE0qgIQk3Tt_SYMDT0Dy1AcjWVFep'],
          'operational': ['DBfLefsrQSDysexl5BmNbgiyjoE_6wHkpACDm4XhgIDO'],
          'messaging': [
            '1AAJAxAExOYTxnMlFtF30ibtc4LWFn92rfoHJDanK2UgZM61',
            'CAT18pFiwxqN76GObnQiJO6Ab8FxiieL6Fm6ViBAK486',
          ],
        },
      );
      expect(
        roleKeyJwk(
          'messaging',
          '1AAJAxAExOYTxnMlFtF30ibtc4LWFn92rfoHJDanK2UgZM61',
        ),
        containsPair('crv', 'P-256'),
      );
    });

    test('the mediator designates a key agreement key and a service', () {
      final aid = aidOf('mediator');
      final kels = party('mediator');
      expect(designatedKeyAgreement(kels, aid).keys, [
        'CHoaTnCb8IWsSUq6BGm5se2gqx94sWqrt5_-2pBiPoUi',
      ]);
      final services = designatedServices(kels, aid);
      expect(services.rejected, isNull);
      expect(
        jsonEncode(toJson(services.services)),
        allOf(contains('DIDCommMessaging'), contains('wss://')),
      );
    });
  });

  group('keys and JWKs', () {
    test('a key-state key the JWK form cannot express is refused', () {
      expect(
        () => jwkFromCesrKey('C${'A' * 43}'),
        throwsA(
          isA<DesignationError>().having(
            (e) => e.message,
            'message',
            'key "C${'A' * 43}" uses CESR code "C", which this implementation '
                'cannot express as a JWK',
          ),
        ),
      );
      expect(
        () => jwkFromCesrKey('!'),
        throwsA(
          isA<DesignationError>().having(
            (e) => e.message,
            'message',
            'key "!" is not a CESR primitive: unknown code !',
          ),
        ),
      );
    });

    test('an EC key that is not a curve point carries noble\'s reason', () {
      // x = 0 is not on secp256k1 (7 has no square root mod p).
      final k1 = matterQb64('1AAB', Uint8List(33)..[0] = 2);
      expect(
        () => jwkFromCesrKey(k1),
        throwsA(
          isA<DesignationError>().having(
            (e) => e.message,
            'message',
            'key ${jsonQuote(k1)} is not a valid public key: not a valid '
                'public key: bad point: is not on curve, sqrt error: Cannot '
                'find square root',
          ),
        ),
      );
      final wrongX = matterQb64('1AAJ', Uint8List(33)..fillRange(0, 33, 0xff));
      expect(
        () => keyAgreementJwk(keyAgreementKey(wrongX)),
        throwsA(
          isA<InvalidKeyError>().having(
            (e) => e.message,
            'message',
            'not a valid public key: bad point: got length 33, expected '
                'compressed=33 or uncompressed=65',
          ),
        ),
      );
      final p256 = matterQb64('1AAJ', Uint8List(33)..[0] = 2);
      expect(keyAgreementJwk(keyAgreementKey(p256)), {
        'crv': 'P-256',
        'kid': p256,
        'kty': 'EC',
        'x': 'A' * 43,
        'y': 'ZkhceA4vg9ckM71dhKBrtlQcKvMdrocXKL-FahdPk_Q',
      });
    });

    test('key agreement and verification keys by CESR code', () {
      expect(
        () => keyAgreementKey('D${'A' * 43}'),
        throwsA(
          isA<InvalidKeyError>().having(
            (e) => e.message,
            'message',
            '"D${'A' * 43}" uses CESR code "D", which is not a key agreement '
                'key type',
          ),
        ),
      );
      expect(
        () => roleKeyJwk('operational', 'C${'A' * 43}'),
        throwsA(
          isA<InvalidKeyError>().having(
            (e) => e.message,
            'message',
            '"C${'A' * 43}" uses CESR code "C", which is not a verification '
                'key',
          ),
        ),
      );
      // A revoked key is read as whichever kind it was.
      expect(revokedKeyJwk('C${'A' * 43}'), containsPair('crv', 'X25519'));
    });

    test('a small-order or non-point Ed25519 key converts to nothing', () {
      // The identity (y = 1) is of small order.
      final identity = Uint8List(32)..[0] = 1;
      expect(convertedKeyAgreement([matterQb64('D', identity)]), isEmpty);
      // y = 2 is not the y of a curve point.
      final noPoint = Uint8List(32)..[0] = 2;
      expect(convertedKeyAgreement([matterQb64('D', noPoint)]), isEmpty);
      expect(convertedKeyAgreement(['not a key']), isEmpty);
    });

    test('the implemented schemas are both versions of each designation', () {
      expect(implementedSchemas, hasLength(8));
      expect(implementedSchemas.toSet(), hasLength(8));
      expect(keyRoles.map((r) => r.relationship), [
        'assertionMethod',
        'authentication',
        'keyAgreement',
      ]);
    });
  });

  group('services', () {
    String? reason(Object? service) {
      try {
        checkService(fromJson(service));
        return null;
      } on DesignationError catch (e) {
        return e.message;
      }
    }

    test('a designated service must be one a DID document can carry', () {
      const ok = {'id': '#m', 'type': 'X', 'serviceEndpoint': 'https://x'};
      expect(reason(ok), isNull);
      expect(
        reason({
          ...ok,
          'type': ['X', 'Y'],
        }),
        isNull,
      );
      expect(
        reason({
          ...ok,
          'serviceEndpoint': {'uri': 'x'},
        }),
        isNull,
      );
      expect(reason({'type': 'X'}), 'a designated service has no `id`');
      expect(
        reason({...ok, 'id': 'm'}),
        'designated service id "m" is not a relative DID URL fragment',
      );
      expect(
        reason({...ok, 'id': '#'}),
        'designated service id "#" is not a relative DID URL fragment',
      );
      expect(
        reason({...ok, 'id': '#a#b'}),
        'designated service id "#a#b" is not a relative DID URL fragment',
      );
      for (final type in [
        '',
        <String>[],
        ['X', ''],
        7,
      ]) {
        expect(
          reason({...ok, 'type': type}),
          'designated service #m has no usable `type`',
        );
      }
      expect(
        reason({...ok, 'serviceEndpoint': 7}),
        'designated service #m has no `serviceEndpoint`',
      );
    });
  });

  group('RFC 3339 (chrono parse_from_rfc3339)', () {
    test('reads what chrono reads, to the same instant', () {
      expect(parseRfc3339('1970-01-01T00:00:00Z'), (0, 0));
      expect(parseRfc3339('1970-01-01t00:00:00z'), (0, 0));
      expect(parseRfc3339('1970-01-01 00:00:01+00:00'), (1, 0));
      expect(parseRfc3339('1970-01-01T01:00:00+01:00'), (0, 0));
      expect(parseRfc3339('1970-01-01T00:00:00−01:00'), (3600, 0));
      expect(parseRfc3339('2026-11-10T07:46:58.751848+00:00'), (
        1794296818,
        751848000,
      ));
      expect(parseRfc3339('2000-02-29T00:00:00.1234567891Z'), (
        951782400,
        123456789,
      ));
      // A leap second is the last second of its minute, plus one.
      expect(parseRfc3339('2016-12-31T23:59:60Z'), (1483228799, 1000000000));
      expect(parseRfc3339('2026-11-10T23:59:60.5Z'), (1794355199, 1500000000));
      expect(parseRfc3339('0000-01-01T00:00:00Z')!.$1, -62167219200);
    });

    test('refuses what chrono refuses', () {
      for (final s in [
        null,
        7,
        '',
        '2026-11-10',
        '2026-11-10T07:46:58',
        '2026-13-01T00:00:00Z',
        '2025-02-29T00:00:00Z',
        '2026-11-10X07:46:58Z',
        '2026-11-10T24:00:00Z',
        '2026-11-10T07:46:58.Z',
        '2026-11-10T07:46:58+0100',
        '2026-11-10T07:46:58+01:60',
        '2026-11-10T07:46:58+24:00',
        '2026-11-10T07:46:58Z ',
      ]) {
        expect(parseRfc3339(s), isNull, reason: '$s');
      }
    });

    test('instants order by second, then nanosecond', () {
      final a = parseRfc3339('2026-01-01T00:00:00.5Z')!;
      final b = parseRfc3339('2026-01-01T00:00:01Z')!;
      expect(compareInstants(a, b), lessThan(0));
      expect(compareInstants(b, a), greaterThan(0));
      expect(compareInstants(a, a), 0);
    });
  });
}
