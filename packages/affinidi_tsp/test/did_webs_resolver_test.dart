// did:webs resolution (lib/src/did_webs/resolver.dart and
// lib/src/ssi/did_webs_resolver.dart), checked three ways:
//
// - against the Rust reference: every `resolve` record of the conformance
//   vectors recorded from `affinidi-did-webs` must give the Rust document and
//   metadata, or be refused with the same error kind;
// - against the JS port it follows (vti-didcomm-js `src/did-webs.js`): every
//   one of those resolutions, and every published fixture with and without
//   its did.json and as of each event, must give the same document and
//   metadata or the same refusal, to the message; and a set of DIDs must
//   parse, and give artifact URLs under each egress policy, as the JS does;
// - and the JS port's own resolver and network-policy tests.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:affinidi_tsp/src/did_webs/kel.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import 'support/did_webs_resolve_outcome.dart';
import 'support/did_webs_vectors.dart';

Map<String, Object?> _golden() {
  final bytes = File(
    '$didWebsFixtures/golden/resolve-golden.json.gz',
  ).readAsBytesSync();
  return jsonDecode(utf8.decode(gzip.decode(bytes))) as Map<String, Object?>;
}

Uint8List _bytes(String s) => Uint8List.fromList(utf8.encode(s));

const String _aid = 'ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe';
const String _did = 'did:webs:did-webs-service%3a7676:$_aid';
final Uint8List _cesr = didWebsFixture('ENro7uf0.keri.cesr');
final Uint8List _didJson = didWebsFixture('ENro7uf0.did.json');

Matcher _refused(String kind) => throwsA(
  isA<DidWebsError>()
      .having((e) => e.kind, 'kind', kind)
      .having((e) => e.code, 'code', SsiExceptionType.unableToResolveDid.code),
);

Matcher _blocked([BlockedReason? reason]) => throwsA(
  isA<BlockedEndpointException>().having(
    (e) => e.reason,
    'reason',
    reason ?? anything,
  ),
);

String _edited(void Function(Map<String, dynamic> doc) edit) {
  final doc = jsonDecode(utf8.decode(_didJson)) as Map<String, dynamic>;
  edit(doc);
  return jsonEncode(doc);
}

DidWebsResolution _resolve(String did, Object cesr, [Object? didJson]) =>
    resolveDidWebsFromArtifacts(
      did,
      cesr is String ? _bytes(cesr) : cesr as Uint8List,
      didJson == null
          ? null
          : didJson is String
          ? _bytes(didJson)
          : didJson as Uint8List,
    );

String _reason(BlockedReason r) => switch (r) {
  BlockedReason.invalidUrl => 'invalid_url',
  BlockedReason.scheme => 'scheme',
  BlockedReason.userinfo => 'userinfo',
  BlockedReason.privateAddress => 'private_address',
  BlockedReason.privateName => 'private_name',
  BlockedReason.notAllowlisted => 'not_allowlisted',
  BlockedReason.redirect => 'redirect',
  BlockedReason.tooLarge => 'too_large',
  BlockedReason.timeout => 'timeout',
};

const Map<String, NetPolicy> _policies = {
  'none': NetPolicy(),
  'private': NetPolicy(allowPrivate: true),
  'insecure': NetPolicy(allowInsecure: true),
  'allow': NetPolicy(allowHosts: ['example.com']),
};

// ─── Network helpers ────────────────────────────────────────────────────

Future<List<InternetAddress>> _publicLookup(String host) async => [
  InternetAddress('93.184.216.34'),
];

/// A transport serving the reference artifacts, recording every request.
(MockClient, List<http.BaseRequest>) _serving({
  Uint8List? cesr,
  Uint8List? didJson,
  int status = 200,
}) {
  final calls = <http.BaseRequest>[];
  final client = MockClient((request) async {
    calls.add(request);
    if (status != 200) return http.Response('nope', status);
    final path = request.url.path;
    if (path.endsWith('/keri.cesr')) {
      return http.Response.bytes(cesr ?? _cesr, 200);
    }
    if (path.endsWith('/did.json')) {
      return http.Response.bytes(didJson ?? _didJson, 200);
    }
    return http.Response('not found', 404);
  });
  return (client, calls);
}

DidWebsResolver _resolver({
  http.Client? transport,
  NetPolicy policy = const NetPolicy(allowPrivate: true),
  Duration timeout = defaultWebsTimeout,
  HostLookup? lookup,
}) => DidWebsResolver(
  netPolicy: policy,
  transport: transport,
  timeout: timeout,
  lookup: lookup ?? _publicLookup,
);

void main() {
  group('did:webs resolution: parity with the Rust reference', () {
    final records = [
      for (final e in loadVectors().entries)
        for (final r in e.value)
          if (r['op'] == 'resolve') r,
    ];

    test('covers every resolve record', () {
      expect(records, hasLength(1610));
    });

    for (final rec in records) {
      final label =
          '${rec['source']}'
          '${rec['mutation'] == null ? '' : ' ${jsonEncode(rec['mutation'])}'}'
          ' [resolve]';
      test(label, () {
        final stream = mutate(
          vectorBlob(rec['keri_cesr']! as String),
          rec['mutation'] as Map<String, Object?>?,
        );
        final didJson = rec['did_json'] == null
            ? null
            : vectorBlob(rec['did_json']! as String);
        final got = resolveOutcome(rec['did']! as String, stream, didJson);
        if (rec['ok'] != true) {
          final want = (rec['error']! as Map)['kind'];
          expect(got['error'], want, reason: '${got['message']}');
        } else {
          expect(got['error'], isNull, reason: '${got['message']}');
          expect(
            jsonDecode(
              jsonEncode(
                asRustDocument(got['document']! as Map<String, Object?>),
              ),
            ),
            asRustDocument(rec['document']! as Map<String, Object?>),
          );
          expect(got['metadata'], rec['metadata']);
        }
      });
    }
  });

  group('did:webs resolution: parity with the JavaScript port', () {
    final golden = _golden();
    final cases = (golden['cases']! as List).cast<Map<String, Object?>>();
    final parses = (golden['parses']! as List).cast<Map<String, Object?>>();

    test('covers every resolve record and fixture', () {
      expect(cases.length, greaterThan(1700));
      expect(parses.length, greaterThan(150));
    });

    for (final c in cases) {
      final name = c['file'] != null
          ? 'fixture ${c['file']} ${c['did']} ${c['didJsonFile']}'
          : '${c['source']} ${jsonEncode(c['mutation'])}';
      test(name, () {
        final Uint8List stream;
        final Uint8List? didJson;
        if (c['file'] != null) {
          stream = didWebsFixture(c['file']! as String);
          didJson = c['didJsonFile'] == null
              ? null
              : didWebsFixture(c['didJsonFile']! as String);
        } else {
          stream = mutate(
            vectorBlob(c['blob']! as String),
            c['mutation'] as Map<String, Object?>?,
          );
          didJson = c['didJson'] == null
              ? null
              : vectorBlob(c['didJson']! as String);
        }
        final want = Map.of(c)
          ..remove('file')
          ..remove('blob')
          ..remove('mutation')
          ..remove('source')
          ..remove('did')
          ..remove('didJson')
          ..remove('didJsonFile');
        final got = jsonDecode(
          jsonEncode(resolveOutcome(c['did']! as String, stream, didJson)),
        );
        expect(got, want);
      });
    }

    test('parses every identifier, and gives its artifact URLs, as the JS '
        'does', () {
      for (final p in parses) {
        final did = p['did']! as String;
        expect(parseOutcome(did), p['parsed'], reason: did);
        final urls = p['urls']! as Map<String, Object?>;
        for (final MapEntry(key: name, value: want) in urls.entries) {
          Object? got;
          try {
            final u = websArtifactUrls(did, _policies[name]!);
            got = [u.keriCesrHref, u.didJsonHref];
          } on BlockedEndpointException catch (e) {
            got = {'error': 'Blocked', 'reason': _reason(e.reason)};
          }
          expect(got, want, reason: '$did under $name');
        }
      }
    });
  });

  // ─── The identifier ───────────────────────────────────────────────────

  group('parseDidWebs', () {
    test('host, port, path and AID, with a versionId', () {
      final p = parseDidWebs('did:webs:example.com:$_aid');
      expect(
        [p.did, p.versionId, p.host, p.path, p.aid],
        ['did:webs:example.com:$_aid', null, 'example.com', <String>[], _aid],
      );
      final parsed = parseDidWebs(
        'did:webs:example.com%3A8443:users:alice:$_aid?versionId=2#key-1',
      );
      expect(parsed.did, 'did:webs:example.com%3A8443:users:alice:$_aid');
      expect(parsed.host, 'example.com:8443');
      expect(parsed.path, ['users', 'alice']);
      expect(parsed.versionId, 2);
      // The port separator is written lowercase in the wild.
      expect(parseDidWebs(_did).host, 'did-webs-service:7676');
      expect(
        parseDidWebs('did:webs:%5B%3A%3A1%5D%3A7676:$_aid').host,
        '[::1]:7676',
      );
    });

    test('refuses what is not a did:webs, or names something other than a '
        'host', () {
      for (final did in [
        'did:web:example.com:$_aid',
        'did:webs:',
        'did:webs:$_aid',
        'did:webs:example.com::$_aid',
        'did:webs:example.com:E!',
        'did:webs:example.com:Eab',
        'did:webs:example.com:$_aid?versionId=two',
        'did:webs:a.example%40b.example:$_aid',
        'did:webs:a.example%2Fb:$_aid',
        'did:webs:a.example%23x:$_aid',
        'did:webs:a.example%2541:$_aid',
        'did:webs:a%20b.example:$_aid',
        'did:webs:example.com%3A99999:$_aid',
        'did:webs:example.com%3A:$_aid',
        'did:webs:%5Bnot-v6%5D:$_aid',
        'did:webs:example.com%zz:$_aid',
        'did:webs:example.com:..:$_aid',
        'did:webs:example.com:a%2Fb:$_aid',
        'did:webs:example.com:a%3Fb:$_aid',
      ]) {
        expect(() => parseDidWebs(did), _refused('InvalidDid'), reason: did);
      }
    });

    test('websArtifactUrls: the artifacts sit under the AID, over https '
        'unless the policy says otherwise', () {
      List<String> urls(String did, [NetPolicy policy = const NetPolicy()]) {
        final u = websArtifactUrls(did, policy);
        return [u.keriCesrHref, u.didJsonHref];
      }

      expect(urls('did:webs:example.com:users:$_aid'), [
        'https://example.com/users/$_aid/keri.cesr',
        'https://example.com/users/$_aid/did.json',
      ]);
      expect(
        urls(
          'did:webs:localhost%3A7676:$_aid',
          const NetPolicy(allowPrivate: true),
        ),
        [
          'http://localhost:7676/$_aid/keri.cesr',
          'http://localhost:7676/$_aid/did.json',
        ],
      );
      expect(
        urls('did:webs:10.0.0.5:$_aid', const NetPolicy(allowPrivate: true))[0],
        'https://10.0.0.5/$_aid/keri.cesr',
      );
      expect(
        urls(
          'did:webs:example.com:$_aid',
          const NetPolicy(allowInsecure: true),
        )[0],
        'http://example.com/$_aid/keri.cesr',
      );
      expect(
        () => websArtifactUrls('did:webs:localhost%3A7676:$_aid'),
        _blocked(),
      );
    });
  });

  // ─── The reference identifier ─────────────────────────────────────────

  group('the did-webs-resolver reference identifier', () {
    test('resolves from its artifacts', () {
      final r = _resolve(_did, _cesr, _didJson);
      expect(r.didResolutionMetadata['contentType'], 'application/did+ld+json');
      final doc = r.didDocument;
      expect(doc['id'], _did);
      expect(doc['controller'], _did);
      const key = '$_did#DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr';
      expect(doc['authentication'], [key]);
      expect(doc['assertionMethod'], [key]);
      expect((doc['verificationMethod']! as List).first, {
        'id': key,
        'type': 'JsonWebKey',
        'controller': _did,
        'publicKeyJwk': {
          'crv': 'Ed25519',
          'kid': 'DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr',
          'kty': 'OKP',
          'x': 'evT4j6Yw3uHpwsw5NEmSR8-4x3S-BA-s6Thjd51oeOs',
        },
      });
      // It designates no key agreement, so its Ed25519 key's X25519
      // conversion is rendered, as KERI practice does.
      expect(doc['keyAgreement'], [
        '$_did#CPz5wadpRpL4rGHeRSLHIc-2jMndx_mYBhuPhcr7WFRg',
      ]);
      final aka = doc['alsoKnownAs']! as List;
      expect(aka, contains('did:keri:$_aid'));
      expect(aka, contains('did:webs:foo.com:$_aid'));
      expect(aka, isNot(contains(_did)), reason: 'not its own alias');
      expect(r.didDocumentMetadata, {
        'versionId': '2',
        'equivalentId': ['did:webs:foo.com:$_aid'],
      });
    });

    test('resolves as of a key event with versionId', () {
      expect(
        _resolve(
          '$_did?versionId=2',
          _cesr,
          _didJson,
        ).didDocumentMetadata['versionId'],
        '2',
      );
      // At sequence number 1 the registry is anchored but the issuance is
      // not, so nothing designated the DID yet, and it did not resolve then.
      expect(
        () => _resolve('$_did?versionId=1', _cesr),
        _refused('NotDesignated'),
      );
      expect(
        () => _resolve('$_did?versionId=7', _cesr, _didJson),
        _refused('Kel'),
      );
    });

    test('the same artifacts do not resolve for a DID the AID never '
        'designated', () {
      expect(
        () => _resolve('did:webs:attacker.example:$_aid', _cesr, _didJson),
        _refused('NotDesignated'),
      );
    });

    test('did.json may leave out what the key state implies, but never add '
        'to it or change it', () {
      _resolve(_did, _cesr, _didJson);
      _resolve(_did, _cesr, _edited((d) => d.remove('service')));
      final edits = <String, void Function(Map<String, dynamic>)>{
        'a member nothing establishes': (d) => d['extra'] = true,
        'an undesignated alias': (d) =>
            (d['alsoKnownAs'] as List).add('did:web:attacker.example:x'),
        'an unauthorised service': (d) => (d['service'] as List).add({
          'id': '#x',
          'type': 'LinkedDomains',
          'serviceEndpoint': 'https://x.example/',
        }),
        'an unauthorised key': (d) => (d['verificationMethod'] as List).add({
          ...((d['verificationMethod'] as List).first as Map),
          'id': '#DAAAA',
        }),
        'a missing key': (d) => d['verificationMethod'] = <Object?>[],
        'a changed key': (d) =>
            (((d['verificationMethod'] as List).first as Map)['publicKeyJwk']
                    as Map)['x'] =
                'AAAA',
        'an empty authentication': (d) => d['authentication'] = <Object?>[],
      };
      for (final MapEntry(key: what, value: edit) in edits.entries) {
        expect(
          () => _resolve(_did, _cesr, _edited(edit)),
          _refused('DocumentMismatch'),
          reason: what,
        );
      }
      expect(
        () => _resolve(
          _did,
          _cesr,
          _edited((d) => d['id'] = 'did:web:other.example:$_aid'),
        ),
        _refused('DocumentMismatch'),
      );
      // In its did:webs form a document names its controller as it stands.
      final webs = _edited((d) {
        d['id'] = _did;
        d['controller'] = 'did:web:attacker.example:x';
      });
      expect(() => _resolve(_did, _cesr, webs), _refused('DocumentMismatch'));
      expect(() => _resolve(_did, _cesr, '{not json'), _refused('Json'));
    });

    test('a tampered key event stream is refused', () {
      final text = utf8.decode(_cesr);
      final tampered = text.replaceFirst(
        'DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr',
        'DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjs',
      );
      expect(() => _resolve(_did, tampered, _didJson), _refused('Kel'));
      expect(
        () => _resolve(_did, _cesr.sublist(0, _cesr.length - 7), _didJson),
        _refused('Stream'),
      );
      expect(
        () => _resolve(_did, Uint8List.fromList([0xa1, 0x61, 0x76]), _didJson),
        _refused('Stream'),
      );
    });

    test('a stream is bounded in bytes', () {
      expect(
        () => _resolve(
          _did,
          Uint8List(maxWebsArtifactBytes + 1)..fillRange(0, 10, 0x20),
          _didJson,
        ),
        _refused('Stream'),
      );
    });
  });

  // ─── Deactivation (0.13.3, TDK-SEC-027) ───────────────────────────────

  group('deactivation', () {
    final cesr = didWebsFixture('deactivated/keri.cesr');
    final did = File(
      '$didWebsFixtures/vectors/deactivated/did.txt',
    ).readAsStringSync().trim();

    test("a deactivated identifier's document keeps no keys, at the "
        'deactivating version', () {
      for (final published in [
        'deactivated/did.json',
        'deactivated/legacy.did.json',
        null,
      ]) {
        final r = _resolve(
          did,
          cesr,
          published == null ? null : didWebsFixture(published),
        );
        expect(r.didDocument.keys.toList()..sort(), [
          'alsoKnownAs',
          'id',
        ], reason: '$published');
        expect(r.didDocumentMetadata['deactivated'], true);
      }
      // An earlier version keeps that version's keys; the DID is still
      // reported deactivated.
      final earlier = _resolve('$did?versionId=3', cesr);
      expect(earlier.didDocument['verificationMethod'], isNotEmpty);
      expect(earlier.didDocumentMetadata['deactivated'], true);
    });

    test('network resolution refuses a deactivated identifier: it is a '
        'document provider', () async {
      for (final published in [
        'deactivated/did.json',
        'deactivated/legacy.did.json',
      ]) {
        final (transport, _) = _serving(
          cesr: cesr,
          didJson: didWebsFixture(published),
        );
        await expectLater(
          _resolver(
            transport: transport,
            policy: const NetPolicy(),
          ).resolveWithMetadata(did),
          _refused('Deactivated'),
        );
      }
    });
  });

  // ─── KERI 2.0 fixtures ────────────────────────────────────────────────

  group('the KERI 2.0 lifecycle keripy accepts', () {
    final spec =
        jsonDecode(
              File(
                '$didWebsFixtures/vectors/ours-v2/lifecycle.json',
              ).readAsStringSync(),
            )
            as Map<String, Object?>;
    final did = spec['did']! as String;
    final cesr = didWebsFixture('ours-v2/lifecycle.keri.cesr');
    final published =
        jsonDecode(utf8.decode(didWebsFixture('ours-v2/lifecycle.did.json')))
            as Map<String, dynamic>;

    test('resolves, with its designations', () {
      final doc = _resolve(
        did,
        cesr,
        didWebsFixture('ours-v2/lifecycle.did.json'),
      ).didDocument;
      expect(doc['keyAgreement'], hasLength(1));
      final services = jsonEncode(doc['service']);
      expect(services, contains('DIDCommMessaging'));
      expect(services, contains('https://example.com/v2/'));
      final state = Kels.parse(cesr).keyState(parseDidWebs(did).aid);
      final kel = spec['kel']! as Map;
      expect(state.sn, kel['sn']);
      expect(state.lastEventDigest, kel['said']);
    });

    test("a service's type is compared as a set, as DID Core writes it "
        'either way', () {
      String withTypes(Object types) {
        final doc = jsonDecode(jsonEncode(published)) as Map<String, dynamic>;
        for (final s in (doc['service'] as List).cast<Map<String, Object?>>()) {
          if (s['type'] == 'DIDCommMessaging') s['type'] = types;
        }
        return jsonEncode(doc);
      }

      _resolve(did, cesr, withTypes(['DIDCommMessaging']));
      final arrays = jsonDecode(jsonEncode(published)) as Map<String, dynamic>;
      for (final s
          in (arrays['service'] as List).cast<Map<String, Object?>>()) {
        s['type'] = [s['type']];
      }
      _resolve(did, cesr, jsonEncode(arrays));
      // The resolver's own rendering of the document, fed back as did.json,
      // resolves.
      final own = _resolve(did, cesr).didDocument;
      _resolve(did, cesr, jsonEncode(own));
      for (final MapEntry(key: what, value: types) in {
        'a type the stream does not authorise': [
          'DIDCommMessaging',
          'LinkedDomains',
        ],
        'no type': <String>[],
        'a type that is not a string': [7],
      }.entries) {
        expect(
          () => _resolve(did, cesr, withTypes(types)),
          _refused('DocumentMismatch'),
          reason: what,
        );
      }
    });
  });

  // ─── The network (vti-didcomm-js did-webs-ssrf.test.js) ───────────────

  group('network policy', () {
    List<(String, BlockedReason)> vectors(int port) => [
      ('localhost%3A$port', BlockedReason.privateName),
      ('log.localhost%3A$port', BlockedReason.privateName),
      ('127.0.0.1%3A$port', BlockedReason.privateAddress),
      ('127.1%3A$port', BlockedReason.privateAddress),
      ('2130706433%3A$port', BlockedReason.privateAddress),
      ('%5B%3A%3A1%5D%3A$port', BlockedReason.privateAddress),
      ('169.254.169.254', BlockedReason.privateAddress),
      ('10.0.0.5', BlockedReason.privateAddress),
      ('192.168.1.1', BlockedReason.privateAddress),
      ('100.100.100.200', BlockedReason.privateAddress),
      ('intranet', BlockedReason.privateName),
      ('log.internal', BlockedReason.privateName),
      ('printer.local', BlockedReason.privateName),
    ];

    test('a non-public host is refused before any fetch, through both entry '
        'points', () async {
      var fetched = 0;
      final transport = MockClient((_) async {
        fetched++;
        throw StateError('must not be called');
      });
      final resolver = DidWebsResolver(
        transport: transport,
        lookup: (h) {
          fetched++;
          throw StateError('must not be looked up');
        },
      );
      final vids = SsiVidResolver(didResolver: resolver);
      for (final (host, reason) in vectors(8000)) {
        final did = 'did:webs:$host:$_aid';
        await expectLater(
          resolver.resolveWithMetadata(did),
          _blocked(reason),
          reason: did,
        );
        await expectLater(
          resolver.resolveDid(did),
          _blocked(reason),
          reason: did,
        );
        await expectLater(
          vids.resolve(did),
          throwsA(
            isA<TspUnsupportedException>().having(
              (e) => e.cause,
              'cause',
              isA<BlockedEndpointException>(),
            ),
          ),
        );
      }
      expect(fetched, 0);
    });

    test('a refused loopback host gets no request and no connection', () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final hits = <String>[];
      var connections = 0;
      server.listen((req) {
        hits.add(req.uri.path);
        req.response
          ..add(req.uri.path.endsWith('/keri.cesr') ? _cesr : _didJson)
          ..close();
      });
      final counting = server.connectionsInfo;
      try {
        for (final host in [
          'localhost%3A${server.port}',
          '127.0.0.1%3A${server.port}',
          '0x7f000001%3A${server.port}',
        ]) {
          final did = 'did:webs:$host:$_aid';
          await expectLater(
            DidWebsResolver().resolveWithMetadata(did),
            _blocked(),
            reason: did,
          );
        }
        connections = counting().total;
        expect(hits, isEmpty);
        expect(connections, 0);

        // Positive control: with private hosts admitted, a loopback host is
        // fetched over plain http — both artifacts, in order — and then
        // refused because the stream does not designate a DID at this host.
        await expectLater(
          DidWebsResolver(
            netPolicy: const NetPolicy(allowPrivate: true),
          ).resolveWithMetadata('did:webs:127.0.0.1%3A${server.port}:$_aid'),
          _refused('NotDesignated'),
        );
        expect(hits, ['/$_aid/keri.cesr', '/$_aid/did.json']);
      } finally {
        await server.close(force: true);
      }
    });

    test('allowHosts narrows, and never re-admits a private address', () async {
      final (transport, calls) = _serving();
      await expectLater(
        _resolver(
          transport: transport,
          policy: const NetPolicy(allowHosts: ['other.example']),
        ).resolveWithMetadata('did:webs:example.com:$_aid'),
        _blocked(BlockedReason.notAllowlisted),
      );
      await expectLater(
        _resolver(
          transport: transport,
          policy: const NetPolicy(allowHosts: ['127.0.0.1']),
        ).resolveWithMetadata('did:webs:127.0.0.1:$_aid'),
        _blocked(BlockedReason.privateAddress),
      );
      expect(calls, isEmpty);
    });

    test('resolves through the vetted transport, which never follows a '
        'redirect', () async {
      final (transport, calls) = _serving();
      final r = await _resolver(transport: transport).resolveWithMetadata(_did);
      expect(r.didDocument['id'], _did);
      expect(calls.map((c) => '${c.url}'), [
        'https://did-webs-service:7676/$_aid/keri.cesr',
        'https://did-webs-service:7676/$_aid/did.json',
      ]);
      for (final c in calls) {
        expect(c.followRedirects, isFalse);
      }

      final redirecting = MockClient(
        (_) async => http.Response(
          '',
          302,
          headers: {'location': 'http://169.254.169.254/'},
        ),
      );
      await expectLater(
        _resolver(transport: redirecting).resolveWithMetadata(_did),
        _blocked(BlockedReason.redirect),
      );
    });

    test('both artifacts are required, and a failed fetch is a Fetch '
        'error', () async {
      final (notFound, _) = _serving(status: 404);
      await expectLater(
        _resolver(transport: notFound).resolveWithMetadata(_did),
        throwsA(
          isA<DidWebsError>()
              .having((e) => e.kind, 'kind', 'Fetch')
              .having((e) => e.status, 'status', 404)
              .having(
                (e) => e.message,
                'message',
                'did:webs: could not fetch '
                    'https://did-webs-service:7676/$_aid/keri.cesr: HTTP 404',
              ),
        ),
      );
      final noDidJson = MockClient(
        (req) async => req.url.path.endsWith('/keri.cesr')
            ? http.Response.bytes(_cesr, 200)
            : http.Response('gone', 410),
      );
      await expectLater(
        _resolver(transport: noDidJson).resolveWithMetadata(_did),
        _refused('Fetch'),
      );
      final failing = MockClient(
        (_) async => throw const SocketException('network down'),
      );
      await expectLater(
        _resolver(transport: failing).resolveWithMetadata(_did),
        _refused('Fetch'),
      );
    });

    test('an artifact over 4 MiB is refused, by its declared length or as it '
        'is read', () async {
      final declared = MockClient.streaming(
        (req, _) async => http.StreamedResponse(
          Stream.value([0x78]),
          200,
          contentLength: maxWebsArtifactBytes + 1,
        ),
      );
      await expectLater(
        _resolver(transport: declared).resolveWithMetadata(_did),
        throwsA(
          isA<DidWebsError>()
              .having((e) => e.kind, 'kind', 'Fetch')
              .having(
                (e) => e.message,
                'message',
                endsWith(
                  ': the did:webs keri.cesr declares 4194305 bytes, over the '
                  '4194304-byte cap',
                ),
              ),
        ),
      );

      var pulled = 0;
      final chunk = List<int>.filled(64 * 1024, 0x20);
      Stream<List<int>> endless() async* {
        while (true) {
          pulled += chunk.length;
          yield chunk;
        }
      }

      final streaming = MockClient.streaming(
        (req, _) async => http.StreamedResponse(endless(), 200),
      );
      await expectLater(
        _resolver(transport: streaming).resolveWithMetadata(_did),
        throwsA(
          isA<DidWebsError>()
              .having((e) => e.kind, 'kind', 'Fetch')
              .having(
                (e) => e.message,
                'message',
                endsWith('is over the 4194304-byte cap'),
              ),
        ),
      );
      expect(
        pulled,
        lessThanOrEqualTo(maxWebsArtifactBytes + 2 * chunk.length),
      );
    });

    test('a stalled host times out', () async {
      final stalled = MockClient((_) => Completer<http.Response>().future);
      await expectLater(
        _resolver(
          transport: stalled,
          timeout: const Duration(milliseconds: 20),
        ).resolveWithMetadata(_did),
        _refused('Fetch'),
      );
    });
  });

  // ─── The surface ──────────────────────────────────────────────────────

  group('SsiVidResolver', () {
    test('resolves a did:webs VID through its default chain', () async {
      final (transport, _) = _serving();
      final vids = SsiVidResolver(
        didResolver: DidPeer4Resolver(
          fallback: DidScidResolver(fallback: _resolver(transport: transport)),
        ),
      );
      final vid = await vids.resolve(_did);
      expect(vid.id, _did);
      expect(vid.verificationKey, isA<Ed25519VerificationKey>());
      expect(vid.encryptionKey, isA<X25519EncryptionKey>());
    });

    test(
      'a did:webs VTA with key roles maps each relationship to its key',
      () async {
        String read(String p) =>
            File('$didWebsFixtures/vectors/parties/vta/$p').readAsStringSync();
        final did = read('did.txt').trim();
        final (transport, _) = _serving(
          cesr: didWebsFixture('parties/vta/keri.cesr'),
          didJson: didWebsFixture('parties/vta/did.json'),
        );
        final doc = await _resolver(transport: transport).resolveDid(did);
        expect(doc.id, did);
        final vid = publicVidFromDocument(doc);
        expect(vid.encryptionKey, isA<X25519EncryptionKey>());
        // The Rust resolver's own derivation of this document.
        final resolved =
            jsonDecode(read('resolved.json')) as Map<String, Object?>;
        final ours = _resolve(
          did,
          didWebsFixture('parties/vta/keri.cesr'),
          didWebsFixture('parties/vta/did.json'),
        );
        expect(
          jsonDecode(jsonEncode(asRustDocument(ours.didDocument))),
          asRustDocument(
            (resolved['didDocument'] ?? resolved['document'] ?? resolved)
                as Map<String, Object?>,
          ),
        );
      },
    );

    test('the default chain resolves did:webs', () {
      final chain = SsiVidResolver().didResolver;
      expect(chain, isA<DidPeer4Resolver>());
      final scid = (chain as DidPeer4Resolver).fallback;
      expect(scid, isA<DidScidResolver>());
      expect((scid as DidScidResolver).fallback, isA<DidWebsResolver>());
    });
  });
}
