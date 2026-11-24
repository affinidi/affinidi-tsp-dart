// did:scid:vh:1 — a DID in its own right, verified by a did:webvh log.
//
// The helper and conversion vectors are the ones OpenVTC vti-didcomm-js
// `test/did-scid.test.js` ports from the Rust stack (affinidi_did_common::scid
// and didwebvh-rs did_web.rs). Resolution runs against `ssi`'s signed example
// did:webvh logs (affinidi-ssi-dart, Apache-2.0), served by a mock client.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

const _bobScid = 'QmRcnRLQ5GGA3JUtCMyEdMEkssSg8Hkvjj9EfKaRQw4YbZ';
const _bobSrc =
    'raw.githubusercontent.com/affinidi/affinidi-ssi-dart/refs/heads/main/'
    'example/dids/didwebvh/bob';
const _bobScidDid = 'did:scid:vh:1:$_bobScid';
const _bobScidUrl = '$_bobScidDid?src=$_bobSrc';
const _bobWebvh =
    'did:webvh:$_bobScid:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:'
    'refs:heads:main:example:dids:didwebvh:bob';
const _bobLogUrl = 'https://$_bobSrc/did.jsonl';

String _fixture(String name) =>
    File('test/fixtures/didwebvh/$name').readAsStringSync();

/// Answers every DNS lookup with a public documentation-free address, so
/// tests make no real lookups.
Future<List<InternetAddress>> _publicDns(String host) async => [
  InternetAddress('93.184.215.14'),
];

/// A resolver whose transport is [client] and whose DNS is [_publicDns].
DidScidResolver _resolver(
  http.Client client, {
  HostLookup lookup = _publicDns,
  NetPolicy netPolicy = const NetPolicy(),
  int maxBytes = defaultMaxArtifactBytes,
  int maxLogEntries = defaultMaxLogEntries,
  Duration timeout = defaultRequestTimeout,
}) => DidScidResolver(
  transport: client,
  lookup: lookup,
  netPolicy: netPolicy,
  maxBytes: maxBytes,
  maxLogEntries: maxLogEntries,
  timeout: timeout,
);

Matcher _blocked(BlockedReason reason) =>
    isA<BlockedEndpointException>().having((e) => e.reason, 'reason', reason);

Matcher _failed(DidScidFailure failure) => isA<DidScidResolutionException>()
    .having((e) => e.failure, 'failure', failure);

/// Serves [body] for the bob log, and 404 for everything else.
http.Client _serving(String Function() body) => MockClient((request) async {
  if (request.url.toString() == _bobLogUrl) {
    return http.Response(body(), 200);
  }
  return http.Response('not found', 404);
});

void main() {
  group('the src locator', () {
    test('stripScidSrc removes src, keeping the fragment', () {
      expect(
        stripScidSrc('did:scid:vh:1:Qm?src=example.com/alice'),
        'did:scid:vh:1:Qm',
      );
      expect(
        stripScidSrc('did:scid:vh:1:Qm?src=localhost%3A8000/a#key-1'),
        'did:scid:vh:1:Qm#key-1',
      );
    });

    test('stripScidSrc leaves everything else', () {
      for (final did in [
        'did:scid:vh:1:Qm',
        'did:scid:vh:1:Qm#key-1',
        'did:scid:vh:1:Qm?src=example.com&versionId=2',
        'did:scid:vh:1:Qm?versionId=2#key-1',
        'did:scid:vh:1:Qm?src=',
        'did:webvh:Qm:example.com?versionId=1#key-1',
        'did:example:123?src=example.com',
      ]) {
        expect(stripScidSrc(did), did, reason: did);
      }
    });

    test('scidSrc', () {
      expect(
        scidSrc('did:scid:vh:1:Qm?src=example.com/alice#k'),
        'example.com/alice',
      );
      expect(scidSrc('did:scid:vh:1:Qm'), isNull);
    });

    test('withScidSrc adds src to a bare reference only', () {
      expect(
        withScidSrc('did:scid:vh:1:Qm#key-1', 'example.com/alice'),
        'did:scid:vh:1:Qm?src=example.com/alice#key-1',
      );
      expect(
        withScidSrc('did:scid:vh:1:Qm', 'example.com'),
        'did:scid:vh:1:Qm?src=example.com',
      );
      for (final unchanged in [
        'did:scid:vh:1:Qm?src=a.example#key-1',
        'did:webvh:Qm:example.com#key-1',
      ]) {
        expect(withScidSrc(unchanged, 'b.example'), unchanged);
      }
    });

    test('sameReference compares by DID and fragment, ignoring src', () {
      expect(
        sameReference(
          'did:scid:vh:1:Qm?src=example.com#key-1',
          'did:scid:vh:1:Qm#key-1',
        ),
        isTrue,
      );
      expect(
        sameReference(
          'did:scid:vh:1:Qm?src=a.example#key-1',
          'did:scid:vh:1:Qm?src=b.example#key-1',
        ),
        isTrue,
      );
      expect(
        sameReference(
          'did:scid:vh:1:Qm?src=example.com#key-1',
          'did:scid:vh:1:Qm#key-2',
        ),
        isFalse,
      );
      expect(
        sameReference(
          'did:scid:vh:1:Qm#key-1',
          'did:webvh:Qm:example.com#key-1',
        ),
        isFalse,
      );
    });
  });

  group('did:scid <-> did:webvh', () {
    test('scidToWebvhDid basic', () {
      expect(
        scidToWebvhDid('did:scid:vh:1:acme1234?src=affinidi.com/path'),
        'did:webvh:acme1234:affinidi.com:path',
      );
      expect(
        scidToWebvhDid('did:scid:vh:1:acme1234?src=affinidi.com'),
        'did:webvh:acme1234:affinidi.com',
      );
    });

    test('round trip', () {
      for (final webvh in [
        'did:webvh:acme1234:affinidi.com',
        'did:webvh:acme1234:affinidi.com:a:b',
        'did:webvh:acme1234:localhost%3A8000:path',
      ]) {
        expect(scidToWebvhDid(webvhToScidDidUrl(webvh)!), webvh);
      }
    });

    test('lenient src', () {
      for (final src in [
        'https://localhost:8000/path/',
        'localhost:8000/path',
        'localhost%3A8000/path',
        'http://localhost%3A8000/path',
      ]) {
        expect(
          scidToWebvhDid('did:scid:vh:1:abc?src=$src'),
          'did:webvh:abc:localhost%3A8000:path',
          reason: src,
        );
      }
    });

    test('keeps the fragment', () {
      expect(
        scidToWebvhDid('did:scid:vh:1:abc?src=example.com#key-1'),
        'did:webvh:abc:example.com#key-1',
      );
    });

    test('rejects', () {
      for (final id in [
        'did:webvh:abc:example.com',
        'did:scid:vh:1:abc',
        'did:scid:vh:2:abc?src=example.com',
        'did:scid:ke:1:abc?src=example.com',
        'did:scid:vh:1:?src=example.com',
        'did:scid:vh:1:abc?src=',
        'did:scid:vh:1:abc?src=https:///',
        'did:scid:vh:1:abc?src=example.com&x=1',
        'did:scid:vh:1:abc?src=example.com:notaport',
        'did:scid:vh:1:abc?src=:8000',
        'did:scid:vh:1:abc?src=example.com//path',
        'did:scid:vh:1:a:b?src=example.com',
      ]) {
        expect(scidToWebvhDid(id), isNull, reason: id);
      }
    });

    test("toScidDidDocument gives the did:scid's own document", () {
      const webvh = 'did:webvh:Qm123:example.com:alice';
      const scid = 'did:scid:vh:1:Qm123';
      const scidUrl = 'did:scid:vh:1:Qm123?src=example.com/alice';
      final doc = <String, dynamic>{
        '@context': ['https://www.w3.org/ns/did/v1'],
        'id': webvh,
        'controller': webvh,
        'alsoKnownAs': [scidUrl, 'did:web:example.com:alice'],
        'verificationMethod': [
          {
            'id': '$webvh#key-1',
            'controller': webvh,
            'type': 'Multikey',
            'publicKeyMultibase': 'z6Mk',
          },
          {
            'id': '#key-2',
            'controller': webvh,
            'type': 'Multikey',
            'publicKeyMultibase': 'z6LS',
          },
        ],
        'authentication': ['$webvh#key-1'],
        'keyAgreement': ['#key-2'],
        'service': [
          {
            'id': '$webvh#didcomm',
            'type': 'DIDCommMessaging',
            'serviceEndpoint': 'did:webvh:QmOther:mediator.example.com',
          },
          {
            'id': '$webvh/whois',
            'type': 'LinkedVerifiablePresentation',
            'serviceEndpoint': 'https://example.com/alice/whois.vp',
          },
        ],
      };

      final out = toScidDidDocument(doc);
      final vms = out['verificationMethod'] as List;
      final services = out['service'] as List;
      expect(out['id'], scid);
      expect(out['controller'], scid);
      expect((vms[0] as Map)['id'], '$scid#key-1');
      expect((vms[0] as Map)['controller'], scid);
      expect((vms[1] as Map)['id'], '#key-2');
      expect((out['authentication'] as List)[0], '$scid#key-1');
      expect((out['keyAgreement'] as List)[0], '#key-2');
      expect((services[0] as Map)['id'], '$scid#didcomm');
      expect(
        (services[0] as Map)['serviceEndpoint'],
        'did:webvh:QmOther:mediator.example.com',
      );
      expect((services[1] as Map)['id'], '$webvh/whois');
      expect(out['alsoKnownAs'], [scidUrl, 'did:web:example.com:alice', webvh]);
      expect(doc['id'], webvh, reason: 'the input is not modified');
    });

    test('toScidDidDocument for a log that never listed its did:scid', () {
      final out = toScidDidDocument({
        'id': 'did:webvh:Qm123:example.com',
        'controller': 'did:webvh:Qm123:example.com:alice',
      });
      expect(out['id'], 'did:scid:vh:1:Qm123');
      expect(out['controller'], 'did:webvh:Qm123:example.com:alice');
      expect(out['alsoKnownAs'], [
        'did:scid:vh:1:Qm123?src=example.com',
        'did:webvh:Qm123:example.com',
      ]);
    });

    test('toScidDidDocument refuses a non-webvh document', () {
      expect(
        () => toScidDidDocument({'id': 'did:web:example.com'}),
        throwsA(isA<SsiException>()),
      );
      expect(
        () => toScidDidDocument({'id': 'did:webvh:Qm123'}),
        throwsA(isA<SsiException>()),
      );
      expect(() => toScidDidDocument({}), throwsA(isA<SsiException>()));
    });
  });

  group('source book', () {
    test('bounded, oldest forgotten first', () {
      final book = ScidSourceBook(capacity: 2)
        ..addSource('did:scid:vh:1:A?src=a.example')
        ..addSource('did:scid:vh:1:B?src=b.example')
        ..addSource('did:scid:vh:1:C?src=c.example');
      expect(book.length, 2);
      expect(book.source('did:scid:vh:1:A'), isNull);
      expect(book.source('did:scid:vh:1:C#key-1'), 'c.example');
      expect(book.addSource('did:scid:vh:1:D'), isFalse);
    });

    test('refuses an older version of a log it has verified', () {
      final book = ScidSourceBook()
        ..accept('did:scid:vh:1:A', 'a.example', 2, '2-x');
      expect(
        () => book.accept('did:scid:vh:1:A', 'a.example', 1, '1-y'),
        throwsA(isA<SsiException>()),
      );
      expect(
        () => book.accept('did:scid:vh:1:A', 'a.example', 2, '2-other'),
        throwsA(isA<SsiException>()),
      );
      book.accept('did:scid:vh:1:A', 'a.example', 3, '3-z');
    });
  });

  group('deactivation', () {
    test('tracks the deactivated parameter up to a version', () {
      // Unsigned entries: only the parameters are read, nothing is verified.
      String entry(int n, Map<String, dynamic> params) => jsonEncode({
        'versionId': '$n-Qm$n',
        'versionTime': '2026-01-0${n}T00:00:00Z',
        'parameters': params,
        'state': {
          '@context': ['https://www.w3.org/ns/did/v1'],
          'id': 'did:webvh:Qm:x.example',
        },
        'proof': <Object>[],
      });
      final log = DidWebVhLog.fromJsonLines(
        [
          entry(1, {'method': 'did:webvh:1.0', 'scid': 'Qm'}),
          entry(2, {}),
          entry(3, {'deactivated': true}),
        ].join('\n'),
      );
      expect(isWebvhDeactivatedAt(log, 2), isFalse);
      expect(isWebvhDeactivatedAt(log, 3), isTrue);
    });
  });

  group('resolution', () {
    test('a did:scid DID URL resolves to its own document', () async {
      final resolver = _resolver(_serving(() => _fixture('bob.jsonl')));
      final doc = await resolver.resolveDid(_bobScidUrl);
      expect(doc.id, _bobScidDid);
      final json = doc.toJson();
      expect(json['alsoKnownAs'], containsAll([_bobScidUrl, _bobWebvh]));
      expect(resolver.book.source(_bobScidDid), _bobSrc);
      for (final vm in doc.verificationMethod) {
        expect(vm.id.startsWith(_bobWebvh), isFalse, reason: vm.id);
      }
    });

    test('a bare DID resolves through the source already verified', () async {
      final resolver = _resolver(_serving(() => _fixture('bob.jsonl')));
      await expectLater(
        resolver.resolveDid(_bobScidDid),
        throwsA(isA<SsiException>()),
      );
      await resolver.resolveDid(_bobScidUrl);
      final doc = await resolver.resolveDid('$_bobScidDid#key-1');
      expect(doc.id, _bobScidDid);
    });

    test('an older copy of the log is refused', () async {
      var body = _fixture('bob.jsonl');
      final resolver = _resolver(_serving(() => body));
      await resolver.resolveDid(_bobScidUrl);
      body = body.trim().split('\n').first;
      await expectLater(
        resolver.resolveDid(_bobScidUrl),
        throwsA(_failed(DidScidFailure.rollback)),
      );
    });

    test('a tampered log is refused', () async {
      const scid = 'QmSgM3nsNxmFKyhiaPvk2nMAvjK4hqQwTHnJCKbHohtSq8';
      const src =
          'raw.githubusercontent.com/affinidi/affinidi-ssi-dart/refs/heads/'
          'main/example/dids/didwebvh/bob-tampered';
      final resolver = _resolver(
        MockClient((request) async {
          if (request.url.toString() == 'https://$src/did.jsonl') {
            return http.Response(_fixture('bob-tampered.jsonl'), 200);
          }
          return http.Response('not found', 404);
        }),
      );
      await expectLater(
        resolver.resolveDid('did:scid:vh:1:$scid?src=$src'),
        throwsA(anything),
      );
    });

    test('other methods go to the fallback', () async {
      final resolver = _resolver(_serving(() => ''));
      final doc = await resolver.resolveDid(
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      );
      expect(doc.id, startsWith('did:key:'));
    });

    test('only the vh:1 format is supported', () async {
      final resolver = _resolver(_serving(() => ''));
      await expectLater(
        resolver.resolveDid('did:scid:ke:1:abc?src=example.com'),
        throwsA(isA<SsiException>()),
      );
    });

    test('SsiVidResolver resolves a did:scid VID by default chain', () async {
      final vid = SsiVidResolver(
        didResolver: DidPeer4Resolver(
          fallback: _resolver(_serving(() => _fixture('bob.jsonl'))),
        ),
      );
      final resolved = await vid.resolve(_bobScidUrl);
      expect(resolved.id, _bobScidUrl);
    });
  });

  group('egress guard', () {
    test('a plaintext scheme in src never makes a plaintext request', () async {
      final schemes = <String>[];
      final resolver = _resolver(
        MockClient((request) async {
          schemes.add(request.url.scheme);
          return http.Response(_fixture('bob.jsonl'), 200);
        }),
      );
      await resolver.resolveDid('$_bobScidDid?src=http://$_bobSrc');
      expect(schemes, isNotEmpty);
      expect(schemes, everyElement('https'));
    });

    test('the guard refuses a plaintext URL unless allowInsecure', () async {
      final guard = GuardedHttpClient(
        lookup: _publicDns,
        inner: MockClient((request) async => http.Response('ok', 200)),
      );
      await expectLater(
        guard.get(Uri.parse('http://example.com/did.jsonl')),
        throwsA(_blocked(BlockedReason.scheme)),
      );
    });

    test('loopback, private and local-name sources are refused', () async {
      final resolver = _resolver(_serving(() => _fixture('bob.jsonl')));
      for (final src in [
        '127.0.0.1/bob',
        '10.0.0.7/bob',
        '169.254.169.254/latest',
        '100.100.100.200/x',
        '0.0.0.0/x',
        '127.0.0.1:8443/bob',
      ]) {
        await expectLater(
          resolver.resolveDid('$_bobScidDid?src=$src'),
          throwsA(_blocked(BlockedReason.privateAddress)),
          reason: src,
        );
      }
      for (final src in ['localhost/bob', 'metadata/x', 'nas.local/x']) {
        await expectLater(
          resolver.resolveDid('$_bobScidDid?src=$src'),
          throwsA(_blocked(BlockedReason.privateName)),
          reason: src,
        );
      }
    });

    test(
      'a public name that resolves to a private address is refused',
      () async {
        for (final address in [
          '10.1.2.3',
          '127.0.0.1',
          '::1',
          '169.254.169.254',
        ]) {
          final resolver = _resolver(
            _serving(() => _fixture('bob.jsonl')),
            lookup: (host) async => [
              InternetAddress('93.184.215.14'),
              InternetAddress(address),
            ],
          );
          await expectLater(
            resolver.resolveDid(_bobScidUrl),
            throwsA(_blocked(BlockedReason.privateAddress)),
            reason: address,
          );
        }
      },
    );

    test('a redirect is refused, wherever it points', () async {
      final resolver = _resolver(
        MockClient(
          (request) async => http.Response(
            '',
            302,
            headers: {'location': 'http://169.254.169.254/latest/meta-data'},
          ),
        ),
      );
      await expectLater(
        resolver.resolveDid(_bobScidUrl),
        throwsA(_blocked(BlockedReason.redirect)),
      );
    });

    test('an oversized log is refused', () async {
      final big = 'x' * (defaultMaxArtifactBytes + 1);
      await expectLater(
        _resolver(_serving(() => big)).resolveDid(_bobScidUrl),
        throwsA(_blocked(BlockedReason.tooLarge)),
      );
      // Without a Content-Length, the body is cut off as it streams.
      final streamed = _resolver(
        MockClient.streaming(
          (request, body) async => http.StreamedResponse(
            Stream.fromIterable(List.filled(30, List.filled(10 * 1024, 120))),
            200,
          ),
        ),
      );
      await expectLater(
        streamed.resolveDid(_bobScidUrl),
        throwsA(_blocked(BlockedReason.tooLarge)),
      );
    });

    test('a log with too many entries is refused', () async {
      final resolver = _resolver(
        _serving(() => _fixture('bob.jsonl')),
        maxLogEntries: 1,
      );
      await expectLater(
        resolver.resolveDid(_bobScidUrl),
        throwsA(_failed(DidScidFailure.tooLarge)),
      );
    });

    test('a request that does not answer in time is refused', () async {
      final never = Completer<http.Response>();
      final resolver = _resolver(
        MockClient((request) => never.future),
        timeout: const Duration(milliseconds: 100),
      );
      await expectLater(
        resolver.resolveDid(_bobScidUrl),
        throwsA(_blocked(BlockedReason.timeout)),
      );
    });

    test(
      'the real transport refuses a redirect and an oversized body',
      () async {
        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(() => server.close(force: true));
        server.listen((req) {
          if (req.uri.path == '/redirect') {
            req.response
              ..statusCode = 302
              ..headers.set('location', 'http://10.0.0.1/')
              ..close();
          } else if (req.uri.path == '/big') {
            req.response
              ..write('y' * (defaultMaxArtifactBytes + 10))
              ..close();
          } else {
            req.response
              ..write('ok')
              ..close();
          }
        });
        final base = 'http://127.0.0.1:${server.port}';
        final local = GuardedHttpClient(
          policy: const NetPolicy(allowInsecure: true, allowPrivate: true),
        );
        expect((await local.get(Uri.parse('$base/ok'))).body, 'ok');
        await expectLater(
          local.get(Uri.parse('$base/redirect')),
          throwsA(_blocked(BlockedReason.redirect)),
        );
        await expectLater(
          local.get(Uri.parse('$base/big')),
          throwsA(_blocked(BlockedReason.tooLarge)),
        );
        // Without the opt-in, the loopback server is never dialled.
        await expectLater(
          GuardedHttpClient(
            policy: const NetPolicy(allowInsecure: true),
          ).get(Uri.parse('$base/ok')),
          throwsA(_blocked(BlockedReason.privateAddress)),
        );
      },
    );

    test('isBlockedIp classifies addresses', () {
      for (final ip in [
        '0.0.0.0',
        '127.0.0.1',
        '10.0.0.1',
        '172.16.5.4',
        '192.168.1.1',
        '169.254.169.254',
        '100.100.100.200',
        '224.0.0.1',
        '255.255.255.255',
        '::',
        '::1',
        '::ffff:127.0.0.1',
        '::ffff:7f00:1',
        '64:ff9b::a00:1',
        '2002:a00:1::',
        'fd00:ec2::254',
        'fe80::1',
        'ff02::1',
        '0177.0.0.1',
        'example.com',
      ]) {
        expect(isBlockedIp(ip), isTrue, reason: ip);
      }
      for (final ip in ['93.184.215.14', '8.8.8.8', '2606:4700:4700::1111']) {
        expect(isBlockedIp(ip), isFalse, reason: ip);
      }
    });
  });

  group('verified log binding', () {
    test("a log for another host is refused when it isn't portable", () async {
      // bob's log, served from a host it does not name.
      final resolver = _resolver(
        MockClient(
          (request) async => http.Response(_fixture('bob.jsonl'), 200),
        ),
      );
      await expectLater(
        resolver.resolveDid('$_bobScidDid?src=evil.example/bob'),
        throwsA(_failed(DidScidFailure.mismatch)),
      );
    });

    test('a log for another SCID is refused', () async {
      final resolver = _resolver(
        MockClient(
          (request) async => http.Response(_fixture('bob.jsonl'), 200),
        ),
      );
      await expectLater(
        resolver.resolveDid(
          'did:scid:vh:1:QmSgM3nsNxmFKyhiaPvk2nMAvjK4hqQwTHnJCKbHohtSq8'
          '?src=$_bobSrc',
        ),
        throwsA(isA<SsiException>()),
      );
    });
  });

  group('malformed input', () {
    test('throws the typed resolution exception, never a crash', () async {
      final resolver = _resolver(_serving(() => _fixture('bob.jsonl')));
      for (final did in [
        'did:scid:vh:1:abc?src=example.com:99999999999999999999999999',
        'did:scid:vh:1:abc?src=example.com:notaport',
        'did:scid:vh:1:abc?src=example.com:70000',
        'did:scid:vh:1:?src=example.com',
        'did:scid:vh:1:a:b?src=example.com',
        'did:scid:vh:1:abc?src=',
        'did:scid:vh:1:abc?src=%zz/x',
        'did:scid:vh:1:abc',
      ]) {
        await expectLater(
          resolver.resolveDid(did),
          throwsA(isA<DidScidResolutionException>()),
          reason: did,
        );
      }
    });

    test('a log that is not JSON lines is a typed failure', () async {
      final resolver = _resolver(_serving(() => '{not json\n'));
      await expectLater(
        resolver.resolveDid(_bobScidUrl),
        throwsA(isA<SsiException>()),
      );
    });
  });
}
