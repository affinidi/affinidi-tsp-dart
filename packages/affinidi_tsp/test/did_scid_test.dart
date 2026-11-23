// did:scid:vh:1 — a DID in its own right, verified by a did:webvh log.
//
// The helper and conversion vectors are the ones OpenVTC vti-didcomm-js
// `test/did-scid.test.js` ports from the Rust stack (affinidi_did_common::scid
// and didwebvh-rs did_web.rs). Resolution runs against `ssi`'s signed example
// did:webvh logs (affinidi-ssi-dart, Apache-2.0), served by a mock client.
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
      final resolver = DidScidResolver(
        httpClient: _serving(() => _fixture('bob.jsonl')),
      );
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
      final resolver = DidScidResolver(
        httpClient: _serving(() => _fixture('bob.jsonl')),
      );
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
      final resolver = DidScidResolver(httpClient: _serving(() => body));
      await resolver.resolveDid(_bobScidUrl);
      body = body.trim().split('\n').first;
      await expectLater(
        resolver.resolveDid(_bobScidUrl),
        throwsA(isA<SsiException>()),
      );
    });

    test('a tampered log is refused', () async {
      const scid = 'QmSgM3nsNxmFKyhiaPvk2nMAvjK4hqQwTHnJCKbHohtSq8';
      const src =
          'raw.githubusercontent.com/affinidi/affinidi-ssi-dart/refs/heads/'
          'main/example/dids/didwebvh/bob-tampered';
      final resolver = DidScidResolver(
        httpClient: MockClient((request) async {
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
      final resolver = DidScidResolver(httpClient: _serving(() => ''));
      final doc = await resolver.resolveDid(
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      );
      expect(doc.id, startsWith('did:key:'));
    });

    test('only the vh:1 format is supported', () async {
      final resolver = DidScidResolver(httpClient: _serving(() => ''));
      await expectLater(
        resolver.resolveDid('did:scid:ke:1:abc?src=example.com'),
        throwsA(isA<SsiException>()),
      );
    });

    test('SsiVidResolver resolves a did:scid VID by default chain', () async {
      final vid = SsiVidResolver(
        didResolver: DidPeer4Resolver(
          fallback: DidScidResolver(
            httpClient: _serving(() => _fixture('bob.jsonl')),
          ),
        ),
      );
      final resolved = await vid.resolve(_bobScidUrl);
      expect(resolved.id, _bobScidUrl);
    });
  });
}
