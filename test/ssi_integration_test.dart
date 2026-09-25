import 'dart:convert';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import 'support/spec_vectors.dart';

Future<DidKeyManager> _didKeyManager(String keyId) async {
  final wallet = PersistentWallet(InMemoryKeyStore());
  final manager = DidKeyManager(wallet: wallet, store: InMemoryDidStore());
  await wallet.generateKey(keyId: keyId, keyType: KeyType.ed25519);
  await manager.addVerificationMethod(keyId);
  return manager;
}

void main() {
  final sv = SpecVectors.load();

  group('DidPeer4Resolver', () {
    test('default pre-authentication policy rejects network-capable VIDs', () {
      final resolver = SsiVidResolver();
      expect(
        resolver.allowsPreAuthenticationResolution('did:web:127.0.0.1'),
        isFalse,
      );
      expect(
        resolver.allowsPreAuthenticationResolution('did:key:z6MkExample'),
        isTrue,
      );
    });

    test(
      'resolves every classical Appendix A long form to its published keys',
      () async {
        final resolver = SsiVidResolver();
        for (final name in [
          'alice',
          'bob',
          'nested_alice',
          'nested_bob',
          'p',
          'q',
        ]) {
          final ident = sv.identifiers[name]!;
          final vid = await resolver.resolve(ident['longForm']! as String);
          expect(
            vid.verificationKey.bytes,
            b64(ident['pkS']! as String),
            reason: name,
          );
          expect(
            vid.encryptionKey!.bytes,
            b64(ident['pkE']! as String),
            reason: name,
          );
          expect(
            DidPeer4Resolver.shortForm(ident['longForm']! as String),
            ident['id'],
          );
        }
      },
    );

    test('a short form resolves once its long form has been seen', () async {
      final peer4 = DidPeer4Resolver();
      final alice = sv.identifiers['alice']!;
      await expectLater(
        peer4.resolveDid(alice['id']! as String),
        throwsA(isA<SsiException>()),
      );
      await peer4.resolveDid(alice['longForm']! as String);
      final doc = await peer4.resolveDid(alice['id']! as String);
      expect(doc.id, alice['id']);
    });

    test(
      'retains no more long forms than its configured cache capacity',
      () async {
        final peer4 = DidPeer4Resolver(maxCachedLongForms: 1);
        final alice = sv.identifiers['alice']!;
        final bob = sv.identifiers['bob']!;
        await peer4.resolveDid(alice['longForm']! as String);
        await peer4.resolveDid(bob['longForm']! as String);
        await expectLater(
          peer4.resolveDid(alice['id']! as String),
          throwsA(isA<SsiException>()),
        );
        expect((await peer4.resolveDid(bob['id']! as String)).id, bob['id']);
      },
    );

    test('a tampered long form is refused', () async {
      final long = sv.identifiers['alice']!['longForm']! as String;
      final tampered =
          '${long.substring(0, long.length - 1)}${long.endsWith('p') ? 'q' : 'p'}';
      await expectLater(
        SsiVidResolver().resolve(tampered),
        throwsA(isA<TspUnsupportedException>()),
      );
    });
  });

  group('DidManager integration', () {
    test(
      'did:key identities pack and open through ssi keys and resolution',
      () async {
        final aliceManager = await _didKeyManager('alice');
        final bobManager = await _didKeyManager('bob');
        final alice = await aliceManager.toTspPrivateVid();
        final bob = await bobManager.toTspPrivateVid();

        final resolver = SsiVidResolver();
        final bobPublic = await resolver.resolve(bob.id);
        final alicePublic = await resolver.resolve(alice.id);
        expect(bobPublic.encryptionKey, isNotNull);

        for (final scheme in TspScheme.values) {
          final packed = await Tsp.pack(
            sender: alice,
            receiver: bobPublic,
            payload: ScsPayload(utf8.encode('hi via ${scheme.wireName}')),
            scheme: scheme,
          );
          final opened = await Tsp.open(
            packed.bytes,
            receiver: bob,
            sender: alicePublic,
          );
          expect(
            utf8.decode((opened.payload as ScsPayload).data),
            'hi via ${scheme.wireName}',
          );
        }
      },
    );

    test('the manager public VID matches what resolution returns', () async {
      final manager = await _didKeyManager('carol');
      final fromManager = await manager.toTspPublicVid();
      final resolved = await SsiVidResolver().resolve(fromManager.id);
      expect(resolved.verificationKey.bytes, fromManager.verificationKey.bytes);
      expect(resolved.encryptionKey!.bytes, fromManager.encryptionKey!.bytes);
    });

    test('endpoints built from DidManagers form a relationship', () async {
      final aManager = await _didKeyManager('a');
      final bManager = await _didKeyManager('b');
      final a = await aManager.toTspPrivateVid();
      final b = await bManager.toTspPrivateVid();
      final resolver = SsiVidResolver();
      final ea = TspEndpoint(identities: [a], resolver: resolver);
      final eb = TspEndpoint(identities: [b], resolver: resolver);

      final invite = await ea.invite(from: a.id, to: b.id);
      expect(
        (await eb.receive(invite.bytes)).kind,
        TspEndpointEventKind.invite,
      );
      final accept = await eb.accept(from: b.id, to: a.id);
      expect(
        (await ea.receive(accept.bytes)).kind,
        TspEndpointEventKind.accept,
      );
      final msg = await ea.send(
        from: a.id,
        to: b.id,
        data: utf8.encode('hello'),
      );
      final ev = await eb.receive(msg.bytes);
      expect(utf8.decode(ev.data!), 'hello');
    });
  });
}
