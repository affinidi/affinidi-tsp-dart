import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:affinidi_tsp/crypto.dart' show Hpke;
import 'package:affinidi_tsp_pq/affinidi_tsp_pq.dart';
import 'package:test/test.dart';

Uint8List hex(String s) => Uint8List.fromList([
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
]);

Uint8List b64(String s) =>
    base64Url.decode(s.padRight(s.length + (4 - s.length % 4) % 4, '='));

void main() {
  group(
    'draft-ietf-hpke-pq MLKEM768-X25519 / HKDF-SHA256 / ChaCha20Poly1305',
    () {
      final v =
          (jsonDecode(
                    File(
                      'test/fixtures/hpke_pq_mlkem768_x25519.json',
                    ).readAsStringSync(),
                  )
                  as Map<String, Object?>)['vector']!
              as Map<String, Object?>;
      String f(String k) => v[k]! as String;

      test('DeriveKeyPair(ikmR) reproduces skRm and pkRm', () {
        final sk = MlKem768X25519.deriveSecretKey(hex(f('ikmR')));
        expect(sk, hex(f('skRm')));
        expect(MlKem768X25519.publicKey(sk), hex(f('pkRm')));
      });

      test(
        'Encap with ikmE as randomness reproduces enc and shared_secret',
        () {
          final e = MlKem768X25519.encapsulate(
            hex(f('pkRm')),
            randomness: hex(f('ikmE')),
          );
          expect(e.enc, hex(f('enc')));
          expect(e.sharedSecret, hex(f('shared_secret')));
        },
      );

      test('Decap recovers shared_secret', () async {
        final key = MlKem768X25519DecryptionKey.fromSeed(hex(f('skRm')));
        expect(await key.decapsulate(hex(f('enc'))), hex(f('shared_secret')));
      });

      test('key schedule and first encryption', () async {
        // The vector file stores info and pt hex-encoded twice.
        final info = hex(f('info'));
        final ks = Hpke.keySchedule(
          kemId: TspKem.mlKem768X25519.id,
          sharedSecret: hex(f('shared_secret')),
          info: info,
        );
        expect(ks.key, hex(f('key')));
        expect(ks.baseNonce, hex(f('base_nonce')));
        final e0 =
            (v['encryptions']! as List<Object?>).first! as Map<String, Object?>;
        final sealed = await Hpke.sealBase(
          recipient: MlKem768X25519EncryptionKey(hex(f('pkRm'))),
          info: info,
          aad: hex(e0['aad']! as String),
          plaintext: hex(e0['pt']! as String),
          ephemeral: hex(f('ikmE')),
        );
        expect(sealed.enc, hex(f('enc')));
        expect(sealed.ciphertext, hex(e0['ct']! as String));
      });
    },
  );

  group('Appendix A post-quantum vector', () {
    final fixture =
        jsonDecode(File('test/fixtures/spec-vectors.json').readAsStringSync())
            as Map<String, Object?>;
    final ids = (fixture['identifiers']! as Map<String, Object?>)
        .cast<String, Map<String, Object?>>();
    final vector =
        (fixture['vectors']! as Map<String, Object?>)['direct-hpke-base-pq']!
            as Map<String, Object?>;

    PrivateVid priv(String n) => PrivateVid(
      id: ids[n]!['id']! as String,
      signingKey: MlDsa65SigningKey(b64(ids[n]!['skS']! as String)),
      decryptionKey: MlKem768X25519DecryptionKey.fromSeed(
        b64(ids[n]!['skE']! as String),
      ),
    );
    PublicVid pub(String n) => PublicVid(
      id: ids[n]!['id']! as String,
      verificationKey: MlDsa65VerificationKey(b64(ids[n]!['pkS']! as String)),
      encryptionKey: MlKem768X25519EncryptionKey(
        b64(ids[n]!['pkE']! as String),
      ),
    );

    test('published seeds derive the published public keys', () {
      for (final n in ['pq_alice', 'pq_bob']) {
        expect(
          MlKem768X25519.publicKey(b64(ids[n]!['skE']! as String)),
          b64(ids[n]!['pkE']! as String),
        );
      }
    });

    test('direct-hpke-base-pq opens and its payload matches', () async {
      final m = await Tsp.open(
        b64(vector['message']! as String),
        receiver: priv('pq_bob'),
        sender: pub('pq_alice'),
      );
      expect(m.scheme, TspScheme.hpkeBase);
      expect(m.kem, TspKem.mlKem768X25519);
      expect(utf8.decode((m.payload as ScsPayload).data), 'hello world');
    });

    test('classical keys refuse the post-quantum ciphertext', () async {
      final bob = priv('pq_bob');
      await expectLater(
        Tsp.open(
          b64(vector['message']! as String),
          receiver: PrivateVid(
            id: bob.id,
            signingKey: bob.signingKey,
            decryptionKey: X25519DecryptionKey.fromSecret(
              Uint8List(32)..[0] = 9,
            ),
          ),
          sender: pub('pq_alice'),
        ),
        throwsA(isA<TspException>()),
      );
    });

    test(
      'pack is deterministic with fixed randomness and round-trips',
      () async {
        final eph = Uint8List(64)..fillRange(0, 64, 7);
        Future<PackedTspMessage> pack() => Tsp.pack(
          sender: priv('pq_alice'),
          receiver: pub('pq_bob'),
          payload: RfiPayload(nonce: Uint8List(16)),
          options: TspPackOptions(ephemeral: eph),
        );
        final a = await pack();
        final b = await pack();
        expect(a.bytes, b.bytes);
        final m = await Tsp.open(
          a.bytes,
          receiver: priv('pq_bob'),
          sender: pub('pq_alice'),
        );
        expect((m.payload as RfiPayload).digest, a.digest);
      },
    );

    test('SsiVidResolver maps the post-quantum did:peer:4 documents', () async {
      final resolver = SsiVidResolver(
        keyMappers: const [ClassicalKeyMapper(), PostQuantumKeyMapper()],
      );
      final vid = await resolver.resolve(
        ids['pq_alice']!['longForm']! as String,
      );
      expect(vid.verificationKey, isA<MlDsa65VerificationKey>());
      expect(
        vid.verificationKey.bytes,
        b64(ids['pq_alice']!['pkS']! as String),
      );
      expect(vid.encryptionKey!.bytes, b64(ids['pq_alice']!['pkE']! as String));
    });
  });
}
