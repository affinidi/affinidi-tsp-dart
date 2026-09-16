import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:affinidi_tsp/crypto.dart';
import 'package:test/test.dart';

Uint8List hex(String s) => Uint8List.fromList([
  for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16),
]);

void main() {
  final v =
      (jsonDecode(File('test/fixtures/rfc9180_a21_base.json').readAsStringSync())
              as Map<String, Object?>)['vector']!
          as Map<String, Object?>;
  String f(String k) => v[k]! as String;

  group('RFC 9180 A.2.1 DHKEM(X25519)/HKDF-SHA256/ChaCha20Poly1305 Base', () {
    test('DeriveKeyPair reproduces skEm/pkEm and skRm/pkRm', () {
      final (skE, pkE) = DhkemX25519.deriveKeyPair(hex(f('ikmE')));
      expect(skE, hex(f('skEm')));
      expect(pkE, hex(f('pkEm')));
      final (skR, pkR) = DhkemX25519.deriveKeyPair(hex(f('ikmR')));
      expect(skR, hex(f('skRm')));
      expect(pkR, hex(f('pkRm')));
    });

    test('Encap with ikmE reproduces enc and shared_secret', () {
      final e = DhkemX25519.encap(hex(f('pkRm')), ikmE: hex(f('ikmE')));
      expect(e.enc, hex(f('enc')));
      expect(e.sharedSecret, hex(f('shared_secret')));
    });

    test('Decap recovers shared_secret', () async {
      final sk = X25519DecryptionKey.fromSecret(hex(f('skRm')));
      expect(await sk.decapsulate(hex(f('enc'))), hex(f('shared_secret')));
    });

    test('KeySchedule reproduces key, base_nonce, exporter_secret', () {
      final ks = Hpke.keySchedule(
        kemId: 0x0020,
        sharedSecret: hex(f('shared_secret')),
        info: hex(f('info')),
      );
      expect(ks.key, hex(f('key')));
      expect(ks.baseNonce, hex(f('base_nonce')));
      expect(ks.exporterSecret, hex(f('exporter_secret')));
    });

    test('first encryption: SealBase with ikmE and OpenBase', () async {
      final enc0 = (v['encryptions']! as List<Object?>).first! as Map<String, Object?>;
      final sealed = await Hpke.sealBase(
        recipient: X25519EncryptionKey(hex(f('pkRm'))),
        info: hex(f('info')),
        aad: hex(enc0['aad']! as String),
        plaintext: hex(enc0['pt']! as String),
        ephemeral: hex(f('ikmE')),
      );
      expect(sealed.enc, hex(f('enc')));
      expect(sealed.ciphertext, hex(enc0['ct']! as String));
      final opened = await Hpke.openBase(
        recipient: X25519DecryptionKey.fromSecret(hex(f('skRm'))),
        enc: sealed.enc,
        info: hex(f('info')),
        aad: hex(enc0['aad']! as String),
        ciphertext: sealed.ciphertext,
      );
      expect(opened, hex(enc0['pt']! as String));
    });

    test('a wrong aad does not open', () async {
      final enc0 = (v['encryptions']! as List<Object?>).first! as Map<String, Object?>;
      expect(
        () => Hpke.openBase(
          recipient: X25519DecryptionKey.fromSecret(hex(f('skRm'))),
          enc: hex(f('enc')),
          info: hex(f('info')),
          aad: [1, 2, 3],
          ciphertext: hex(enc0['ct']! as String),
        ),
        throwsA(isA<TspDecryptionException>()),
      );
    });

    test('ChaCha20Poly1305 matches every listed sequence-numbered encryption', () async {
      final ks = Hpke.keySchedule(
        kemId: 0x0020,
        sharedSecret: hex(f('shared_secret')),
        info: hex(f('info')),
      );
      for (final raw in v['encryptions']! as List<Object?>) {
        final e = raw! as Map<String, Object?>;
        final ct = await ChaCha20Poly1305.seal(
          key: ks.key,
          nonce: hex(e['nonce']! as String),
          aad: hex(e['aad']! as String),
          plaintext: hex(e['pt']! as String),
        );
        expect(ct, hex(e['ct']! as String));
      }
    });
  });
}
