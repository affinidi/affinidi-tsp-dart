import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;

import '../errors.dart';

/// ChaCha20-Poly1305 (RFC 8439) single-shot AEAD over `package:cryptography`.
abstract final class ChaCha20Poly1305 {
  /// Key length.
  static const int keyLength = 32;

  /// Nonce length.
  static const int nonceLength = 12;

  /// Tag length.
  static const int tagLength = 16;

  static final c.Cipher _cipher = c.Chacha20.poly1305Aead();

  /// Encrypts [plaintext], returning `ciphertext ‖ tag`.
  static Future<Uint8List> seal({
    required List<int> key,
    required List<int> nonce,
    required List<int> aad,
    required List<int> plaintext,
  }) async {
    final box = await _cipher.encrypt(
      plaintext,
      secretKey: c.SecretKey(List<int>.of(key)),
      nonce: nonce,
      aad: aad,
    );
    final out = Uint8List(box.cipherText.length + tagLength)
      ..setAll(0, box.cipherText)
      ..setAll(box.cipherText.length, box.mac.bytes);
    return out;
  }

  /// Decrypts `ciphertext ‖ tag`. Throws [TspDecryptionException] when
  /// authentication fails.
  static Future<Uint8List> open({
    required List<int> key,
    required List<int> nonce,
    required List<int> aad,
    required List<int> ciphertextAndTag,
  }) async {
    if (ciphertextAndTag.length < tagLength) {
      throw const TspDecryptionException('AEAD ciphertext shorter than its tag');
    }
    final split = ciphertextAndTag.length - tagLength;
    try {
      final clear = await _cipher.decrypt(
        c.SecretBox(
          ciphertextAndTag.sublist(0, split),
          nonce: nonce,
          mac: c.Mac(ciphertextAndTag.sublist(split)),
        ),
        secretKey: c.SecretKey(List<int>.of(key)),
        aad: aad,
      );
      return Uint8List.fromList(clear);
    } on c.SecretBoxAuthenticationError catch (e) {
      throw TspDecryptionException('AEAD authentication failed', cause: e);
    }
  }
}
