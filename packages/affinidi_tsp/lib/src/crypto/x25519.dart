import 'dart:typed_data';

import 'package:pinenacl/tweetnacl.dart';

import '../errors.dart';

/// X25519 (RFC 7748) on TweetNaCl's constant-time scalar multiplication.
abstract final class X25519 {
  /// Key and shared-secret length.
  static const int keyLength = 32;

  /// Computes the public key for [secretKey].
  static Uint8List publicKey(List<int> secretKey) {
    _checkLength(secretKey, 'secret key');
    return TweetNaCl.crypto_scalarmult_base(
      Uint8List(keyLength),
      Uint8List.fromList(secretKey),
    );
  }

  /// Computes `X25519(secretKey, publicKey)`.
  ///
  /// Throws [TspDecryptionException] when the result is all zero, which
  /// happens exactly when [publicKey] is a small-order point (RFC 7748 §6.1,
  /// RFC 9180 §7.1.4).
  static Uint8List diffieHellman(List<int> secretKey, List<int> publicKey) {
    _checkLength(secretKey, 'secret key');
    _checkLength(publicKey, 'public key');
    final out = TweetNaCl.crypto_scalarmult(
      Uint8List(keyLength),
      Uint8List.fromList(secretKey),
      Uint8List.fromList(publicKey),
    );
    checkContributory(out);
    return out;
  }

  /// Throws if [shared] is the all-zero value.
  static void checkContributory(List<int> shared) {
    if (shared.length != keyLength) {
      throw TspDecryptionException(
        'X25519 shared secret is ${shared.length} bytes, expected $keyLength',
      );
    }
    var acc = 0;
    for (final b in shared) {
      acc |= b;
    }
    if (acc == 0) {
      throw const TspDecryptionException(
        'X25519 produced the all-zero shared secret (small-order point)',
      );
    }
  }

  static void _checkLength(List<int> key, String what) {
    if (key.length != keyLength) {
      throw TspInvalidInputException(
        'X25519 $what must be $keyLength bytes, got ${key.length}',
      );
    }
  }
}
