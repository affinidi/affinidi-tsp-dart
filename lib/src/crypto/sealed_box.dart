import 'dart:typed_data';

import 'package:pinenacl/tweetnacl.dart';

import '../errors.dart';
import '../keys/keys.dart';
import '../util/bytes.dart';
import '../util/random.dart';
import 'digest.dart';
import 'x25519.dart';

/// libsodium `crypto_box_seal` / `crypto_box_seal_open` (TSP Rev 3 §8.3).
///
/// ```text
/// nonce  = Blake2b-192(epk ‖ pk)
/// k      = HSalsa20(X25519(esk, pk), 0^16)
/// sealed = epk ‖ Poly1305 tag ‖ XSalsa20(pt)
/// ```
abstract final class SealedBox {
  /// Bytes a sealed box adds to its plaintext.
  static const int overhead = 32 + 16;

  // "expand 32-byte k"
  static final Uint8List _sigma = Uint8List.fromList(
    'expand 32-byte k'.codeUnits,
  );

  static Uint8List _nonce(List<int> epk, List<int> pk) =>
      computeBlake2b(concatBytes([epk, pk]), 24);

  static Uint8List _beforenm(Uint8List shared) {
    final k = Uint8List(32);
    TweetNaCl.crypto_core_hsalsa20(k, Uint8List(16), shared, _sigma);
    return k;
  }

  /// Seals [plaintext] to [recipientPublicKey].
  ///
  /// [ephemeralSecretKey] fixes the ephemeral key (test vectors only; reuse
  /// links messages and breaks confidentiality).
  static Uint8List seal(
    List<int> plaintext,
    List<int> recipientPublicKey, {
    List<int>? ephemeralSecretKey,
  }) {
    final esk = ephemeralSecretKey ?? secureRandomBytes(32);
    final epk = X25519.publicKey(esk);
    final k = _beforenm(X25519.diffieHellman(esk, recipientPublicKey));
    final nonce = _nonce(epk, recipientPublicKey);
    final m = Uint8List(32 + plaintext.length)..setAll(32, plaintext);
    final c = Uint8List(m.length);
    final boxed = TweetNaCl.crypto_box_afternm(c, m, m.length, nonce, k);
    // `boxed` is tag ‖ ciphertext.
    return concatBytes([epk, boxed]);
  }

  /// Opens a sealed box with the recipient's key agreement capability.
  static Future<Uint8List> open(
    Uint8List sealed,
    X25519KeyAgreement recipient,
  ) async {
    if (sealed.length < overhead) {
      throw const TspDecryptionException(
        'sealed box shorter than its overhead',
      );
    }
    final epk = Uint8List.sublistView(sealed, 0, 32);
    final shared = await recipient.diffieHellman(Uint8List.fromList(epk));
    X25519.checkContributory(shared);
    final k = _beforenm(Uint8List.fromList(shared));
    final nonce = _nonce(epk, recipient.publicKey);
    final c = Uint8List(16 + sealed.length - 32)
      ..setAll(16, Uint8List.sublistView(sealed, 32));
    final m = Uint8List(c.length);
    try {
      return TweetNaCl.crypto_box_open_afternm(m, c, c.length, nonce, k);
    } on Object catch (e) {
      throw TspDecryptionException(
        'sealed box authentication failed',
        cause: e,
      );
    }
  }
}
