import 'dart:typed_data';

import '../keys/keys.dart';
import '../util/bytes.dart';
import '../util/random.dart';
import 'hpke.dart';
import 'x25519.dart';

/// DHKEM(X25519, HKDF-SHA256), RFC 9180 §4.1 and §7.1.
abstract final class DhkemX25519 {
  static final Uint8List _suiteId = Hpke.kemSuiteId(TspKem.x25519.id);

  /// RFC 9180 §7.1.3 `DeriveKeyPair(ikm)`, returning `(skX, pkX)`.
  static (Uint8List, Uint8List) deriveKeyPair(List<int> ikm) {
    final prk = Hpke.labeledExtract(_suiteId, const [], 'dkp_prk', ikm);
    final sk = Hpke.labeledExpand(_suiteId, prk, 'sk', const [], 32);
    return (sk, X25519.publicKey(sk));
  }

  /// `ExtractAndExpand(dh, kem_context)`.
  static Uint8List extractAndExpand(List<int> dh, List<int> kemContext) {
    final prk = Hpke.labeledExtract(_suiteId, const [], 'eae_prk', dh);
    return Hpke.labeledExpand(_suiteId, prk, 'shared_secret', kemContext, 32);
  }

  /// `Encap(pkR)`. [ikmE], when given, is fed to [deriveKeyPair] to fix the
  /// ephemeral key (test vectors only).
  static KemEncapsulation encap(List<int> pkR, {List<int>? ikmE}) {
    final (skE, pkE) = deriveKeyPair(ikmE ?? secureRandomBytes(32));
    final dh = X25519.diffieHellman(skE, pkR);
    return KemEncapsulation(
      sharedSecret: extractAndExpand(dh, concatBytes([pkE, pkR])),
      enc: pkE,
    );
  }

  /// `Decap(enc, skR)` given the raw DH output and the recipient public key.
  static Uint8List decapWithDh(List<int> dh, List<int> enc, List<int> pkR) {
    X25519.checkContributory(dh);
    return extractAndExpand(dh, concatBytes([enc, pkR]));
  }
}
