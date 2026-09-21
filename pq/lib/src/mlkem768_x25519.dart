import 'dart:convert';
import 'dart:typed_data';

import 'package:tsp/crypto.dart';
import 'package:pqcrypto/pqcrypto.dart';

/// The MLKEM768-X25519 hybrid KEM (HPKE KEM id `0x647a`).
///
/// This is the X-Wing construction as pinned by draft-ietf-hpke-pq: a 32-byte
/// private seed expanded with SHAKE256 into an ML-KEM-768 key pair and an
/// X25519 key, and a SHA3-256 combiner over both shared secrets bound to the
/// X25519 ciphertext and public key.
abstract final class MlKem768X25519 {
  /// Private key (seed) length.
  static const int secretKeyLength = 32;

  /// Public key length: ML-KEM-768's 1184 plus X25519's 32.
  static const int publicKeyLength = 1216;

  /// Encapsulated key length: ML-KEM-768's 1088 plus X25519's 32.
  static const int encLength = 1120;

  /// Encapsulation randomness length (32 for ML-KEM, 32 for X25519).
  static const int encapsulationRandomnessLength = 64;

  static const int _mlKemPublicKeyLength = 1184;
  static const int _mlKemCiphertextLength = 1088;

  /// `\.//^\`
  static final Uint8List _label = Uint8List.fromList(r'\.//^\'.codeUnits);

  static final KyberKem _mlKem = PqcKem.kyber768;

  /// Expands a 32-byte [seed] into `(skM, skX, pkM, pkX)`.
  static (Uint8List, Uint8List, Uint8List, Uint8List) expand(Uint8List seed) {
    if (seed.length != secretKeyLength) {
      throw TspInvalidInputException(
        'MLKEM768-X25519 private key must be $secretKeyLength bytes, got ${seed.length}',
      );
    }
    final expanded = Shake256.shake(seed, 96);
    final (pkM, skM) = _mlKem.generateKeyPair(
      Uint8List.sublistView(expanded, 0, 64),
    );
    final skX = Uint8List.fromList(Uint8List.sublistView(expanded, 64, 96));
    return (skM, skX, pkM, X25519.publicKey(skX));
  }

  /// The public key for a private [seed].
  static Uint8List publicKey(Uint8List seed) {
    final (_, _, pkM, pkX) = expand(seed);
    return _cat([pkM, pkX]);
  }

  /// HPKE `DeriveKeyPair(ikm)`: a SHAKE256 labeled derivation of the seed.
  static Uint8List deriveSecretKey(List<int> ikm) {
    final suiteId = Hpke.kemSuiteId(TspKem.mlKem768X25519.id);
    final label = ascii.encode('DeriveKeyPair');
    return Shake256.shake(
      _cat([
        ikm,
        ascii.encode('HPKE-v1'),
        suiteId,
        Hpke.i2osp2(label.length),
        label,
        Hpke.i2osp2(secretKeyLength),
      ]),
      secretKeyLength,
    );
  }

  static Uint8List _combine(
    List<int> ssM,
    List<int> ssX,
    List<int> ctX,
    List<int> pkX,
  ) => sha3256(_cat([ssM, ssX, ctX, pkX, _label]));

  /// Encapsulates to [publicKey]. [randomness], when given, is the 64-byte
  /// encapsulation randomness (test vectors only).
  static KemEncapsulation encapsulate(
    Uint8List publicKey, {
    Uint8List? randomness,
  }) {
    if (publicKey.length != publicKeyLength) {
      throw TspInvalidInputException(
        'MLKEM768-X25519 public key must be $publicKeyLength bytes, got ${publicKey.length}',
      );
    }
    final rnd = randomness ?? secureRandomBytes(encapsulationRandomnessLength);
    if (rnd.length != encapsulationRandomnessLength) {
      throw const TspInvalidInputException(
        'MLKEM768-X25519 encapsulation randomness must be $encapsulationRandomnessLength bytes',
      );
    }
    final pkM = Uint8List.sublistView(publicKey, 0, _mlKemPublicKeyLength);
    final pkX = Uint8List.sublistView(publicKey, _mlKemPublicKeyLength);
    final (Uint8List, Uint8List) mlKem;
    try {
      mlKem = _mlKem.encapsulate(
        Uint8List.fromList(pkM),
        Uint8List.fromList(Uint8List.sublistView(rnd, 0, 32)),
      );
    } on Object catch (e) {
      throw TspInvalidInputException('invalid ML-KEM-768 public key', cause: e);
    }
    final (ctM, ssM) = mlKem;
    final ekX = Uint8List.sublistView(rnd, 32, 64);
    final ctX = X25519.publicKey(ekX);
    final ssX = X25519.diffieHellman(ekX, pkX);
    return KemEncapsulation(
      sharedSecret: _combine(ssM, ssX, ctX, pkX),
      enc: _cat([ctM, ctX]),
    );
  }

  /// Decapsulates [enc] with the private [seed].
  static Uint8List decapsulate(Uint8List seed, Uint8List enc) {
    if (enc.length != encLength) {
      throw TspDecryptionException(
        'MLKEM768-X25519 encapsulated key must be $encLength bytes, got ${enc.length}',
      );
    }
    final (skM, skX, _, pkX) = expand(seed);
    final ctM = Uint8List.fromList(
      Uint8List.sublistView(enc, 0, _mlKemCiphertextLength),
    );
    final ctX = Uint8List.sublistView(enc, _mlKemCiphertextLength);
    final Uint8List ssM;
    try {
      ssM = _mlKem.decapsulate(skM, ctM);
    } on Object catch (e) {
      throw TspDecryptionException('ML-KEM-768 decapsulation failed', cause: e);
    }
    final ssX = X25519.diffieHellman(skX, ctX);
    return _combine(ssM, ssX, ctX, pkX);
  }
}

Uint8List _cat(List<List<int>> parts) {
  final b = BytesBuilder(copy: false);
  for (final p in parts) {
    b.add(p);
  }
  return b.takeBytes();
}
