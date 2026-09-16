import 'dart:typed_data';

/// A signature algorithm a VID's signing key may use.
enum TspSignatureAlgorithm {
  /// Ed25519 (RFC 8032), carried as an indexed `B#` signature.
  ed25519('Ed25519', 32, 64),

  /// ML-DSA-65 (FIPS 204), carried under the provisional code `1AAQ`.
  mlDsa65('MlDsa65', 1952, 3309);

  const TspSignatureAlgorithm(
    this.wireName,
    this.publicKeyLength,
    this.signatureLength,
  );

  /// The key type name used by the conformance driver protocol.
  final String wireName;

  /// Length of a public verification key.
  final int publicKeyLength;

  /// Length of a signature.
  final int signatureLength;
}

/// A private signing key bound to a VID.
///
/// Implementations may keep the key outside the process (a wallet, a KMS); the
/// library only ever asks for signatures.
abstract interface class TspSigningKey {
  /// The algorithm this key signs with.
  TspSignatureAlgorithm get algorithm;

  /// Signs [message].
  Future<Uint8List> sign(Uint8List message);
}

/// A public verification key bound to a VID.
abstract interface class TspVerificationKey {
  /// The algorithm this key verifies.
  TspSignatureAlgorithm get algorithm;

  /// The raw public key.
  Uint8List get bytes;

  /// Returns whether [signature] is valid for [message]. Must return `false`,
  /// not throw, for a malformed signature.
  Future<bool> verify(Uint8List message, Uint8List signature);
}

/// An HPKE KEM TSP can select through a VID's encryption key type.
final class TspKem {
  const TspKem._(this.id, this.wireName, this.encLength, this.publicKeyLength);

  /// DHKEM(X25519, HKDF-SHA256), KEM id `0x0020`.
  static const TspKem x25519 = TspKem._(0x0020, 'X25519', 32, 32);

  /// The MLKEM768-X25519 post-quantum/traditional hybrid, KEM id `0x647a`.
  static const TspKem mlKem768X25519 = TspKem._(
    0x647a,
    'MLKEM768-X25519',
    1120,
    1216,
  );

  /// All KEMs known to the wire layer.
  static const List<TspKem> values = [x25519, mlKem768X25519];

  /// The IANA HPKE KEM identifier.
  final int id;

  /// The key type name used by the conformance driver protocol.
  final String wireName;

  /// Length of the encapsulated key `enc`.
  final int encLength;

  /// Length of a public encryption key.
  final int publicKeyLength;

  @override
  String toString() => 'TspKem($wireName, 0x${id.toRadixString(16)})';
}

/// The result of a KEM encapsulation.
final class KemEncapsulation {
  /// Creates an encapsulation result.
  const KemEncapsulation({required this.sharedSecret, required this.enc});

  /// The KEM shared secret.
  final Uint8List sharedSecret;

  /// The encapsulated key sent to the recipient.
  final Uint8List enc;
}

/// A public encryption key bound to a VID.
abstract interface class TspEncryptionKey {
  /// The KEM this key belongs to.
  TspKem get kem;

  /// The raw public key.
  Uint8List get bytes;

  /// Encapsulates a fresh shared secret to this key.
  ///
  /// [ephemeral] fixes the encapsulation randomness (for X25519, the `ikmE`
  /// fed to DeriveKeyPair) and exists only to reproduce test vectors. Reusing
  /// it across messages destroys confidentiality.
  Future<KemEncapsulation> encapsulate({Uint8List? ephemeral});
}

/// A private decryption key bound to a VID.
abstract interface class TspDecryptionKey {
  /// The KEM this key belongs to.
  TspKem get kem;

  /// The matching public key.
  Uint8List get publicKey;

  /// Recovers the KEM shared secret from [enc]. Throws a `TspException` on
  /// failure.
  Future<Uint8List> decapsulate(Uint8List enc);
}

/// Raw X25519 key agreement, needed by the libsodium sealed box.
///
/// Implemented by X25519 decryption keys; a custody backend that only offers
/// "compute the shared secret with this peer" can implement it without ever
/// exposing its private key.
abstract interface class X25519KeyAgreement {
  /// The agreement key's own public key.
  Uint8List get publicKey;

  /// Returns the raw X25519 output with [peerPublicKey] (no KDF applied).
  Future<Uint8List> diffieHellman(Uint8List peerPublicKey);
}
