import 'dart:typed_data';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:pqcrypto/pqcrypto.dart';

import 'mlkem768_x25519.dart';

/// An MLKEM768-X25519 public encryption key (1216 bytes).
final class MlKem768X25519EncryptionKey implements TspEncryptionKey {
  /// Creates a key from its raw bytes.
  MlKem768X25519EncryptionKey(List<int> bytes)
    : bytes = Uint8List.fromList(bytes) {
    if (this.bytes.length != MlKem768X25519.publicKeyLength) {
      throw const TspInvalidInputException(
        'MLKEM768-X25519 public key must be ${MlKem768X25519.publicKeyLength} bytes',
      );
    }
  }

  @override
  final Uint8List bytes;

  @override
  TspKem get kem => TspKem.mlKem768X25519;

  @override
  Future<KemEncapsulation> encapsulate({Uint8List? ephemeral}) async =>
      MlKem768X25519.encapsulate(bytes, randomness: ephemeral);
}

/// An MLKEM768-X25519 private key: the 32-byte seed, which is the whole key.
final class MlKem768X25519DecryptionKey implements TspDecryptionKey {
  MlKem768X25519DecryptionKey._(this._seed, this.publicKey);

  /// Creates a key from its 32-byte seed.
  factory MlKem768X25519DecryptionKey.fromSeed(List<int> seed) {
    final s = Uint8List.fromList(seed);
    return MlKem768X25519DecryptionKey._(s, MlKem768X25519.publicKey(s));
  }

  final Uint8List _seed;

  @override
  final Uint8List publicKey;

  @override
  TspKem get kem => TspKem.mlKem768X25519;

  @override
  Future<Uint8List> decapsulate(Uint8List enc) async =>
      MlKem768X25519.decapsulate(_seed, enc);
}

/// An ML-DSA-65 signing key in its 4032-byte expanded form.
///
/// Signs deterministically (FIPS 204 with `rnd = 0`) with an empty context,
/// so TSP signatures are reproducible, as they are with Ed25519.
final class MlDsa65SigningKey implements TspSigningKey {
  /// Creates a key from its 4032-byte expanded encoding.
  MlDsa65SigningKey(List<int> expandedKey)
    : _sk = Uint8List.fromList(expandedKey) {
    if (_sk.length != DilithiumParams.mlDsa65.secretKeyBytes) {
      throw TspInvalidInputException(
        'ML-DSA-65 private key must be ${DilithiumParams.mlDsa65.secretKeyBytes} bytes',
      );
    }
  }

  final Uint8List _sk;

  @override
  TspSignatureAlgorithm get algorithm => TspSignatureAlgorithm.mlDsa65;

  @override
  Future<Uint8List> sign(Uint8List message) async {
    try {
      return MlDsa.signDeterministic(_sk, message, DilithiumParams.mlDsa65);
    } on Object catch (e) {
      throw TspInvalidInputException('ML-DSA-65 signing failed', cause: e);
    }
  }
}

/// An ML-DSA-65 public verification key (1952 bytes).
final class MlDsa65VerificationKey implements TspVerificationKey {
  /// Creates a key from its raw bytes.
  MlDsa65VerificationKey(List<int> bytes) : bytes = Uint8List.fromList(bytes) {
    if (this.bytes.length != TspSignatureAlgorithm.mlDsa65.publicKeyLength) {
      throw TspInvalidInputException(
        'ML-DSA-65 public key must be ${TspSignatureAlgorithm.mlDsa65.publicKeyLength} bytes',
      );
    }
  }

  @override
  final Uint8List bytes;

  @override
  TspSignatureAlgorithm get algorithm => TspSignatureAlgorithm.mlDsa65;

  @override
  Future<bool> verify(Uint8List message, Uint8List signature) async {
    try {
      return MlDsa.verify(bytes, message, signature, DilithiumParams.mlDsa65);
    } on Object {
      return false;
    }
  }
}
