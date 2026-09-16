import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;

import '../crypto/dhkem_x25519.dart';
import '../crypto/x25519.dart';
import '../errors.dart';
import 'keys.dart';

/// An Ed25519 signing key held in memory as its 32-byte seed.
final class Ed25519SigningKey implements TspSigningKey {
  Ed25519SigningKey._(this._seed);

  /// Creates a key from its 32-byte seed (the RFC 8032 private key).
  factory Ed25519SigningKey.fromSeed(List<int> seed) {
    if (seed.length != 32) {
      throw TspInvalidInputException(
        'Ed25519 private key must be 32 bytes, got ${seed.length}',
      );
    }
    return Ed25519SigningKey._(Uint8List.fromList(seed));
  }

  final Uint8List _seed;
  static final c.Ed25519 _ed25519 = c.Ed25519();
  Future<c.SimpleKeyPair>? _keyPair;

  @override
  TspSignatureAlgorithm get algorithm => TspSignatureAlgorithm.ed25519;

  Future<c.SimpleKeyPair> get _pair =>
      _keyPair ??= _ed25519.newKeyPairFromSeed(_seed);

  /// The matching public key.
  Future<Ed25519VerificationKey> verificationKey() async {
    final pk = await (await _pair).extractPublicKey();
    return Ed25519VerificationKey(pk.bytes);
  }

  @override
  Future<Uint8List> sign(Uint8List message) async {
    final sig = await _ed25519.sign(message, keyPair: await _pair);
    return Uint8List.fromList(sig.bytes);
  }
}

/// A signing key backed by a callback, for custody that never exposes the key
/// (a wallet, `ssi`'s `DidSigner`, a KMS).
final class CallbackSigningKey implements TspSigningKey {
  /// Creates a signing key that delegates to [signer].
  const CallbackSigningKey(this.algorithm, this.signer);

  @override
  final TspSignatureAlgorithm algorithm;

  /// Produces a signature over its argument.
  final Future<Uint8List> Function(Uint8List message) signer;

  @override
  Future<Uint8List> sign(Uint8List message) => signer(message);
}

/// An Ed25519 public verification key.
final class Ed25519VerificationKey implements TspVerificationKey {
  /// Creates a key from its 32 raw bytes.
  Ed25519VerificationKey(List<int> bytes) : bytes = Uint8List.fromList(bytes) {
    if (this.bytes.length != 32) {
      throw TspInvalidInputException(
        'Ed25519 public key must be 32 bytes, got ${this.bytes.length}',
      );
    }
  }

  static final c.Ed25519 _ed25519 = c.Ed25519();

  @override
  final Uint8List bytes;

  @override
  TspSignatureAlgorithm get algorithm => TspSignatureAlgorithm.ed25519;

  @override
  Future<bool> verify(Uint8List message, Uint8List signature) async {
    if (signature.length != 64) return false;
    try {
      return await _ed25519.verify(
        message,
        signature: c.Signature(
          signature,
          publicKey: c.SimplePublicKey(bytes, type: c.KeyPairType.ed25519),
        ),
      );
    } on Object {
      return false;
    }
  }
}

/// An X25519 public encryption key (DHKEM(X25519, HKDF-SHA256)).
final class X25519EncryptionKey implements TspEncryptionKey {
  /// Creates a key from its 32 raw bytes.
  X25519EncryptionKey(List<int> bytes) : bytes = Uint8List.fromList(bytes) {
    if (this.bytes.length != 32) {
      throw TspInvalidInputException(
        'X25519 public key must be 32 bytes, got ${this.bytes.length}',
      );
    }
  }

  @override
  final Uint8List bytes;

  @override
  TspKem get kem => TspKem.x25519;

  @override
  Future<KemEncapsulation> encapsulate({Uint8List? ephemeral}) async {
    if (ephemeral != null && ephemeral.length != 32) {
      throw TspInvalidInputException(
        'X25519 ikmE must be 32 bytes, got ${ephemeral.length}',
      );
    }
    return DhkemX25519.encap(bytes, ikmE: ephemeral);
  }
}

/// An X25519 private key, held in memory or behind a key-agreement callback.
final class X25519DecryptionKey
    implements TspDecryptionKey, X25519KeyAgreement {
  X25519DecryptionKey._(this.publicKey, this._agree);

  /// Creates a key from its 32-byte secret.
  factory X25519DecryptionKey.fromSecret(List<int> secretKey) {
    if (secretKey.length != 32) {
      throw TspInvalidInputException(
        'X25519 private key must be 32 bytes, got ${secretKey.length}',
      );
    }
    final sk = Uint8List.fromList(secretKey);
    return X25519DecryptionKey._(
      X25519.publicKey(sk),
      (peer) async => X25519.diffieHellman(sk, peer),
    );
  }

  /// Creates a key whose Diffie-Hellman is delegated to [agree], for custody
  /// that exposes only "compute the shared secret" (e.g. `ssi`'s
  /// `KeyPair.computeEcdhSecret`). [publicKey] is the matching X25519 key.
  factory X25519DecryptionKey.fromAgreement(
    List<int> publicKey,
    Future<Uint8List> Function(Uint8List peerPublicKey) agree,
  ) {
    if (publicKey.length != 32) {
      throw TspInvalidInputException(
        'X25519 public key must be 32 bytes, got ${publicKey.length}',
      );
    }
    return X25519DecryptionKey._(Uint8List.fromList(publicKey), agree);
  }

  final Future<Uint8List> Function(Uint8List) _agree;

  @override
  final Uint8List publicKey;

  @override
  TspKem get kem => TspKem.x25519;

  @override
  Future<Uint8List> diffieHellman(Uint8List peerPublicKey) async {
    try {
      final shared = await _agree(peerPublicKey);
      X25519.checkContributory(shared);
      return shared;
    } on TspException {
      rethrow;
    } on Object catch (e) {
      throw TspDecryptionException('X25519 key agreement failed', cause: e);
    }
  }

  @override
  Future<Uint8List> decapsulate(Uint8List enc) async {
    if (enc.length != 32) {
      throw TspDecryptionException(
        'X25519 encapsulated key must be 32 bytes, got ${enc.length}',
      );
    }
    final dh = await diffieHellman(enc);
    return DhkemX25519.decapWithDh(dh, enc, publicKey);
  }
}
