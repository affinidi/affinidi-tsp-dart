import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';

import '../keys/classical.dart';
import '../keys/keys.dart';

/// Maps DID document verification methods to TSP keys.
///
/// The default [ClassicalKeyMapper] understands Ed25519 and X25519 keys in
/// JWK, Multikey and base58 form. Key-type extensions (such as the
/// post-quantum package) provide further mappers.
abstract interface class TspKeyMapper {
  /// Returns a verification key for [method], or `null` if this mapper does
  /// not understand its key type.
  TspVerificationKey? verificationKey(VerificationMethod method);

  /// Returns an encryption key for [method], or `null` if this mapper does
  /// not understand its key type.
  TspEncryptionKey? encryptionKey(VerificationMethod method);
}

/// Decodes an unsigned LEB128 varint multicodec prefix, returning the codec
/// and the offset of the key bytes, or `null` when malformed.
(int, int)? decodeMulticodec(Uint8List bytes) {
  var value = 0;
  for (var i = 0; i < bytes.length && i < 4; i++) {
    value |= (bytes[i] & 0x7f) << (7 * i);
    if (bytes[i] & 0x80 == 0) return (value, i + 1);
  }
  return null;
}

/// Maps Ed25519 (`authentication`/`assertionMethod`) and X25519
/// (`keyAgreement`) verification methods.
final class ClassicalKeyMapper implements TspKeyMapper {
  /// Creates the mapper.
  const ClassicalKeyMapper();

  static const int _ed25519Codec = 0xed;
  static const int _x25519Codec = 0xec;

  (String, Uint8List)? _okp(VerificationMethod method) {
    try {
      final jwk = method.asJwk().toJson();
      final x = jwk['x'];
      if (jwk['kty'] == 'OKP' && x != null) {
        final padded = x.padRight(x.length + (4 - x.length % 4) % 4, '=');
        return (jwk['crv'] ?? '', base64Url.decode(padded));
      }
    } on Object {
      // Fall through to the multikey form.
    }
    try {
      final multikey = method.asMultiKey();
      final codec = decodeMulticodec(multikey);
      if (codec == null) return null;
      final key = Uint8List.sublistView(multikey, codec.$2);
      return switch (codec.$1) {
        _ed25519Codec => ('Ed25519', key),
        _x25519Codec => ('X25519', key),
        _ => null,
      };
    } on Object {
      return null;
    }
  }

  @override
  TspVerificationKey? verificationKey(VerificationMethod method) {
    final k = _okp(method);
    if (k == null || k.$1 != 'Ed25519' || k.$2.length != 32) return null;
    return Ed25519VerificationKey(k.$2);
  }

  @override
  TspEncryptionKey? encryptionKey(VerificationMethod method) {
    final k = _okp(method);
    if (k == null || k.$1 != 'X25519' || k.$2.length != 32) return null;
    return X25519EncryptionKey(k.$2);
  }
}
