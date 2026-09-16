import 'dart:typed_data';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:ssi/ssi.dart';

import 'keys.dart';

/// Maps post-quantum Multikey verification methods to TSP keys.
///
/// No multicodec is registered yet for either key type. The codes used are
/// the private-use values the ToIP reference implementation writes into
/// `did:peer:4` documents, as seen in the Rev 3 Appendix A identifiers:
/// `0x300001` for an ML-DSA-65 public key and `0x300000` for an
/// MLKEM768-X25519 public key. They are provisional.
final class PostQuantumKeyMapper implements TspKeyMapper {
  /// Creates the mapper.
  const PostQuantumKeyMapper();

  /// Provisional multicodec of an ML-DSA-65 public key.
  static const int mlDsa65Codec = 0x300001;

  /// Provisional multicodec of an MLKEM768-X25519 public key.
  static const int mlKem768X25519Codec = 0x300000;

  Uint8List? _key(VerificationMethod method, int codec, int length) {
    try {
      final multikey = method.asMultiKey();
      final decoded = decodeMulticodec(multikey);
      if (decoded == null || decoded.$1 != codec) return null;
      final key = Uint8List.sublistView(multikey, decoded.$2);
      return key.length == length ? key : null;
    } on Object {
      return null;
    }
  }

  @override
  TspVerificationKey? verificationKey(VerificationMethod method) {
    final k = _key(method, mlDsa65Codec, TspSignatureAlgorithm.mlDsa65.publicKeyLength);
    return k == null ? null : MlDsa65VerificationKey(k);
  }

  @override
  TspEncryptionKey? encryptionKey(VerificationMethod method) {
    final k = _key(method, mlKem768X25519Codec, TspKem.mlKem768X25519.publicKeyLength);
    return k == null ? null : MlKem768X25519EncryptionKey(k);
  }
}
