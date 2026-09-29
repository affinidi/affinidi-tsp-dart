import 'package:ssi/ssi.dart';

import '../errors.dart';
import '../keys/classical.dart';
import '../keys/keys.dart';
import '../message/model.dart';
import 'key_mapping.dart';
import 'ssi_vid_resolver.dart';

/// Builds TSP identities from an `ssi` [DidManager], mirroring how the
/// `didcomm` package takes its signers and key agreement keys.
extension TspDidManagerExtension on DidManager {
  /// Returns a [PrivateVid] whose keys stay in the manager's wallet.
  ///
  /// Signing uses [signingMethodId] (default: the first `authentication`
  /// method, else the first `assertionMethod`), which must be Ed25519.
  /// Decryption uses [keyAgreementMethodId] (default: the first
  /// `keyAgreement` method), which must be X25519; for an `ssi` Ed25519 key
  /// this is the derived X25519 key, and Diffie-Hellman runs through
  /// `KeyPair.computeEcdhSecret`.
  Future<PrivateVid> toTspPrivateVid({
    String? signingMethodId,
    String? keyAgreementMethodId,
  }) async {
    final doc = await getDidDocument();
    final signId =
        signingMethodId ??
        (authentication.isNotEmpty
            ? authentication.first
            : assertionMethod.isNotEmpty
            ? assertionMethod.first
            : throw TspInvalidInputException(
                '${doc.id} has no signing method',
              ));
    final signer = await getSigner(signId);
    final signKey = await getKey(signId);
    if (signKey.publicKey.type != KeyType.ed25519) {
      throw TspUnsupportedException(
        'TSP signing requires Ed25519; $signId is ${signKey.publicKey.type.name}',
      );
    }

    TspDecryptionKey? decryption;
    final kaId =
        keyAgreementMethodId ??
        (keyAgreement.isNotEmpty ? keyAgreement.first : null);
    if (kaId != null) {
      final vm = _findMethod(doc.keyAgreement, kaId, doc.id);
      final pk = vm == null
          ? null
          : const ClassicalKeyMapper().encryptionKey(vm);
      if (pk == null) {
        throw TspUnsupportedException(
          '$kaId is not an X25519 key agreement key',
        );
      }
      final pair = await getKey(kaId);
      decryption = X25519DecryptionKey.fromAgreement(
        pk.bytes,
        pair.computeEcdhSecret,
      );
    }

    return PrivateVid(
      id: doc.id,
      signingKey: CallbackSigningKey(
        TspSignatureAlgorithm.ed25519,
        signer.sign,
      ),
      decryptionKey: decryption,
    );
  }

  /// Returns the manager's own [PublicVid], as a peer would resolve it.
  Future<PublicVid> toTspPublicVid({
    List<TspKeyMapper> keyMappers = const [ClassicalKeyMapper()],
  }) async =>
      publicVidFromDocument(await getDidDocument(), keyMappers: keyMappers);
}

VerificationMethod? _findMethod(
  List<VerificationMethod> methods,
  String id,
  String did,
) {
  String norm(String s) => s.startsWith('#') ? '$did$s' : s;
  for (final m in methods) {
    if (norm(m.id) == norm(id)) return m;
  }
  // `ssi`'s DidKeyManager records a derived X25519 key agreement method under
  // a DID built from the X25519 key rather than the document's DID, so fall
  // back to matching the fragment, which is the key's multibase either way.
  final fragment = id.split('#').last;
  for (final m in methods) {
    if (m.id.split('#').last == fragment) return m;
  }
  return null;
}
