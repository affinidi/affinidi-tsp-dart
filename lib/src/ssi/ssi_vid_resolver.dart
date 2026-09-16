import 'package:ssi/ssi.dart';

import '../errors.dart';
import '../keys/keys.dart';
import '../message/model.dart';
import '../relationship/endpoint.dart';
import 'did_peer4_resolver.dart';
import 'key_mapping.dart';

/// Resolves DID-based VIDs through `ssi`'s DID resolution and maps their
/// verification methods to TSP keys.
///
/// The signing key is the first `authentication` method (then
/// `assertionMethod`) a mapper understands; the encryption key is the first
/// such `keyAgreement` method.
final class SsiVidResolver implements VidResolver {
  /// Creates a resolver.
  ///
  /// [didResolver] defaults to a [DidPeer4Resolver] in front of `ssi`'s
  /// `UniversalDIDResolver` (did:key, did:peer:0/2, did:web, did:webvh).
  SsiVidResolver({
    DidResolver? didResolver,
    List<TspKeyMapper> keyMappers = const [ClassicalKeyMapper()],
  }) : didResolver = didResolver ?? DidPeer4Resolver(),
       keyMappers = List.unmodifiable(keyMappers);

  /// The underlying DID resolver.
  final DidResolver didResolver;

  /// Mappers tried in order for each verification method.
  final List<TspKeyMapper> keyMappers;

  @override
  Future<PublicVid> resolve(String vid) async {
    final DidDocument doc;
    try {
      doc = await didResolver.resolveDid(vid);
    } on Object catch (e) {
      throw TspUnsupportedException('cannot resolve VID $vid', cause: e);
    }
    return publicVidFromDocument(doc, vid: vid, keyMappers: keyMappers);
  }
}

/// Builds a [PublicVid] from a resolved DID [document].
PublicVid publicVidFromDocument(
  DidDocument document, {
  String? vid,
  List<TspKeyMapper> keyMappers = const [ClassicalKeyMapper()],
}) {
  TspVerificationKey? verification;
  for (final vm in [...document.authentication, ...document.assertionMethod]) {
    for (final m in keyMappers) {
      verification ??= m.verificationKey(vm);
    }
    if (verification != null) break;
  }
  if (verification == null) {
    throw TspUnsupportedException(
      '${document.id} has no signing key of a supported type',
    );
  }
  TspEncryptionKey? encryption;
  for (final vm in document.keyAgreement) {
    for (final m in keyMappers) {
      encryption ??= m.encryptionKey(vm);
    }
    if (encryption != null) break;
  }
  return PublicVid(
    id: vid ?? document.id,
    verificationKey: verification,
    encryptionKey: encryption,
  );
}
