/// Trust Spanning Protocol (TSP) Rev 3 for Dart.
///
/// A pure-Dart implementation of the ToIP Trust Spanning Protocol, revision 3
/// (`YTSP-AAC`): binary CESR framing, HPKE-Base and libsodium sealed-box
/// confidentiality, signed-only messages, nested and routed messages,
/// relationship forming control messages with self-addressing digests, and a
/// relationship state machine.
///
/// Two layers are exported:
///
/// * a low-level API over raw keys — [Tsp], [PrivateVid], [PublicVid] and the
///   [TspPayload] types — that performs no I/O and resolves nothing;
/// * an `ssi`-integrated layer — [TspDidManagerExtension], [SsiVidResolver],
///   [DidPeer4Resolver] and [TspEndpoint] — that takes keys from a `DidManager`
///   and resolves peers' VIDs through `ssi`'s DID resolution.
library;

export 'src/crypto/digest.dart' show TspDigest, TspDigestAlgorithm;
export 'src/errors.dart';
export 'src/keys/classical.dart';
export 'src/keys/keys.dart';
export 'src/message/model.dart';
export 'src/message/tsp.dart';
