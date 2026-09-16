/// Post-quantum key types for `affinidi_tsp`.
///
/// TSP Rev 3 post-quantum support is not a separate mode: it is HPKE-Base
/// with the MLKEM768-X25519 hybrid KEM (`0x647a`) selected by the receiver's
/// encryption key type, and ML-DSA-65 signatures (`1AAQ`) selected by the
/// sender's signing key type. This package supplies those key types; the
/// wire format lives in `affinidi_tsp`.
///
/// It is a separate package because `pqcrypto` requires Dart 3.10, while
/// `affinidi_tsp` supports Dart 3.8 like the rest of the Affinidi TDK.
library;

export 'src/keys.dart';
export 'src/mlkem768_x25519.dart';
export 'src/pq_key_mapper.dart';
