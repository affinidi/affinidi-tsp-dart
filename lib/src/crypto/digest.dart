import 'dart:typed_data';

import 'package:crypto/crypto.dart' as dart_crypto;
import 'package:pinenacl/digests.dart' as nacl;

import '../cesr/tsp_codes.dart';
import '../util/bytes.dart';

/// Hash function of a TSP digest, identified on the wire by its CESR code.
enum TspDigestAlgorithm {
  /// SHA2-256, CESR code `I`. The default for HPKE-Base and signed-only.
  sha256('sha2-256'),

  /// Blake2b-256, CESR code `F`. Paired with the libsodium sealed box.
  blake2b256('blake2b-256');

  const TspDigestAlgorithm(this.wireName);

  /// The algorithm name used by the conformance driver protocol.
  final String wireName;

  /// The one-character CESR identifier of this digest's code.
  int get cesrIdentifier => switch (this) {
    TspDigestAlgorithm.sha256 => TspCodes.sha256Digest,
    TspDigestAlgorithm.blake2b256 => TspCodes.blake2b256Digest,
  };

  /// Hashes [data] to 32 bytes.
  Uint8List hash(List<int> data) => switch (this) {
    TspDigestAlgorithm.sha256 => computeSha256(data),
    TspDigestAlgorithm.blake2b256 => computeBlake2b(data, 32),
  };

  /// Looks up an algorithm by its [wireName].
  static TspDigestAlgorithm? byWireName(String name) {
    for (final a in values) {
      if (a.wireName == name) return a;
    }
    return null;
  }
}

/// A 32-byte TSP digest together with its hash function.
final class TspDigest {
  /// Creates a digest. [bytes] must be exactly 32 bytes.
  TspDigest(List<int> bytes, [this.algorithm = TspDigestAlgorithm.sha256])
    : bytes = Uint8List.fromList(bytes) {
    if (this.bytes.length != 32) {
      throw ArgumentError.value(
        bytes.length,
        'bytes',
        'digest must be 32 bytes',
      );
    }
  }

  /// The raw digest value (not its CESR encoding).
  final Uint8List bytes;

  /// The hash function that produced [bytes].
  final TspDigestAlgorithm algorithm;

  @override
  bool operator ==(Object other) =>
      other is TspDigest &&
      other.algorithm == algorithm &&
      constantTimeEquals(other.bytes, bytes);

  @override
  int get hashCode => Object.hash(algorithm, Object.hashAll(bytes));

  @override
  String toString() =>
      'TspDigest(${algorithm.wireName}, ${base64UrlNoPad(bytes)})';
}

/// SHA2-256 of [data].
Uint8List computeSha256(List<int> data) =>
    Uint8List.fromList(dart_crypto.sha256.convert(data).bytes);

/// Unkeyed Blake2b of [data] with a [length]-byte output.
Uint8List computeBlake2b(List<int> data, int length) =>
    nacl.Hash.blake2b(Uint8List.fromList(data), digestSize: length);
