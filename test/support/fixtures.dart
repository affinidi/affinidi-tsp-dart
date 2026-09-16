import 'dart:typed_data';

import 'package:affinidi_tsp/affinidi_tsp.dart';

/// A throwaway identity with deterministic keys derived from [seed].
({PrivateVid private, PublicVid public}) identity(String id, int seed) {
  final skS = Uint8List(32)..fillRange(0, 32, seed);
  final skE = Uint8List(32)..fillRange(0, 32, seed + 100);
  final signing = Ed25519SigningKey.fromSeed(skS);
  final decryption = X25519DecryptionKey.fromSecret(skE);
  return (
    private: PrivateVid(id: id, signingKey: signing, decryptionKey: decryption),
    public: PublicVid(
      id: id,
      verificationKey: _ed25519Public(skS),
      encryptionKey: X25519EncryptionKey(decryption.publicKey),
    ),
  );
}

final Map<int, Ed25519VerificationKey> _cache = {};

Ed25519VerificationKey _ed25519Public(Uint8List seed) =>
    _cache[seed[0]] ?? (throw StateError('call primeIdentities() first'));

/// Precomputes Ed25519 public keys for the seeds [identity] will use.
Future<void> primeIdentities(Iterable<int> seeds) async {
  for (final s in seeds) {
    _cache[s] = await Ed25519SigningKey.fromSeed(
      Uint8List(32)..fillRange(0, 32, s),
    ).verificationKey();
  }
}

/// Re-signs [message] (whose signature attachment is the trailing Ed25519
/// one) after [mutate] has changed its signable bytes.
Future<Uint8List> resign(
  Uint8List message,
  TspSigningKey key,
  void Function(Uint8List signable) mutate,
) async {
  const attachmentLength = 6 + 66;
  final signable = Uint8List.fromList(
    message.sublist(0, message.length - attachmentLength),
  );
  mutate(signable);
  final sig = await key.sign(signable);
  return Uint8List.fromList([
    ...signable,
    ...message.sublist(message.length - attachmentLength, message.length - 64),
    ...sig,
  ]);
}

/// Returns the index of the first occurrence of [needle] in [haystack].
int indexOfBytes(List<int> haystack, List<int> needle, [int start = 0]) {
  outer:
  for (var i = start; i <= haystack.length - needle.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}
