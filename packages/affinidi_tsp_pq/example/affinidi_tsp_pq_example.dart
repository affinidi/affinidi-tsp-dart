// Two parties with post-quantum keys exchange a confidential TSP message.
//
// Post-quantum support is not a separate mode: the receiver's MLKEM768-X25519
// encryption key selects the hybrid KEM (0x647a) and the sender's ML-DSA-65
// signing key selects the signature algorithm (1AAQ). The wire format is the
// same HPKE-Base scheme the classical keys use.
//
//   dart run example/affinidi_tsp_pq_example.dart

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:affinidi_tsp_pq/affinidi_tsp_pq.dart';
import 'package:pqcrypto/pqcrypto.dart';

Uint8List randomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList([
    for (var i = 0; i < length; i++) random.nextInt(256),
  ]);
}

({PrivateVid private, PublicVid public}) createIdentity(String id) {
  // ML-DSA-65 for signing.
  final (verificationKey, signingKey) = MlDsa.generateKeyPair(
    DilithiumParams.mlDsa65,
  );

  // MLKEM768-X25519 for encryption. The 32-byte seed is the whole private key.
  final seed = MlKem768X25519.deriveSecretKey(randomBytes(32));
  final decryptionKey = MlKem768X25519DecryptionKey.fromSeed(seed);

  return (
    private: PrivateVid(
      id: id,
      signingKey: MlDsa65SigningKey(signingKey),
      decryptionKey: decryptionKey,
    ),
    public: PublicVid(
      id: id,
      verificationKey: MlDsa65VerificationKey(verificationKey),
      encryptionKey: MlKem768X25519EncryptionKey(decryptionKey.publicKey),
    ),
  );
}

Future<void> main() async {
  final alice = createIdentity('did:example:alice');
  final bob = createIdentity('did:example:bob');

  final packed = await Tsp.pack(
    sender: alice.private,
    receiver: bob.public,
    payload: ScsPayload(utf8.encode('hello over post-quantum TSP')),
  );
  stdout.writeln('Sealed ${packed.bytes.length} bytes');

  final opened = await Tsp.open(
    packed.bytes,
    receiver: bob.private,
    sender: alice.public,
  );
  final payload = opened.payload as ScsPayload;
  stdout.writeln('Negotiated KEM: 0x${opened.kem?.id.toRadixString(16)}');
  stdout.writeln('Bob read: ${utf8.decode(payload.data)}');

  // Resolving post-quantum VIDs from real DID documents needs the key mapper,
  // which reads the provisional Multikey codecs the ToIP implementation
  // writes. Pass it wherever a resolver is constructed.
  final resolver = SsiVidResolver(keyMappers: const [PostQuantumKeyMapper()]);
  stdout.writeln(
    'Resolver understands ML-DSA-65 and MLKEM768-X25519: '
    '${resolver.keyMappers.length} mapper(s)',
  );
}
