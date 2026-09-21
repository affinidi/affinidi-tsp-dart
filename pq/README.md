# affinidi_tsp_pq

Post-quantum key types for [`affinidi_tsp`](../):

- `MlKem768X25519EncryptionKey` / `MlKem768X25519DecryptionKey` — the
  MLKEM768-X25519 hybrid HPKE KEM (`0x647a`, the X-Wing construction as pinned
  by draft-ietf-hpke-pq). The private key is the 32-byte seed.
- `MlDsa65SigningKey` (4032-byte expanded key, deterministic signing, empty
  context) / `MlDsa65VerificationKey` (1952 bytes).
- `PostQuantumKeyMapper` for `SsiVidResolver`, recognising the provisional
  private-use multicodecs the ToIP reference writes into `did:peer:4`
  documents (`0x300001` ML-DSA-65, `0x300000` MLKEM768-X25519).

TSP Rev 3 post-quantum support is HPKE-Base with the KEM selected by the
receiver's key type and the signature scheme by the sender's, so these keys go
straight into `PrivateVid`/`PublicVid` and the usual `Tsp.pack`/`Tsp.open`.

ML-KEM-768 and ML-DSA-65 come from [`pqcrypto`](https://pub.dev/packages/pqcrypto)
(pure Dart, zero dependencies, KAT-verified against the NIST FIPS 203/204
corpora), which `ssi` 4.x already depends on. It requires Dart 3.10, which is
why this is a separate package from `affinidi_tsp` (Dart 3.8).

Verified by `dart test`: the draft-ietf-hpke-pq MLKEM768-X25519 /
HKDF-SHA256 / ChaCha20Poly1305 vector (DeriveKeyPair, Encap with fixed
randomness, Decap, key schedule, first encryption) and opening the TSP
Appendix A `direct-hpke-base-pq` vector.

Note: `1AAQ` (the ML-DSA-65 signature code) is provisional in the
specification, pending CESR registration.
