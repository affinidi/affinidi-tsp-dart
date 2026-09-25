# Affinidi TSP for Dart

A pure-Dart implementation of the [Trust Spanning Protocol](https://github.com/trustoverip/tswg-tsp-specification)
(TSP), **revision 3** (`YTSP-AAC`), shaped to sit in the Affinidi TDK the way
the [`didcomm`](https://pub.dev/packages/didcomm) package does: a low-level
protocol API over raw keys, plus an [`ssi`](https://pub.dev/packages/ssi)
integration so a `DidManager` can pack and open messages and peers' VIDs are
resolved through `ssi`'s DID resolution.

No Flutter, no FFI, no platform crypto: it runs on the Dart VM, in the browser
and on mobile.

> **Status: pre-release (0.1.0), not independently security-audited.** Checked
> against the specification's Appendix A vectors and, for interoperability, against
> the ToIP reference and other implementations by
> [tsp-conformance](https://github.com/OpenVTC/tsp-conformance).

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [With ssi (DidManager and DID resolution)](#with-ssi-didmanager-and-did-resolution)
  - [Relationships with TspEndpoint](#relationships-with-tspendpoint)
  - [Low-level API over raw keys](#low-level-api-over-raw-keys)
  - [Post-quantum](#post-quantum)
- [Errors](#errors)
- [Conformance](#conformance)
- [Specification notes](#specification-notes)
- [Security considerations](#security-considerations)
- [Integrating into the Affinidi TDK](#integrating-into-the-affinidi-tdk)

## Features

| Area | Support |
|---|---|
| Framing | Binary CESR (qb2): short and long count codes (`-X##`, `--X#####`), variable-size codes with lead pad 0/1/2 (`4B`…`9AAB`), long VIDs, canonical-encoding checks |
| Envelope | `-E` group over version, sender, receiver (NULL VID `4BAA` supported), indexed Ed25519 (`B#`) and ML-DSA-65 (`1AAQ`) signature attachments |
| Payloads | `XSCS`, `XCTL`, `XPAD`, `XRFI` (incl. `Reply_Path` and `Referral_Field`), `XRFA`, `XRFD`, `XHOP` (nested and routed); padding field; ESSR payload sender (NULL or present) |
| Digests | Self-addressing TSP digests, SHA2-256 (`I`) and Blake2b-256 (`F`), computed on pack and verified on open |
| Confidentiality | HPKE-Base (RFC 9180, DHKEM(X25519)/HKDF-SHA256/ChaCha20Poly1305), libsodium sealed box, signed-only |
| Post-quantum | MLKEM768-X25519 hybrid KEM and ML-DSA-65 via the companion package [`affinidi_tsp_pq`](pq/) |
| Relationships | State machine (`none` / `invite-sent` / `invite-received` / `bidirectional`), invite race tie-break by lower digest, decline/cancel, application messages refused without a relationship |
| ssi | `DidManager` → `PrivateVid` (keys stay in the wallet), `SsiVidResolver` (did:key, did:peer, did:web, did:webvh via `ssi`), `DidPeer4Resolver` |
| Hardening | Size limits checked before allocation, trailing bytes rejected, unknown MAJOR version rejected, only typed `TspException`s on untrusted input |

Cryptographic primitives come from packages already in the `ssi`/`didcomm`
dependency graph: `crypto` (SHA-256, HMAC), `cryptography` (Ed25519,
ChaCha20-Poly1305) and `pinenacl` (X25519, Blake2b, HSalsa20/XSalsa20-Poly1305).
HKDF and the HPKE key schedule are implemented here and checked against the
RFC 9180 test vectors.

## Installation

```yaml
dependencies:
  affinidi_tsp: ^0.1.0
  ssi: ^3.9.0
```

Requires Dart 3.8 or later.

## Usage

### With ssi (DidManager and DID resolution)

```dart
import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:ssi/ssi.dart';

final wallet = PersistentWallet(InMemoryKeyStore());
final didManager = DidKeyManager(wallet: wallet, store: InMemoryDidStore());
await wallet.generateKey(keyId: 'key-1', keyType: KeyType.ed25519);
await didManager.addVerificationMethod('key-1');

// Signing uses the first Ed25519 authentication method through the manager's
// DidSigner; decryption uses the X25519 keyAgreement method through
// KeyPair.computeEcdhSecret. No private key leaves the wallet.
final me = await didManager.toTspPrivateVid();

// Resolve a peer: Ed25519 authentication/assertionMethod → verification key,
// X25519 keyAgreement → encryption key.
final resolver = SsiVidResolver();
final peer = await resolver.resolve('did:peer:4zQm...:z2...');

final packed = await Tsp.pack(
  sender: me,
  receiver: peer,
  payload: ScsPayload(utf8.encode('hello')),
);
```

`SsiVidResolver` accepts any `ssi` `DidResolver` and a list of
`TspKeyMapper`s, so custom DID methods and key types plug in without changes
here. Its default pre-authentication policy permits only `did:key` and
`did:peer:4`, which resolve without network access. To receive messages from a
network-capable DID method such as `did:web`, provide a `VidResolutionPolicy`
and a resolver that validates resolved IP addresses and every redirect against
your egress policy. Any custom resolver used with `TspEndpoint.receive` must
implement `PreAuthenticationVidResolver`; unmarked resolvers are denied before
they can resolve an unauthenticated sender VID.

### Relationships with TspEndpoint

TSP §7.2.2 says an endpoint SHOULD drop an application message from a VID it
has no relationship with, so real applications form one first:

```dart
final alice = TspEndpoint(identities: [aliceVid], resolver: resolver);
final bob = TspEndpoint(identities: [bobVid], resolver: resolver);

final invite = await alice.invite(from: aliceVid.id, to: bobVid.id);   // XRFI
await bob.receive(invite.bytes);                                        // invite-received
final accept = await bob.accept(from: bobVid.id, to: aliceVid.id);     // XRFA
await alice.receive(accept.bytes);                                      // bidirectional

final msg = await alice.send(from: aliceVid.id, to: bobVid.id, data: utf8.encode('hi'));
final event = await bob.receive(msg.bytes); // event.kind == TspEndpointEventKind.message
```

`receive` verifies, decrypts and applies the message to the relationship
state, refusing with `TspRelationshipException` what the state forbids (data
before a relationship, an accept for an unknown invite, a losing crossing
invite). State lives in a `RelationshipStore`; `InMemoryRelationshipStore` is
provided and a persistent store is a small interface to implement. See
[`example/affinidi_tsp_example.dart`](example/affinidi_tsp_example.dart).

### Low-level API over raw keys

```dart
final alice = PrivateVid(
  id: 'did:example:alice',
  signingKey: Ed25519SigningKey.fromSeed(aliceSeed),
  decryptionKey: X25519DecryptionKey.fromSecret(aliceX25519Secret),
);
final bob = PublicVid(
  id: 'did:example:bob',
  verificationKey: Ed25519VerificationKey(bobEd25519Public),
  encryptionKey: X25519EncryptionKey(bobX25519Public),
);

final invite = await Tsp.pack(
  sender: alice,
  receiver: bob,
  payload: RfiPayload(replyPath: const []),
  scheme: TspScheme.hpkeBase,          // or sealedBox, signedOnly
  options: const TspPackOptions(payloadSender: PayloadSenderMode.present),
);
invite.digest; // the invite's self-addressing digest

final opened = await Tsp.open(invite.bytes, receiver: bobPrivate, sender: alicePublic);
opened.payload;        // RfiPayload with its digest verified
opened.payloadSender;  // ESSR sender, checked against the envelope
Tsp.peek(invite.bytes); // what an intermediary sees, no keys
```

Keys are interfaces (`TspSigningKey`, `TspVerificationKey`,
`TspEncryptionKey`, `TspDecryptionKey`), so custody that never exposes a
private key — a KMS, a wallet, a secure element with X25519 — plugs in via
`CallbackSigningKey` and `X25519DecryptionKey.fromAgreement`.

Payload types: `ScsPayload` (application bytes, carried as exactly one Bytes primitive —
[spec issue #77](https://github.com/trustoverip/tswg-tsp-specification/issues/77)), `CtlPayload`, `PadPayload`, `RfiPayload` (with optional
`Referral` / `Referral.signWith` and `Tsp.verifyReferral`), `RfaPayload`,
`RfdPayload`, `HopPayload` (nested when `hops` is empty, routed otherwise; the
inner message is carried unopened).

`Tsp.packForTestVector` fixes the HPKE `ikmE` or sealed-box ephemeral secret
so the specification's test vectors reproduce byte for byte. It is marked
test-only because reusing its randomness in production breaks confidentiality
and integrity.

### Post-quantum

```dart
import 'package:affinidi_tsp_pq/affinidi_tsp_pq.dart';

final pqAlice = PrivateVid(
  id: aliceId,
  signingKey: MlDsa65SigningKey(expandedSecretKey4032),
  decryptionKey: MlKem768X25519DecryptionKey.fromSeed(seed32),
);
```

Post-quantum TSP is HPKE-Base with the KEM chosen by the receiver's key type,
so the same `Tsp.pack`/`Tsp.open` calls apply. It lives in a separate package
because its ML-KEM/ML-DSA dependency, `pqcrypto`, requires Dart 3.10.

## Errors

Every failure is a subclass of the sealed `TspException`, carrying a
`TspErrorCode`: `malformed`, `version`, `signature`, `decrypt`, `sender`,
`receiver`, `digest`, `relationship`, `unsupported`, `invalidInput`. Opening
untrusted bytes never throws anything else.

## Conformance

- **Appendix A**: every vector opens with its payload fields and digests
  checked; all nine classical vectors (`direct-sealed-box`, `direct-hpke-base`,
  `direct-signed-only`, `control-rfi-direct`, `control-rfa-direct`,
  `control-rfd`, `control-rfi-sealed-box`, `nested-direct`, `routed`) re-pack
  **byte-exact** from their published ephemeral material;
  `direct-hpke-base-pq` opens (the specification publishes no ephemeral
  material for it).
- **RFC 9180** A.2.1 (DHKEM(X25519), HKDF-SHA256, ChaCha20Poly1305, Base).
- **draft-ietf-hpke-pq** MLKEM768-X25519 vector (in `affinidi_tsp_pq`).
- A conformance driver lives in `tsp-conformance/drivers/dart`.

```sh
dart analyze && dart test
(cd pq && dart test)
```

## Specification notes

Choices made where Rev 3 leaves room, consistent with `affinidi-tsp` (Rust)
and the ToIP reference:

- **Version.** Packs `YTSP-AAC` (0.2, MAJOR.MINOR). Opens any 0.x with MINOR ≥
  2, so the reference's `YTSP-ABA` is accepted; MAJOR ≠ 0 or MINOR < 2 is a
  version error.
- **Digest algorithm.** Packs SHA2-256 under HPKE-Base and signed-only,
  Blake2b-256 under the sealed box. On open the hash is taken from each
  digest's own CESR code, as §7.2.1 states.
- **Referral digest input.** The SAID over an invite with a referral includes
  `VID_new` as a bare VID field and excludes the `-J` group header and
  `Signature_new` (no vector covers this case).
- **Nested messages must be confidential** (§4.1): signed-only `XHOP` is
  refused on pack and open.
- **Cancel digest.** `TspEndpoint.cancel` names the invite's `Digest`, which
  both sides record; on receipt either `Digest` or `Reply_Digest` is
  recognised (§7.3).
- **Hop limits.** Up to 64 VIDs in a hop list or reply path by default
  (`TspLimits.maxHops`); the spec sets no limit. 64 matches affinidi-tsp,
  tsp-js and affinidi-tsp-go.
- **Message limit.** Inbound messages default to 4 MiB
  (`TspLimits.maxMessageLength`); applications with larger trusted payloads
  must opt in with an explicit limit.
- **Referral signatures.** A decoded referral retains the algorithm declared
  by its CESR signature primitive. Supplying a precomputed referral signature
  requires its algorithm explicitly.
- **Signature attachments.** Rev 3 permits multiple signatures, but this
  implementation deliberately accepts exactly one index-0 signature because a
  VID maps to one signing key here. This prevents unsigned attachment
  malleability; multi-key VID support requires an explicit verification model.
- **Application body.** `XSCS`/`XCTL` data is exactly one Bytes primitive
  inside `-A##`; any other body is refused
  ([tswg-tsp-specification#77](https://github.com/trustoverip/tswg-tsp-specification/issues/77)).

## Security considerations

- The signature is verified before decryption; the HPKE aad is rebuilt from
  the received envelope bytes, so a ciphertext moved under another envelope
  does not open.
- A decoded referral's `Signature_new` is **not** verified by `open` (it needs
  the introduced VID's key): call `Tsp.verifyReferral` before acting on it.
- X25519 rejects all-zero shared secrets (small-order points) everywhere,
  including behind custody callbacks.
- Ed25519 verification rejects non-canonical `S` values.
- Signature attachments are restricted to one index-0 signature; see the
  intentional compatibility restriction under Specification notes.
- TSP does not provide replay protection, ordering or freshness for application
  payloads. Applications must supply the nonce, timestamp, sequence or stable
  message identifier appropriate to their protocol semantics.

## Integrating into the Affinidi TDK

See [`doc/tdk-integration.md`](doc/tdk-integration.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
