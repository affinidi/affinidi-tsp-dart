# Integrating TSP into the Affinidi TDK for Dart

**Headline:** keep the protocol in a standalone library, exactly as DIDComm is
split today. `tsp` (this repository) plays the role of `didcomm`; the
TDK gains one package, `packages/tsp/tsp_client` →
**`affinidi_tdk_tsp_client`**, that plays the role of
`affinidi_tdk_didcomm_mediator_client`: it owns transport, mediator
authentication and pickup, persistent relationship state, and a `DidManager`-
first convenience API. Post-quantum stays opt-in through `affinidi_tsp_pq`.
Nothing in the existing DIDComm packages changes.

Read this with the DIDComm layout in mind:

| DIDComm today | TSP proposal |
|---|---|
| `didcomm` (standalone repo, pub.dev) — message model, JWE/JWS, key selection from `ssi` | `affinidi_tsp` (standalone repo, pub.dev) — CESR, HPKE/sealed box, payloads, SAIDs, relationship state machine, `ssi` integration |
| — | `affinidi_tsp_pq` (same repo, pub.dev) — ML-KEM-768/X25519 and ML-DSA-65 key types |
| `packages/didcomm/didcomm_mediator_client` → `affinidi_tdk_didcomm_mediator_client` | `packages/tsp/tsp_client` → `affinidi_tdk_tsp_client` |
| `packages/didcomm/vdsp`, `vdip` (protocols over DIDComm) | future protocols over TSP use `XSCS`/`XCTL` payloads through `affinidi_tdk_tsp_client` |

## 1. What goes where

### In the library (`affinidi_tsp`) — already done

Everything that is protocol and has no I/O:

- Wire format: binary CESR, envelope, all Rev 3 payload types, signature
  attachments, size limits, strict parsing.
- Cryptography: HPKE-Base (RFC 9180), libsodium sealed box, Ed25519, digests.
- Key abstractions: `TspSigningKey`, `TspVerificationKey`, `TspEncryptionKey`,
  `TspDecryptionKey`, `X25519KeyAgreement` — interfaces, so custody stays
  wherever the app keeps it.
- `Tsp.pack` / `Tsp.open` / `Tsp.peek` / `Tsp.looksLikeTsp`.
- Relationships: `RelationshipState`, `transitionRelationship`,
  `RelationshipStore` (interface + in-memory), `TspEndpoint`.
- `ssi` integration: `DidManager.toTspPrivateVid()` /
  `toTspPublicVid()`, `SsiVidResolver` (any `ssi` `DidResolver`, pluggable
  `TspKeyMapper`s), `DidPeer4Resolver`. The default inbound policy permits
  only local `did:key` and `did:peer:4` resolution before authentication;
  transport clients enabling `did:web` must use a resolver with an egress
  policy that validates DNS results and redirects.

It depends only on `ssi`, `crypto`, `cryptography` and `pinenacl`, all already
in the TDK's dependency graph through `ssi` (`pinenacl` via `ed25519_hd_key`); it adds no new
transitive dependency to the TDK. It supports Dart `^3.8.0` and resolves
against `ssi` 3.9.x (the TDK's current line) as well as 4.x.

### In the TDK package (`affinidi_tdk_tsp_client`) — to build

Everything that touches the network, storage or Affinidi services:

1. **Transport.** An interface and two implementations:
   - `TspMediatorTransport` — POSTs raw qb2 bytes to the mediator's
     `/inbound` with `Content-Type: application/tsp` and the bearer token from
     the mediator's DID authentication (the same token
     `affinidi_tdk_didcomm_mediator_client` obtains today; reuse its
     `AuthorizationProvider` rather than duplicating it). The Affinidi mediator
     sniffs the TSP leading byte (`0xF8`, or `0xFB` for long frames) on the same
     endpoint it serves DIDComm on.
   - `TspDirectTransport` — HTTPS/WSS to the endpoint in the peer's
     `TSPTransport` service (constant `TspServiceType.tspTransport` in the TDK
     package; value `"TSPTransport"`, matching the Rust `TSP_SERVICE_TYPE`).
2. **Pickup.** Messages the mediator stores for the profile are
   `base64url(qb2)`; split a fetched batch into DIDComm and TSP with
   `Tsp.looksLikeTsp(base64UrlDecode(stored))` and hand TSP ones to
   `TspEndpoint.receive`. The WebSocket live-delivery stream in the mediator
   client needs the same classification.
3. **Persistent relationships.** A `RelationshipStore` backed by the vault
   stack (`affinidi_tdk_vault_data_manager` or the drift/edge providers), so
   relationships survive restarts. The record is small: local VID, remote VID,
   state, two optional 32-byte digests with their algorithm, and who invited.
4. **Protocol selection.** A policy hook mirroring the Rust SDK's
   `TspPolicy`: send TSP when the peer's DID document advertises
   `TSPTransport` (or a relationship already exists), otherwise DIDComm. Keep
   it off by default so existing apps are unaffected.
5. **Routing.** Cross-mediator delivery wraps the inner message in
   `HopPayload(hops: [...])` addressed to the sender's mediator, as
   `affinidi-messaging-sdk` does in Rust; the hop list comes from the peer's
   mediator DID learned in the relationship invite's `replyPath` or
   configuration.

What it should **not** do: re-implement any wire format, crypto or state
transition. If the TDK package needs a protocol change, it goes into
`tsp` first.

## 2. Workspace and melos wiring

The TDK root `pubspec.yaml` is a pub workspace with melos 7 reading members
from it.

1. Create `packages/tsp/tsp_client/` with:

   ```yaml
   # packages/tsp/tsp_client/pubspec.yaml
   name: affinidi_tdk_tsp_client
  description: Trust Spanning Protocol (TSP) client for the Affinidi TDK — mediator transport, pickup, and persistent relationships over tsp.
   version: 0.1.0
   homepage: https://github.com/affinidi/affinidi-tdk-dart/tree/main/packages/tsp/tsp_client
   repository: https://github.com/affinidi/affinidi-tdk-dart

   environment:
     sdk: ^3.8.0

   resolution: workspace

   dependencies:
    affinidi_tsp: ^0.1.0
     affinidi_tdk_didcomm_mediator_client: ^2.0.3  # AuthorizationProvider, mediator pickup
     dio: ^5.9.0
     ssi: ^3.3.0

   dev_dependencies:
     lints: ^5.0.0
     test: ^1.24.0
   ```

2. Add the member to the root `pubspec.yaml`:

   ```yaml
   workspace:
     # ...
     - packages/didcomm/vdip
     - packages/tsp/tsp_client
   ```

3. Add `LICENSE`, `README.md`, `CHANGELOG.md`, `example/`, `test/` following
   `packages/didcomm/didcomm_mediator_client`.

4. **Trap — tests would be skipped.** The root melos `test-dart` and
   `test-flutter` scripts ignore packages matching `*_client*` (intended for
   the generated API clients under `clients/`). `affinidi_tdk_tsp_client`
   matches, so `melos run test` would silently not run its tests — as is
   already the case for `affinidi_tdk_didcomm_mediator_client`. Either narrow
   the ignore to the generated clients (e.g. list them, or move the glob to a
   `scope`/`dirExists` rule on `clients/`), or name the package
   `affinidi_tdk_tsp` at `packages/tsp/tsp`. The first is the better fix
   because it also restores the DIDComm client's tests.

5. **Post-quantum is a separate decision.** `affinidi_tsp_pq` requires Dart
   `^3.10.0` (its `pqcrypto` dependency does) and is not needed by the client.
   Adding it to the workspace raises the effective SDK floor for the whole
   workspace resolution; do it only when the TDK moves to Dart 3.10 (which the
   `ssi` 4.x line already requires). Until then an app adds it directly.

## 3. Code sketch

```dart
// packages/tsp/tsp_client/lib/src/tsp_client.dart
import 'dart:async';
import 'dart:typed_data';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:ssi/ssi.dart';

import 'transport/tsp_transport.dart';

/// A DidManager-backed TSP client: identities from the wallet, peers from DID
/// resolution, relationships persisted, delivery through a transport.
class TspClient {
  TspClient._(this._endpoint, this._transport, this._me);

  static Future<TspClient> init({
    required DidManager didManager,
    required TspTransport transport,
    RelationshipStore? relationships,
    DidResolver? didResolver,
    List<TspKeyMapper> keyMappers = const [ClassicalKeyMapper()],
  }) async {
    final me = await didManager.toTspPrivateVid();
    final endpoint = TspEndpoint(
      identities: [me],
      resolver: SsiVidResolver(didResolver: didResolver, keyMappers: keyMappers),
      store: relationships, // e.g. VaultRelationshipStore(...)
    );
    return TspClient._(endpoint, transport, me);
  }

  final TspEndpoint _endpoint;
  final TspTransport _transport;
  final PrivateVid _me;

  String get vid => _me.id;

  Future<void> invite(String peer) async =>
      _transport.send(to: peer, message: (await _endpoint.invite(from: vid, to: peer)).bytes);

  Future<void> accept(String peer) async =>
      _transport.send(to: peer, message: (await _endpoint.accept(from: vid, to: peer)).bytes);

  Future<void> send(String peer, Uint8List data) async =>
      _transport.send(to: peer, message: (await _endpoint.send(from: vid, to: peer, data: data)).bytes);

  /// Inbound events; messages the relationship state refuses are dropped
  /// silently, as §3.7 recommends.
  Stream<TspEndpointEvent> get events => _transport.inbound
      .where(Tsp.looksLikeTsp)
      .asyncExpand((bytes) async* {
        try {
          final event = await _endpoint.receive(bytes);
          if (event.reply != null) {
            await _transport.send(to: event.from, message: event.reply!.bytes);
          }
          yield event;
        } on TspException {
          // Drop: a receiver should not respond to a failed message.
        }
      });
}
```

```dart
// packages/tsp/tsp_client/lib/src/transport/tsp_mediator_transport.dart
class TspMediatorTransport implements TspTransport {
  TspMediatorTransport({required this.mediatorUri, required this.authorization, required Dio dio});

  @override
  Future<void> send({required String to, required Uint8List message}) async {
    final tokens = await authorization.getAuthorizationTokens();
    await dio.post<void>(
      '$mediatorUri/inbound',
      data: Stream.value(message),
      options: Options(headers: {
        'Content-Type': 'application/tsp',
        'Authorization': 'Bearer ${tokens.accessToken}',
        'Content-Length': message.length,
      }),
    );
  }

  @override
  Stream<Uint8List> get inbound => /* mediator pickup / live delivery,
      base64url-decoding stored messages and keeping those that looksLikeTsp */;
}
```

## 4. Testing in the TDK

- Unit tests with two `TspClient`s over an in-memory `TspTransport`.
- Integration tests (the existing `integration_tests` package pattern) against
  a mediator built with the `tsp` feature (`affinidi-messaging-mediator`,
  `--features didcomm,tsp`), whose DID document advertises `TSPTransport`.
- Wire interoperability is already covered outside the TDK by
  `tsp-conformance`, which pairs this library's driver with the Rust
  `affinidi-tsp`, the ToIP reference and the JS implementation.

## 5. Checklist for the Dart team

- [ ] Publish `affinidi_tsp` (and, when needed, `affinidi_tsp_pq`) from
      `affinidi/affinidi-tsp-dart` with the same release pipeline as `didcomm`.
- [ ] Fix or sidestep the `*_client*` melos test filter (§2.4).
- [ ] Add `packages/tsp/tsp_client` to the workspace; implement transport,
      pickup classification, `VaultRelationshipStore`, protocol policy.
- [ ] Add a `TSPTransport` service to DIDs the TDK mints for mediators and
      agents that should be reachable over TSP.
- [ ] Integration test against a `tsp`-enabled mediator.
