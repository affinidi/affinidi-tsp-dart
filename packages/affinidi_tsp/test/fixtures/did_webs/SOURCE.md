# did:webs test fixtures

`vectors/` is copied unchanged from
[OpenVTC/vti-didcomm-js](https://github.com/OpenVTC/vti-didcomm-js)
`test/fixtures/did-webs/` at commit `56aa0f2` (Apache-2.0). That directory's
own provenance is in `vectors/ATTRIBUTION.md`: the Rust reference
`affinidi-did-webs` (Apache-2.0), keripy-produced artifacts from
hyperledger-labs/did-webs-resolver (Apache-2.0), and conformance vectors
recorded from `affinidi-did-webs` (`vectors/rust-vectors/README.md`).

`golden/cesr-golden.json.gz` holds what the JavaScript port's CESR layer
(`src/did-webs-cesr.js`, the reference this Dart port follows) answers for
every stand-alone `.cesr` fixture and every (stream, mutation) pair the Rust
vectors name: the message count and a SHA-256 of a canonical summary of each
parse, or the exact `KeriError` type and message of a refusal. It also holds
the qb64 digest of three inputs under every KERI digest code.

Regenerate it from a vti-didcomm-js checkout with its dependencies installed:

```sh
node test/tool/did_webs_cesr_golden.mjs <vti-didcomm-js checkout> \
  test/fixtures/did_webs/golden/cesr-golden.json.gz <commit>
```

`golden/kel-golden.json.gz` holds what the JavaScript port's KEL layer
(`src/did-webs-kel.js`) answers for the same streams: the parse verdict, then
for every identifier its key state (or the exact refusal), deactivation,
sequence numbers, issuer log, anchored digests and key state as of each of
its events (the first 24), and the verdict on every transferable signature
group in the stream. `test/did_webs_kel_test.dart` requires the Dart port to
answer identically, and separately requires every `key_state` and `parse`
record of the Rust vectors to give the Rust key state or error kind.
Regenerate it the same way:

```sh
node test/tool/did_webs_kel_golden.mjs <vti-didcomm-js checkout> \
  test/fixtures/did_webs/golden/kel-golden.json.gz <commit>
```

`golden/designations-golden.json.gz` holds what the JavaScript port's
designation layer (`src/did-webs-designations.js`, and the endpoint readers of
`src/did-webs.js`) answers for the same streams: for every identifier whose key
state verifies, read as of the whole stream and as of each of its events (the
first 24), the critical-designation check, the credentials issued under every
implemented schema with their status and attributes, the designated aliases,
key agreement keys, services and key roles (each with its first rejection
reason), the role and witness endpoints under BADA reply state, and the
delegator service; plus the X25519 conversion and the JWK of every key-state
key. `test/did_webs_designations_test.dart` requires the Dart port to answer
identically, and separately requires every `service_endpoints`,
`delegator_service` and `designated_*` record of the Rust vectors to give the
Rust answer or error kind. Regenerate it the same way:

```sh
node test/tool/did_webs_designations_golden.mjs <vti-didcomm-js checkout> \
  test/fixtures/did_webs/golden/designations-golden.json.gz <commit>
```

`golden/resolve-golden.json.gz` holds what the JavaScript port's resolver
(`src/did-webs.js`, `resolveFromArtifacts`) answers for every `resolve`
record of the Rust vectors and for every published fixture (with and without
its `did.json`, and as of each of its events): the resolved document,
document metadata and resolution metadata exactly as the JS returns them, or
the refusal's kind and exact message. It also holds a set of DIDs as
`parseDidWebs` reads them, and their artifact URLs (`websArtifactUrls`) under
the default, private, insecure and allow-listed egress policies.
`test/did_webs_resolver_test.dart` requires the Dart port to answer
identically, and separately requires every `resolve` record to give the Rust
document and metadata, or its error kind. Regenerate it the same way:

```sh
node test/tool/did_webs_resolve_golden.mjs <vti-didcomm-js checkout> \
  test/fixtures/did_webs/golden/resolve-golden.json.gz <commit>
```
