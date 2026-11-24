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
