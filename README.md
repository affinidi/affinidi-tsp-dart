# Affinidi TSP for Dart

Trust Spanning Protocol (TSP) Rev 3 for Dart, published as a Dart pub
workspace of two packages.

| Package | Description |
| --- | --- |
| [`affinidi_tsp`](packages/affinidi_tsp) | Core library: CESR framing, HPKE-Base, libsodium sealed box, signed-only messages, relationship control and the `ssi`-integrated layer for DID-based VIDs. |
| [`affinidi_tsp_pq`](packages/affinidi_tsp_pq) | Post-quantum key types: the MLKEM768-X25519 hybrid HPKE KEM (`0x647a`) and ML-DSA-65 signatures. |

Start with the [core package README](packages/affinidi_tsp/README.md) for
installation and usage.

## Development

```sh
dart pub get
dart run melos analyze
dart run melos test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow.
