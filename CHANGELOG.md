## 0.1.0

- Initial release: TSP Rev 3 (`YTSP-AAC`).
- Binary CESR framing with short/long count codes, lead-pad variants and long
  VIDs; canonical-encoding checks.
- Payloads XSCS, XCTL, XPAD, XRFI (Reply_Path, Referral), XRFA, XRFD, XHOP
  (nested and routed); padding; ESSR payload sender.
- Self-addressing digests (SHA2-256, Blake2b-256).
- HPKE-Base (RFC 9180), libsodium sealed box, signed-only.
- Relationship state machine and `TspEndpoint`.
- `ssi` integration: `DidManager` identities, `SsiVidResolver`,
  `DidPeer4Resolver`.
- Appendix A vectors reproduce byte-exact; RFC 9180 vectors pass.
