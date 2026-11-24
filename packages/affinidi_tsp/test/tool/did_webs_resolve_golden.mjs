// Golden resolutions from the JS reference (vti-didcomm-js), for the Dart
// port's stage-4 parity tests.
//
//   node test/tool/did_webs_resolve_golden.mjs <vti-didcomm-js checkout> <out.json.gz> <commit>
//
// Records what `src/did-webs.js` answers for:
//
// - every `resolve` record of the Rust conformance vectors (its DID, stream
//   and did.json), and every published fixture, resolved with and without
//   its did.json and as of each of its events: the resolved document,
//   document metadata and resolution metadata exactly as the JS returns them,
//   or the refusal's kind and exact message;
// - a set of DIDs, parsed (`parseDidWebs`) and turned into artifact URLs
//   (`websArtifactUrls`) under the default, private and insecure policies:
//   the parse, the URLs, or the refusal (an `InvalidDid` message, or the
//   egress policy's reason).
import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { resolve, relative } from "node:path";
import { gzipSync } from "node:zlib";

const REF = process.argv[2];
const OUT = process.argv[3];
const webs = await import(resolve(REF, "src/did-webs.js"));
const vec = await import(resolve(REF, "test/support-did-webs-vectors.js"));
const { DidWebsError, parseDidWebs, resolveFromArtifacts, websArtifactUrls } = webs;

function err(e) {
  if (e instanceof DidWebsError) return { error: e.kind, message: e.message };
  if (e?.code === "E_BLOCKED_ENDPOINT" || e?.name === "BlockedEndpointError") return { error: "Blocked", reason: e.reason };
  return { error: "js", message: String(e && e.message) };
}

function attempt(fn) {
  try {
    return fn();
  } catch (e) {
    return err(e);
  }
}

const resolution = (did, cesr, didJson) =>
  attempt(() => {
    const r = resolveFromArtifacts(did, cesr, didJson);
    return { document: r.didDocument, metadata: r.didDocumentMetadata, resolution: r.didResolutionMetadata };
  });

const cases = [];
for (const [, records] of vec.loadVectors()) {
  for (const r of records) {
    if (r.op !== "resolve") continue;
    const base = new Uint8Array(readFileSync(resolve(vec.VECTORS, "blobs", r.keri_cesr)));
    const didJson = r.did_json ? new Uint8Array(readFileSync(resolve(vec.VECTORS, "blobs", r.did_json))) : null;
    cases.push({ source: r.source, did: r.did, blob: r.keri_cesr, mutation: r.mutation ?? null, didJson: r.did_json ?? null, ...resolution(r.did, vec.mutate(base, r.mutation), didJson) });
  }
}

// The published fixtures: each DID with and without its did.json, and as of
// each of its events.
const FIX = resolve(REF, "test/fixtures/did-webs");
const read = (p) => new Uint8Array(readFileSync(resolve(FIX, p)));
const fixtures = [["ENro7uf0.keri.cesr", "ENro7uf0.did.json", `did:webs:did-webs-service%3a7676:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe`]];
for (const dir of ["deactivated", "parties/vta", "parties/mediator"]) {
  fixtures.push([`${dir}/keri.cesr`, `${dir}/did.json`, readFileSync(resolve(FIX, dir, "did.txt"), "utf8").trim()]);
}
fixtures.push(["deactivated/keri.cesr", "deactivated/legacy.did.json", readFileSync(resolve(FIX, "deactivated", "did.txt"), "utf8").trim()]);
fixtures.push(["ours-v2/lifecycle.keri.cesr", "ours-v2/lifecycle.did.json", JSON.parse(readFileSync(resolve(FIX, "ours-v2", "lifecycle.json"), "utf8")).did]);
for (const [cesr, didJson, did] of fixtures) {
  const stream = read(cesr);
  for (const v of [null, 0, 1, 2, 3, 4, 5, 6, 7, 8, 99]) {
    const d = v === null ? did : `${did}?versionId=${v}`;
    for (const j of [didJson, null]) {
      cases.push({ file: cesr, did: d, didJsonFile: j, ...resolution(d, stream, j && read(j)) });
    }
  }
}

// Identifiers and artifact URLs.
const AID = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";
const dids = new Set([
  `did:webs:example.com:${AID}`,
  `did:webs:example.com%3A8443:users:alice:${AID}?versionId=2#key-1`,
  `did:webs:did-webs-service%3a7676:${AID}`,
  `did:webs:%5B%3A%3A1%5D%3A7676:${AID}`,
  "did:web:example.com:" + AID,
  "did:webs:",
  `did:webs:${AID}`,
  `did:webs:example.com::${AID}`,
  "did:webs:example.com:E!",
  "did:webs:example.com:Eab",
  `did:webs:example.com:${AID}?versionId=two`,
  `did:webs:a.example%40b.example:${AID}`,
  `did:webs:a.example%2Fb:${AID}`,
  `did:webs:a.example%23x:${AID}`,
  `did:webs:a.example%2541:${AID}`,
  `did:webs:a%20b.example:${AID}`,
  `did:webs:example.com%3A99999:${AID}`,
  `did:webs:example.com%3A:${AID}`,
  `did:webs:%5Bnot-v6%5D:${AID}`,
  `did:webs:example.com%zz:${AID}`,
  `did:webs:example.com:..:${AID}`,
  `did:webs:example.com:a%2Fb:${AID}`,
  `did:webs:example.com:a%3Fb:${AID}`,
  `did:webs:example.com:users:${AID}`,
  `did:webs:localhost%3A7676:${AID}`,
  `did:webs:10.0.0.5:${AID}`,
  // Hosts a URL parser rewrites or refuses.
  `did:webs:EXAMPLE.com:${AID}`,
  `did:webs:example.com%3A443:${AID}`,
  `did:webs:example.com%3A0443:${AID}`,
  `did:webs:example.com%3A80:${AID}`,
  `did:webs:127.1:${AID}`,
  `did:webs:2130706433:${AID}`,
  `did:webs:0x7f000001%3A8000:${AID}`,
  `did:webs:0177.0.0.1:${AID}`,
  `did:webs:1.2.3.256:${AID}`,
  `did:webs:1.2.3.4.5:${AID}`,
  `did:webs:example.123:${AID}`,
  `did:webs:example.0x:${AID}`,
  `did:webs:8.8.8.8.:${AID}`,
  `did:webs:a%3Cb.example:${AID}`,
  `did:webs:a%5Eb.example:${AID}`,
  `did:webs:a%7Cb.example:${AID}`,
  `did:webs:a_b.example:${AID}`,
  `did:webs:%5B0%3A0%3A0%3A0%3A0%3A0%3A0%3A1%5D:${AID}`,
  `did:webs:%5B%3A%3Affff%3A127.0.0.1%5D:${AID}`,
  `did:webs:%5B2001%3Adb8%3A%3A1%5D%3A8443:${AID}`,
  `did:webs:%5B2606%3A4700%3A%3A1111%5D:${AID}`,
  `did:webs:%5B%3A%3A1%25eth0%5D:${AID}`,
  `did:webs:%5B%3A%3A1:${AID}`,
  `did:webs:example.com:a%20b:${AID}`,
  `did:webs:example.com:a%3cb:${AID}`,
  `did:webs:example.com:%7Euser:${AID}`,
  `did:webs:example.com:a<b:${AID}`,
  `did:webs:example.com:${AID}?versionId=+3`,
  `did:webs:example.com:${AID}?versionId=18446744073709551615`,
  `did:webs:example.com:${AID}?versionId=18446744073709551616`,
  `did:webs:example.com:${AID}?x=1&versionId=5&versionId=6`,
  `did:webs:example.com:${AID}?versionId`,
  `did:webs:example.com:${AID}#frag?versionId=2`,
  `did:webs:log.localhost:${AID}`,
  `did:webs:intranet:${AID}`,
  `did:webs:printer.local:${AID}`,
  `did:webs:169.254.169.254:${AID}`,
  `did:webs:100.100.100.200:${AID}`,
  `did:webs:LocalHost:${AID}`,
  `did:webs:localhost.:${AID}`,
]);
for (const [, records] of vec.loadVectors()) for (const r of records) if (r.did) dids.add(r.did);
const POLICIES = { none: undefined, private: { allowPrivate: true }, insecure: { allowInsecure: true }, allow: { allowHosts: ["example.com"] } };
const parses = [...dids].map((did) => {
  const parsed = attempt(() => parseDidWebs(did));
  const urls = {};
  if (!parsed.error) {
    for (const [name, policy] of Object.entries(POLICIES)) {
      urls[name] = attempt(() => {
        const u = websArtifactUrls(did, policy);
        return [u.keriCesr.href, u.didJson.href];
      });
    }
  }
  return { did, parsed, urls };
});

writeFileSync(OUT, gzipSync(JSON.stringify({ source: `vti-didcomm-js ${process.argv[4]}`, cases, parses })));
const ok = cases.filter((c) => !c.error).length;
const kinds = {};
for (const c of cases) if (c.error) kinds[c.error] = (kinds[c.error] ?? 0) + 1;
console.log(`${cases.length} resolutions (${ok} resolved, refused: ${JSON.stringify(kinds)}), ${parses.length} identifiers (${parses.filter((p) => !p.parsed.error).length} parse)`);
