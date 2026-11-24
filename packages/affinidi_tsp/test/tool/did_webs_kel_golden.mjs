// Golden KEL verification outcomes from the JS reference (vti-didcomm-js),
// for the Dart port's stage-2 parity tests.
//
//   node test/tool/did_webs_kel_golden.mjs <vti-didcomm-js checkout> <out.json.gz> <commit>
//
// For every stand-alone `.cesr` fixture and every (stream, mutation) pair the
// Rust conformance vectors name, it records what `Kels` answers: the parse
// verdict, then for every identifier in the stream its key state (or the
// refusal), whether it is deactivated, its sequence numbers, the key state as
// of each of its events, its issuer log and anchored digests, and the verdict
// on every transferable signature group the stream carries.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { resolve, relative } from "node:path";
import { gzipSync } from "node:zlib";

const REF = process.argv[2];
const OUT = process.argv[3];
const kel = await import(resolve(REF, "src/did-webs-kel.js"));
const cesr = await import(resolve(REF, "src/did-webs-cesr.js"));
const vec = await import(resolve(REF, "test/support-did-webs-vectors.js"));
const { Kels, KelError, StreamError, thresholdJson } = kel;
const { KeriError, transIdxSigGroups, str, get } = cesr;

/** Every sequence number `as of` is tried at, at most, per identifier. */
const MAX_AS_OF = 24;

function err(e) {
  if (e instanceof StreamError) return { error: "Stream", message: e.message };
  if (e instanceof KelError) return { error: "Kel", message: e.message };
  if (e instanceof KeriError) return { error: `Keri:${e.type}`, message: e.message };
  return { error: "js", message: String(e && e.message) };
}

function attempt(fn) {
  try {
    return fn();
  } catch (e) {
    return err(e);
  }
}

const state = (s) => ({
  prefix: s.prefix,
  sn: s.sn,
  said: s.said,
  lastEventDigest: s.lastEventDigest,
  keys: s.keys,
  nextKeys: s.nextKeys,
  threshold: thresholdJson(s.threshold),
  nextThreshold: thresholdJson(s.nextThreshold),
  backers: s.backers,
  backerThreshold: s.backerThreshold,
  config: s.config,
  delegated: s.delegated,
  delegator: s.delegator,
  protocolMajor: s.protocolMajor,
});

const logEvent = (e) => ({ sn: e.sn, said: e.said, seals: e.seals.length, est: e.establishment ? e.establishment.sn : null });

function outcome(bytes) {
  let kels;
  try {
    kels = Kels.parse(bytes);
  } catch (e) {
    return { parse: err(e) };
  }
  const prefixes = [...kels.byPrefix.keys()];
  const ids = prefixes.map((prefix) => {
    const out = { prefix };
    out.state = attempt(() => state(kels.keyState(prefix)));
    out.deactivated = kels.isDeactivated(prefix);
    out.inception = kels.inceptionSaid(prefix);
    const sns = kels.sequenceNumbers(prefix);
    out.sns = sns;
    out.anchored = attempt(() => [...kels.anchoredDigests(prefix)].sort());
    out.log = attempt(() => {
      const log = kels.issuerLog(prefix);
      return { events: log.events.map(logEvent), superseded: log.superseded.map(logEvent), limit: log.limit };
    });
    out.asOf = [...new Set(sns)].slice(0, MAX_AS_OF).map((sn) =>
      attempt(() => {
        const at = kels.asOf(prefix, sn);
        return { sn, state: attempt(() => state(at.keyState(prefix))) };
      }),
    );
    return out;
  });
  const groups = [];
  kels.messages.forEach((msg, i) => {
    for (const g of transIdxSigGroups(msg)) {
      groups.push({ message: i, prefix: g.prefix, said: g.said, result: attempt(() => kels.verifySignatureGroup(g.prefix, msg.serder.raw, g).sn) });
    }
  });
  const ilks = kels.messages.map((m) => str(get(m.serder.sad, "t")) ?? null);
  return { parse: { ok: kels.messages.length }, ilks, ids, groups };
}

const cases = [];
const fixtures = resolve(REF, "test/fixtures/did-webs");
const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((d) => (d.isDirectory() ? walk(resolve(dir, d.name)) : [resolve(dir, d.name)]));
for (const f of walk(fixtures).filter((p) => p.endsWith(".cesr")).sort()) {
  cases.push({ file: relative(fixtures, f), ...outcome(new Uint8Array(readFileSync(f))) });
}
const seen = new Set();
for (const [, records] of vec.loadVectors()) {
  for (const r of records) {
    if (!r.keri_cesr) continue;
    const key = JSON.stringify([r.keri_cesr, r.mutation ?? null]);
    if (seen.has(key)) continue;
    seen.add(key);
    const base = new Uint8Array(readFileSync(resolve(vec.VECTORS, "blobs", r.keri_cesr)));
    cases.push({ blob: r.keri_cesr, mutation: r.mutation ?? null, ...outcome(vec.mutate(base, r.mutation)) });
  }
}
writeFileSync(OUT, gzipSync(JSON.stringify({ source: `vti-didcomm-js ${process.argv[4]}`, cases })));
const parsed = cases.filter((c) => c.parse.ok !== undefined);
const ids = parsed.flatMap((c) => c.ids);
const js = JSON.stringify(cases).match(/"error":"js"/g)?.length ?? 0;
console.log(
  `${cases.length} streams (${parsed.length} parse), ${ids.length} identifiers, ` +
    `${ids.filter((i) => !i.state.error).length} verify, ${parsed.reduce((n, c) => n + c.groups.length, 0)} signature groups, ${js} untyped errors`,
);
