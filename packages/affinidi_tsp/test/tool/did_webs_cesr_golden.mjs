// Golden CESR parse outcomes from the JS reference (vti-didcomm-js), for the
// Dart port's stage-1 parity tests.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { resolve, relative } from "node:path";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
const REF = process.argv[2];
const OUT = process.argv[3];
const cesr = await import(resolve(REF, "src/did-webs-cesr.js"));
const vec = await import(resolve(REF, "test/support-did-webs-vectors.js"));
const { parseAll, serializeJson, computeSaid, isDigestCode, b64Encode, nativeDump, KeriError } = cesr;

const sig = (s) => `${s.code}:${s.index}:${s.ondex ?? "-"}:${b64Encode(s.raw)}`;
function att(a) {
  switch (a.type) {
    case "ControllerSigs": case "WitnessSigs": return `${a.type}[${a.sigs.map(sig).join(",")}]`;
    case "ReceiptCouples": return `${a.type}[${a.couples.map(([p, r]) => `${p}/${b64Encode(r)}`).join(",")}]`;
    case "FirstSeenReplayCouples": case "SealSourceCouples": return `${a.type}[${a.couples.map(([x, y]) => `${x}/${y}`).join(",")}]`;
    case "TransIdxSigGroups": return `${a.type}[${a.groups.map((g) => `${g.prefix}/${g.sn}/${g.said}/{${g.sigs.map(sig).join(",")}}`).join(",")}]`;
    case "BlindedStates": return `${a.type}[${a.states.map((s) => `${s.blid}/${s.uuid}/${s.acdc}/${s.state}`).join(",")}]`;
  }
  throw new Error(a.type);
}
function said(sad, kind) {
  const d = sad.get("d");
  if (typeof d !== "string" || d.length === 0) return "-";
  const code = d.startsWith("0") ? d.slice(0, 2) : d.slice(0, 1);
  if (!isDigestCode(code)) return "-";
  try { return computeSaid(sad, "d", code, kind); } catch (e) { return `!${e.type}:${e.message}`; }
}
function ver(v) { return v ? `${v.protocol},${v.major},${v.minor},${v.kind},${v.size},${v.genus ? v.genus.join(".") : "-"}` : "null"; }
export function summary(msgs) {
  return msgs.map((m) => {
    const s = m.serder;
    const dump = s.kind === "CESR" ? nativeDump(s.sad, []) : "";
    return [s.kind, ver(s.version), s.raw.length, serializeJson(s.sad), dump, said(s.sad, s.kind), m.attachments.map(att).join(";")].join("|");
  }).join("\n");
}
function outcome(bytes) {
  try {
    const msgs = parseAll(bytes);
    return { ok: true, n: msgs.length, sha256: createHash("sha256").update(summary(msgs)).digest("hex") };
  } catch (e) {
    if (!(e instanceof KeriError)) return { ok: false, error: { type: "js", message: String(e.message) } };
    return { ok: false, error: { type: e.type, message: e.message } };
  }
}
const cases = [];
// Every stand-alone fixture stream.
const fixtures = resolve(REF, "test/fixtures/did-webs");
const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((d) => d.isDirectory() ? walk(resolve(dir, d.name)) : [resolve(dir, d.name)]);
for (const f of walk(fixtures).filter((p) => p.endsWith(".cesr")).sort()) {
  cases.push({ file: relative(fixtures, f), ...outcome(new Uint8Array(readFileSync(f))) });
}
// Every (base stream, mutation) the Rust vectors name.
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
const digests = {};
for (const input of ["", "abc", "x".repeat(1025)]) {
  for (const code of ["E", "F", "G", "H", "I", "0D", "0E", "0F", "0G"]) digests[`${code}:${input.length}`] = cesr.digest(code, new TextEncoder().encode(input));
}
writeFileSync(OUT, gzipSync(JSON.stringify({ source: "vti-didcomm-js " + process.argv[4], digests, cases })));
const ok = cases.filter((c) => c.ok).length;
console.log(`${cases.length} cases, ${ok} ok, ${cases.length - ok} refused`);
