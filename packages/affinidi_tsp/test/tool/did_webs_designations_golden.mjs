// Golden designation outcomes from the JS reference (vti-didcomm-js), for the
// Dart port's stage-3 parity tests.
//
//   node test/tool/did_webs_designations_golden.mjs <vti-didcomm-js checkout> <out.json.gz> <commit>
//
// For every stand-alone `.cesr` fixture and every (stream, mutation) pair the
// Rust conformance vectors name, and for every identifier in the stream whose
// key state verifies — read as of the whole stream and as of each of its
// events (the first 24) — it records what `src/did-webs-designations.js` and
// the endpoint readers of `src/did-webs.js` answer: the critical-designation
// check, the credentials issued under every implemented schema (with their
// status and attributes), the designated aliases, key agreement keys,
// services and key roles, the BADA-ordered role and witness endpoints, the
// delegator service, the X25519 conversion of the key state's keys and the
// JWK of each of them. A refusal is recorded by type and exact message.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { resolve, relative } from "node:path";
import { gzipSync } from "node:zlib";

const REF = process.argv[2];
const OUT = process.argv[3];
const kel = await import(resolve(REF, "src/did-webs-kel.js"));
const cesr = await import(resolve(REF, "src/did-webs-cesr.js"));
const des = await import(resolve(REF, "src/did-webs-designations.js"));
const webs = await import(resolve(REF, "src/did-webs.js"));
const vec = await import(resolve(REF, "test/support-did-webs-vectors.js"));
const { Kels, KelError, StreamError } = kel;
const { KeriError, toJson } = cesr;
const { RegistryError, InvalidKeyError } = des;

/** Every sequence number `as of` is tried at, at most, per identifier. */
const MAX_AS_OF = 24;

function err(e) {
  if (e instanceof RegistryError) return { error: "Registry", message: e.message };
  if (e instanceof InvalidKeyError) return { error: "InvalidKey", message: e.message };
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

const plain = (v) => JSON.parse(JSON.stringify(toJson(v)));

function designationsOf(kels, aid) {
  const out = {};
  out.critical = attempt(() => des.unsupportedCritical(kels, aid));
  out.issued = des.IMPLEMENTED_SCHEMAS.map((schema) =>
    attempt(() => {
      const rejected = {};
      const issued = des.issuedDesignations(kels, aid, [schema], rejected);
      return {
        credentials: issued.map(([d, withdrawn]) => ({
          said: d.said,
          version: d.version,
          registry: d.registry,
          event: d.event,
          withdrawn,
          attributes: plain(d.attributes),
        })),
        rejected: rejected.reason ?? null,
      };
    }),
  );
  out.aliases = attempt(() => des.designatedAliases(kels, aid));
  out.keyAgreement = attempt(() => des.designatedKeyAgreement(kels, aid));
  out.services = attempt(() => {
    const v = des.designatedServices(kels, aid);
    return { services: v.services.map(plain), rejected: v.rejected };
  });
  out.keyRoles = attempt(() => {
    const v = des.designatedKeyRoles(kels, aid);
    return { issued: v.issued, roles: v.roles.map(([role, keys]) => [role.name, keys]), revoked: v.revoked, rejected: v.rejected };
  });
  out.endpoints = attempt(() => webs.internals.serviceEndpoints(kels, aid).map((e) => ({ eid: e.eid, role: e.role, urls: [...e.urls] })));
  out.delegator = attempt(() => webs.internals.delegatorService(kels, aid));
  return out;
}

function outcome(bytes) {
  let kels;
  try {
    kels = Kels.parse(bytes);
  } catch (e) {
    return { parse: err(e) };
  }
  const ids = [];
  for (const prefix of kels.byPrefix.keys()) {
    let state;
    try {
      state = kels.keyState(prefix);
    } catch {
      continue;
    }
    const out = { prefix, ...designationsOf(kels, prefix) };
    out.converted = des.convertedKeyAgreement(state.keys);
    out.jwks = state.keys.map((k) => attempt(() => des.jwkFromCesrKey(k)));
    out.asOf = [...new Set(kels.sequenceNumbers(prefix))].slice(0, MAX_AS_OF).map((sn) =>
      attempt(() => {
        const at = kels.asOf(prefix, sn);
        at.keyState(prefix);
        return { sn, ...designationsOf(at, prefix) };
      }),
    );
    ids.push(out);
  }
  return { parse: { ok: kels.messages.length }, ids };
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
const ids = cases.flatMap((c) => c.ids ?? []);
const views = ids.flatMap((i) => [i, ...i.asOf.filter((a) => !a.error)]);
const count = (pick) => views.filter((v) => { const x = pick(v); return x && !x.error; }).length;
const creds = views.reduce((n, v) => n + v.issued.reduce((m, s) => m + (s.credentials?.length ?? 0), 0), 0);
const js = JSON.stringify(cases).match(/"error":"js"/g)?.length ?? 0;
console.log(
  `${cases.length} streams, ${ids.length} verified identifiers, ${views.length} views (whole stream and as of each event), ` +
    `${creds} credentials, ${count((v) => v.aliases)} alias reads, ${count((v) => v.keyRoles)} key-role reads, ` +
    `${views.reduce((n, v) => n + (Array.isArray(v.endpoints) ? v.endpoints.length : 0), 0)} endpoints, ${js} untyped errors`,
);
