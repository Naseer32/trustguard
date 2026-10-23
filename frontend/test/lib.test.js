import test from "node:test";
import assert from "node:assert/strict";
import { validateRegistration, validateEvidence, checkDigest, checkRef, hasErrors } from "../src/lib/validate.js";
import { aggregate, filterArtifacts } from "../src/lib/stats.js";
import { parseHash, hrefFor } from "../src/lib/route.js";
import { plain, friendlyError } from "../src/normalize.js";

const good = { name: "left-pad", ecosystem: "npm", version: "1.3.0", source_ref: "https://github.com/o/r", digest: "" };

test("valid registration passes", () => assert.equal(hasErrors(validateRegistration(good)), false));
test("floating version rejected", () => assert.ok(validateRegistration({ ...good, version: "latest" }).version));
test("bad ecosystem rejected", () => assert.ok(validateRegistration({ ...good, ecosystem: "NPM" }).ecosystem));
test("credentials in url rejected", () => assert.ok(checkRef("https://user:pw@host.com/x")));
test("http scheme rejected", () => assert.ok(checkRef("http://example.com")));
test("digest rules", () => {
  assert.equal(checkDigest(""), "");
  assert.equal(checkDigest("a".repeat(64)), "");
  assert.ok(checkDigest("0".repeat(64)));
  assert.ok(checkDigest("abc"));
  assert.equal(checkDigest("sha256:" + "b".repeat(64)), "");
});
test("evidence rules", () => {
  const ok = { desc: "Install script contacts a host", ref: "https://x.io/a", digest: "", observed: "2026-10-14", refs: "0,1" };
  assert.equal(hasErrors(validateEvidence(ok, "2026-10-22")), false);
  assert.ok(validateEvidence({ ...ok, desc: "short" }, "2026-10-22").desc);
  assert.ok(validateEvidence({ ...ok, observed: "2026-12-01" }, "2026-10-22").observed);
  assert.ok(validateEvidence({ ...ok, observed: "2026-02-31" }, "2026-10-22").observed);
  assert.ok(validateEvidence({ ...ok, refs: "a" }, "2026-10-22").refs);
});

const A = (o) => ({ artifact_id: "tg1-" + o.name, name: o.name, artifact_type: "NPM_PACKAGE", ecosystem: "npm", version: "1.0.0",
  registered_at: "2026-10-19T10:00:00Z", evidence_count: 0, assessment_count: 0, assessed_evidence_count: 0,
  current_classification: "UNASSESSED", current_score: 0, current_score_applicable: false, ...o });

test("aggregate counts only real data", () => {
  const items = [
    { artifact: A({ name: "a", current_classification: "HIGH_RISK", current_score: 55, assessment_count: 2, evidence_count: 2, assessed_evidence_count: 2 }),
      current: { classification: "HIGH_RISK", confidence: "MEDIUM", assessed_at: "2026-10-19T17:28:35Z" },
      lastEvidence: { submitted_at: "2026-10-19T17:00:00Z" } },
    { artifact: A({ name: "b", evidence_count: 1 }), current: null, lastEvidence: { submitted_at: "2026-10-20T09:00:00Z" } },
  ];
  const s = aggregate(items);
  assert.equal(s.total, 2);
  assert.equal(s.byClass.HIGH_RISK, 1);
  assert.equal(s.byClass.UNASSESSED, 1);
  assert.equal(s.assessments, 2);
  assert.equal(s.evidence, 3);
  assert.equal(s.assessed, 1);
  assert.equal(s.unassessed, 1);
  assert.equal(s.byConfidence.MEDIUM, 1);
  assert.equal(s.needsAssessment.length, 1);
  assert.equal(s.attention.length, 1);
  assert.equal(s.events[0].at, "2026-10-20T09:00:00Z");
  assert.equal(s.events.length, 5);
});
test("aggregate of nothing is zeros", () => {
  const s = aggregate([]);
  assert.equal(s.total, 0);
  assert.equal(s.events.length, 0);
});
test("insufficient evidence is not counted in confidence", () => {
  const s = aggregate([{ artifact: A({ name: "c", assessment_count: 1, current_classification: "INSUFFICIENT_EVIDENCE" }), current: { classification: "INSUFFICIENT_EVIDENCE", confidence: "LOW", assessed_at: "2026-10-19T00:00:00Z" } }]);
  assert.equal(s.byConfidence.LOW, 0);
});

test("filter and sort", () => {
  const l = [A({ name: "zeta", current_classification: "LOW_RISK", current_score: 10 }), A({ name: "alpha", current_classification: "CRITICAL_RISK", current_score: 85 })];
  assert.equal(filterArtifacts(l, { query: "ALP" }).length, 1);
  assert.equal(filterArtifacts(l, { cls: "LOW_RISK" })[0].name, "zeta");
  assert.equal(filterArtifacts(l, { sort: "risk" })[0].name, "alpha");
  assert.equal(filterArtifacts(l, { sort: "name" })[0].name, "alpha");
});

test("routes round trip", () => {
  assert.deepEqual(parseHash("#/"), { name: "dashboard" });
  assert.deepEqual(parseHash("#/registry"), { name: "registry" });
  const r = parseHash("#/artifact/tg1-abc/evidence");
  assert.deepEqual(r, { name: "artifact", id: "tg1-abc", tab: "evidence" });
  assert.equal(hrefFor(r), "#/artifact/tg1-abc/evidence");
  assert.equal(hrefFor({ name: "artifact", id: "x", tab: "assessments" }), "#/artifact/x");
});

test("plain converts maps and bigint", () => {
  const out = plain(new Map([["a", 1n], ["b", [new Map([["c", 2n]])]]]));
  assert.deepEqual(out, { a: 1, b: [{ c: 2 }] });
});
test("friendlyError extracts code", () => assert.match(friendlyError(new Error("x [TG_DUPLICATE] y")), /TG_DUPLICATE/));
