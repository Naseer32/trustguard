// Pure aggregation over what the contract returned. Nothing here invents data.

export const CLASSES = ["CRITICAL_RISK", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "INSUFFICIENT_EVIDENCE", "UNASSESSED"];
export const RISK_RANK = { CRITICAL_RISK: 5, HIGH_RISK: 4, MEDIUM_RISK: 3, LOW_RISK: 2, INSUFFICIENT_EVIDENCE: 1, UNASSESSED: 0 };

// items: [{ artifact, current: assessment|null, lastEvidence: evidence|null }]
export function aggregate(items) {
  const byClass = Object.fromEntries(CLASSES.map((c) => [c, 0]));
  const byConfidence = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  let assessments = 0;
  let evidence = 0;
  let assessed = 0;
  const needsAssessment = [];
  const events = [];

  for (const it of items) {
    const a = it.artifact;
    if (!a) continue;
    const c = a.current_classification in byClass ? a.current_classification : "UNASSESSED";
    byClass[c] += 1;
    assessments += a.assessment_count || 0;
    evidence += a.evidence_count || 0;
    if ((a.assessment_count || 0) > 0) assessed += 1;
    if ((a.evidence_count || 0) > (a.assessed_evidence_count || 0)) needsAssessment.push(a);

    if (a.registered_at) events.push({ kind: "registered", at: a.registered_at, artifact: a });
    if (it.lastEvidence && it.lastEvidence.submitted_at) {
      events.push({ kind: "evidence", at: it.lastEvidence.submitted_at, artifact: a, detail: it.lastEvidence });
    }
    if (it.current && it.current.assessed_at) {
      const conf = String(it.current.confidence || "").toUpperCase();
      if (conf in byConfidence && it.current.classification !== "INSUFFICIENT_EVIDENCE") byConfidence[conf] += 1;
      events.push({ kind: "assessment", at: it.current.assessed_at, artifact: a, detail: it.current });
    }
  }

  events.sort((x, y) => String(y.at).localeCompare(String(x.at)));
  const total = items.filter((i) => i.artifact).length;
  const attention = items
    .map((i) => i.artifact)
    .filter((a) => a && (RISK_RANK[a.current_classification] || 0) >= 4)
    .sort((x, y) => (RISK_RANK[y.current_classification] - RISK_RANK[x.current_classification]) || (y.current_score - x.current_score));

  return { total, byClass, byConfidence, assessments, evidence, assessed, unassessed: total - assessed, needsAssessment, attention, events };
}

export function filterArtifacts(list, { query = "", cls = "ALL", type = "ALL", sort = "newest" } = {}) {
  const q = query.trim().toLowerCase();
  let out = list.filter((a) => {
    if (cls !== "ALL" && (a.current_classification || "UNASSESSED") !== cls) return false;
    if (type !== "ALL" && a.artifact_type !== type) return false;
    if (!q) return true;
    return [a.name, a.ecosystem, a.version, a.artifact_id, a.artifact_type].some((v) => String(v || "").toLowerCase().includes(q));
  });
  const risk = (a) => RISK_RANK[a.current_classification] || 0;
  const by = {
    newest: (x, y) => String(y.registered_at).localeCompare(String(x.registered_at)),
    name: (x, y) => String(x.name).localeCompare(String(y.name)),
    risk: (x, y) => risk(y) - risk(x) || (y.current_score - x.current_score),
    evidence: (x, y) => (y.evidence_count || 0) - (x.evidence_count || 0),
  }[sort] || null;
  if (by) out = [...out].sort(by);
  return out;
}
