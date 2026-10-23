import { useCallback, useEffect, useState } from "react";
import { read, write } from "../chain";
import { EVIDENCE_TYPES } from "../config";
import { friendlyError, short, fmtDate, LABEL } from "../normalize";
import RiskBadge from "./RiskBadge.jsx";
import RiskGauge from "./RiskGauge.jsx";
import { useAction, Feedback } from "./Tx.jsx";

const nice = (s) => String(s || "").replace(/_/g, " ").toLowerCase();

function List({ title, items }) {
  if (!items || !items.length) return null;
  return (
    <div className="list">
      <h5>{title}</h5>
      <ul>{items.map((x, i) => <li key={i}>{x}</li>)}</ul>
    </div>
  );
}

function Assessment({ a, open }) {
  const changed = a.previous_classification && a.previous_classification !== a.classification;
  return (
    <details className="assess" open={open}>
      <summary>
        <span className="seq">Assessment {a.sequence}</span>
        <RiskBadge classification={a.classification} score={a.score} applicable={a.score_applicable} />
        <span className="shift">
          {a.previous_classification === "UNASSESSED"
            ? "First assessment"
            : changed
            ? `Changed from ${LABEL[a.previous_classification] || a.previous_classification}`
            : "Unchanged"}
        </span>
        <time>{fmtDate(a.assessed_at)}</time>
      </summary>
      <div className="assess-body">
        <p className="meta">
          Confidence {String(a.confidence || "").toLowerCase()}. Based on {a.evidence_count_used} evidence item(s).
          Requested by <code>{short(a.requested_by, 6, 4)}</code>. Method: {a.method}.
        </p>
        <p>{a.explanation}</p>
        <List title="Warning indicators" items={a.warning_indicators} />
        <List title="Missing information" items={a.missing_information} />
        <List title="Mitigations" items={a.mitigations} />
        <p className="fine">
          The category and score are agreed by every validator. The explanation and lists are written by the leader
          validator and are not part of that agreement.
        </p>
      </div>
    </details>
  );
}

function EvidenceForm({ wallet, artifactId, assessmentCount, onDone }) {
  const [f, setF] = useState({ type: "SECURITY_ADVISORY", ref: "", digest: "", desc: "", observed: "", refs: "" });
  const act = useAction();
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });

  async function submit(e) {
    e.preventDefault();
    const refs = f.refs.split(",").map((s) => s.trim()).filter(Boolean).map(Number);
    const out = await act.run((st) =>
      write(wallet, "submit_evidence", [artifactId, f.type, f.ref.trim(), f.digest.trim(), f.desc.trim(), f.observed.trim(), refs], st)
    );
    if (out) {
      setF({ ...f, ref: "", digest: "", desc: "", observed: "", refs: "" });
      onDone();
    }
  }

  return (
    <form onSubmit={submit} className="panel form">
      <h3>Add evidence</h3>
      <p className="fine">Stored as an unverified claim from your wallet. Identical evidence cannot be added twice.</p>
      <label>Kind of evidence
        <select value={f.type} onChange={set("type")}>
          {EVIDENCE_TYPES.map((t) => <option key={t} value={t}>{nice(t)}</option>)}
        </select>
      </label>
      <label>Source reference
        <input value={f.ref} onChange={set("ref")} placeholder="https://..." required />
      </label>
      <label>What was found
        <textarea value={f.desc} onChange={set("desc")} rows={4} required />
        <small>{f.desc.trim().length} of 600 characters, at least 10.</small>
      </label>
      <label>Date observed
        <input value={f.observed} onChange={set("observed")} placeholder="2026-10-14" required />
      </label>
      <label>Content SHA-256 (optional)
        <input className="mono" value={f.digest} onChange={set("digest")} placeholder="64 hexadecimal characters" />
      </label>
      <label>Related assessments (optional)
        <input value={f.refs} onChange={set("refs")} placeholder={assessmentCount ? `Numbers 0 to ${assessmentCount - 1}, comma separated` : "None yet"} />
      </label>
      <div className="actions">
        <button className="primary" type="submit" disabled={act.busy || !wallet}>
          {act.busy ? "Submitting" : wallet ? "Add evidence" : "Connect a wallet to add evidence"}
        </button>
      </div>
      <Feedback status={act.status} error={act.error} />
    </form>
  );
}

export default function ArtifactDetail({ wallet, artifactId, onChangeId }) {
  const [input, setInput] = useState(artifactId || "");
  const [art, setArt] = useState(null);
  const [history, setHistory] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [reason, setReason] = useState("");
  const act = useAction();

  const load = useCallback(async () => {
    if (!artifactId) return;
    setLoading(true);
    setError("");
    try {
      const a = await read("get_artifact", [artifactId]);
      setArt(a);
      const h = a.assessment_count ? await read("get_assessment_history", [artifactId, 0, 20]) : { items: [] };
      const ev = a.evidence_count ? await read("get_evidence_page", [artifactId, 0, 20]) : { items: [] };
      setHistory(h.items);
      setEvidence(ev.items);
    } catch (e) {
      setArt(null);
      setHistory([]);
      setEvidence([]);
      setError(friendlyError(e));
    } finally {
      setLoading(false);
    }
  }, [artifactId]);

  useEffect(() => {
    setInput(artifactId || "");
    load();
  }, [artifactId, load]);

  async function assess() {
    const out = await act.run((st) => write(wallet, "assess_artifact", [artifactId, reason.trim() || "assessment"], st));
    if (out) load();
  }

  const latest = history.length ? history[history.length - 1] : null;

  return (
    <section>
      <form className="finder" onSubmit={(e) => { e.preventDefault(); if (input) onChangeId(input); }}>
        <input aria-label="Artifact id" placeholder="Artifact id (tg1-...)" value={input} onChange={(e) => setInput(e.target.value.trim())} spellCheck={false} />
        <button className="primary" type="submit" disabled={!input}>Load</button>
        <button type="button" onClick={load} disabled={!artifactId || loading}>{loading ? "Loading" : "Refresh"}</button>
      </form>

      {error && <p className="error">{error}</p>}
      {!artifactId && (
        <div className="empty">
          <h3>No case file open</h3>
          <p>Choose an artifact in the registry, or paste an artifact id above.</p>
        </div>
      )}

      {art && (
        <>
          <header className="case">
            <p className="kind">{nice(art.artifact_type)} in {art.ecosystem}, version {art.version}</p>
            <h1>{art.name}</h1>
            <p className="src">{art.source_ref}</p>

            <div className="verdict">
              <div className="verdict-text">
                <RiskBadge classification={art.current_classification} score={art.current_score} applicable={art.current_score_applicable} />
                <span>
                  {latest
                    ? `Assessment ${latest.sequence} of ${art.assessment_count}, using ${latest.evidence_count_used} of ${art.evidence_count} evidence item(s).`
                    : "Not assessed yet. Add evidence, then request an assessment."}
                </span>
              </div>
              <RiskGauge classification={art.current_classification} score={art.current_score} applicable={art.current_score_applicable} />
            </div>

            <dl className="facts">
              <div><dt>Artifact id</dt><dd><code>{art.artifact_id}</code></dd></div>
              <div><dt>Digest</dt><dd><code>{art.digest_sha256 || "not supplied"}</code> <span className="chip">{nice(art.digest_status)}</span></dd></div>
              <div><dt>Owner</dt><dd><code>{short(art.owner, 8, 6)}</code></dd></div>
            </dl>
          </header>

          <div className="cols">
            <div className="col-main">
              <h2>Assessments</h2>
              {history.length === 0 && <p className="muted">No assessments yet.</p>}
              {[...history].reverse().map((a, i) => <Assessment key={a.sequence} a={a} open={i === 0} />)}

              <h2>Evidence</h2>
              {evidence.length === 0 && <p className="muted">No evidence yet. Without evidence the result is always insufficient evidence.</p>}
              <ol className="ledger">
                {evidence.map((e) => (
                  <li key={e.sequence}>
                    <span className="n">{e.sequence}</span>
                    <div>
                      <p className="ev-head"><strong>{nice(e.evidence_type)}</strong><span className="chip">unverified claim</span></p>
                      <p>{e.description}</p>
                      <p className="meta">
                        Observed {e.observed_at}. Added {fmtDate(e.submitted_at)} by <code>{short(e.reporter, 6, 4)}</code>.
                      </p>
                      <p className="meta ref">{e.source_ref}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </div>

            <aside className="col-side">
              <div className="panel form">
                <h3>Request assessment</h3>
                <p className="fine">
                  Validators run the model independently, which can take several minutes. It needs new evidence since
                  the last assessment. If they disagree, nothing changes and you can try again.
                </p>
                <label>Reason
                  <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reassessment after new evidence" />
                </label>
                <div className="actions">
                  <button className="primary" onClick={assess} disabled={act.busy || !wallet}>
                    {act.busy ? "Waiting for validators" : wallet ? "Request assessment" : "Connect a wallet to assess"}
                  </button>
                </div>
                <Feedback status={act.status} error={act.error} />
              </div>
              <EvidenceForm wallet={wallet} artifactId={artifactId} assessmentCount={art.assessment_count} onDone={load} />
            </aside>
          </div>
        </>
      )}
    </section>
  );
}
