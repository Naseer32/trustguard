import { useCallback, useEffect, useState } from "react";
import { read } from "../chain";
import { EVIDENCE_TYPES } from "../config";
import { validateEvidence, hasErrors } from "../lib/validate";
import { hrefFor } from "../lib/route";
import { useWallet } from "../lib/wallet.jsx";
import { useTx } from "../lib/useTx";
import { useRegistry } from "../lib/store.jsx";
import { friendlyError, short, fmtDate, ago, nice, LABEL } from "../normalize";
import { Icon } from "../ui/Icon.jsx";
import RiskBadge from "../ui/RiskBadge.jsx";
import RiskGauge from "../ui/RiskGauge.jsx";
import { CopyButton, Empty, Field, Skeleton, TxProgress } from "../ui/bits.jsx";

const TABS = [
  { id: "assessments", label: "Assessments" },
  { id: "evidence", label: "Evidence" },
  { id: "actions", label: "Take action" },
];

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
          {a.previous_classification === "UNASSESSED" ? "First assessment" : changed ? `Changed from ${LABEL[a.previous_classification] || a.previous_classification}` : "Unchanged"}
        </span>
        <time title={a.assessed_at}>{ago(a.assessed_at)}</time>
      </summary>
      <div className="assess-body">
        <p className="meta">
          Confidence {String(a.confidence || "").toLowerCase()}. Based on {a.evidence_count_used} evidence item{a.evidence_count_used === 1 ? "" : "s"}.
          Requested by <code>{short(a.requested_by, 6, 4)}</code> on {fmtDate(a.assessed_at)}. Reason: {a.reason || "none given"}.
        </p>
        <p>{a.explanation}</p>
        <List title="Warning indicators" items={a.warning_indicators} />
        <List title="Missing information" items={a.missing_information} />
        <List title="Mitigations" items={a.mitigations} />
        <p className="fine">
          Validators agree on the category and score. The explanation and lists are written by the leader validator and are not part of that agreement. {a.disclaimer}
        </p>
      </div>
    </details>
  );
}

function AssessPanel({ artifact, onDone }) {
  const { wallet, connect, busy: connecting } = useWallet();
  const [reason, setReason] = useState("");
  const tx = useTx(wallet);
  const fresh = artifact.evidence_count - (artifact.assessed_evidence_count || 0);
  const canAssess = artifact.assessment_count === 0 ? true : fresh > 0;

  async function go() {
    const out = await tx.run("assess_artifact", [artifact.artifact_id, reason.trim() || "assessment"], {
      success: { title: "Assessment accepted", body: "The new result appears once the network finalizes it." },
    });
    if (out) onDone();
  }

  return (
    <div className="panel form">
      <h3>Request assessment</h3>
      <p className="fine">
        {artifact.evidence_count === 0
          ? "With no evidence the result is always insufficient evidence. Add evidence first."
          : canAssess
          ? artifact.assessment_count === 0 ? "Ready for the first assessment." : `${fresh} new evidence item${fresh === 1 ? "" : "s"} since the last assessment.`
          : "Add new evidence before assessing again."}
      </p>
      <Field label="Reason" hint="Stored with the assessment.">
        <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reassessment after new evidence" maxLength={200} />
      </Field>
      {!wallet ? (
        <button className="btn primary" onClick={connect} disabled={connecting}><Icon name="wallet" /> {connecting ? "Connecting" : "Connect wallet"}</button>
      ) : (
        <button className="btn primary" onClick={go} disabled={tx.busy || !canAssess}>{tx.busy ? "Waiting for validators" : "Request assessment"}</button>
      )}
      <TxProgress step={tx.step} hash={tx.hash} />
      {tx.error && <p className="error">{tx.error}</p>}
    </div>
  );
}

const blankEv = { type: "SECURITY_ADVISORY", ref: "", digest: "", desc: "", observed: "", refs: "" };

function EvidenceForm({ artifact, onDone }) {
  const { wallet, connect, busy: connecting } = useWallet();
  const [f, setF] = useState(blankEv);
  const [touched, setTouched] = useState({});
  const tx = useTx(wallet);
  const errors = validateEvidence(f);
  const show = (k) => (touched[k] ? errors[k] : "");
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const blur = (k) => () => setTouched((t) => ({ ...t, [k]: true }));

  async function submit(e) {
    e.preventDefault();
    setTouched({ desc: 1, ref: 1, digest: 1, observed: 1, refs: 1 });
    if (hasErrors(errors) || !wallet) return;
    const refs = f.refs.split(",").map((s) => s.trim()).filter(Boolean).map(Number);
    const out = await tx.run(
      "submit_evidence",
      [artifact.artifact_id, f.type, f.ref.trim(), f.digest.trim(), f.desc.trim(), f.observed.trim(), refs],
      { success: { title: "Evidence accepted", body: "It will show in the list once the network finalizes it." } }
    );
    if (out) {
      setF(blankEv);
      setTouched({});
      onDone();
    }
  }

  return (
    <form onSubmit={submit} className="panel form" noValidate>
      <h3>Add evidence</h3>
      <p className="fine">Stored as an unverified claim from your wallet. Identical evidence cannot be added twice.</p>
      <Field label="Kind of evidence">
        <select value={f.type} onChange={set("type")}>{EVIDENCE_TYPES.map((t) => <option key={t} value={t}>{nice(t)}</option>)}</select>
      </Field>
      <Field label="What was found" error={show("desc")} hint={`${f.desc.trim().length} of 600 characters, at least 10.`}>
        <textarea value={f.desc} onChange={set("desc")} onBlur={blur("desc")} rows={4} />
      </Field>
      <Field label="Source reference (optional)" error={show("ref")}>
        <input value={f.ref} onChange={set("ref")} onBlur={blur("ref")} placeholder="https://..." inputMode="url" autoCapitalize="none" spellCheck={false} />
      </Field>
      <Field label="Date observed (optional)" error={show("observed")} hint="Format 2026-10-14. Not in the future.">
        <input value={f.observed} onChange={set("observed")} onBlur={blur("observed")} placeholder="2026-10-14" />
      </Field>
      <Field label="Content SHA-256 (optional)" error={show("digest")}>
        <input className="mono" value={f.digest} onChange={set("digest")} onBlur={blur("digest")} placeholder="64 hexadecimal characters" autoCapitalize="none" spellCheck={false} />
      </Field>
      <Field label="Related assessments (optional)" error={show("refs")} hint={artifact.assessment_count ? `Numbers 0 to ${artifact.assessment_count - 1}, comma separated.` : "None exist yet."}>
        <input value={f.refs} onChange={set("refs")} onBlur={blur("refs")} placeholder="0,1" inputMode="numeric" />
      </Field>
      {!wallet ? (
        <button type="button" className="btn primary" onClick={connect} disabled={connecting}><Icon name="wallet" /> {connecting ? "Connecting" : "Connect wallet"}</button>
      ) : (
        <button type="submit" className="btn primary" disabled={tx.busy}>{tx.busy ? "Submitting" : "Add evidence"}</button>
      )}
      <TxProgress step={tx.step} hash={tx.hash} />
      {tx.error && <p className="error">{tx.error}</p>}
    </form>
  );
}

export default function Artifact({ id, tab }) {
  const { reload: reloadRegistry } = useRegistry();
  const [art, setArt] = useState(null);
  const [history, setHistory] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const a = await read("get_artifact", [id]);
      setArt(a);
      const h = a.assessment_count ? await read("get_assessment_history", [id, 0, 20]) : { items: [] };
      const ev = a.evidence_count ? await read("get_evidence_page", [id, 0, 20]) : { items: [] };
      setHistory(h.items);
      setEvidence(ev.items);
    } catch (e) {
      setArt(null);
      setError(friendlyError(e));
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const afterWrite = () => { load(); reloadRegistry(); };
  const current = TABS.some((t) => t.id === tab) ? tab : "assessments";
  const latest = history.length ? history[history.length - 1] : null;

  if (loading && !art) {
    return (
      <div className="stack">
        <Skeleton h={18} w={160} /><Skeleton h={40} w="60%" /><Skeleton h={150} r={14} /><Skeleton h={220} r={14} />
      </div>
    );
  }

  if (!art) {
    return (
      <div className="stack">
        <a className="back" href="#/registry"><Icon name="arrow" size={15} /> Registry</a>
        <Empty icon="search" title="This artifact is not readable yet" action={<button className="btn" onClick={load}>Try again</button>}>
          Either the id is wrong, or it was registered very recently and the network has not finalized it. {error && <span className="muted">({error})</span>}
        </Empty>
      </div>
    );
  }

  return (
    <div className="stack">
      <a className="back" href="#/registry"><Icon name="arrow" size={15} /> Registry</a>
      <header className="case">
        <p className="kind">{nice(art.artifact_type)} in {art.ecosystem}, version {art.version}</p>
        <h1>{art.name}</h1>
        <p className="src">{art.source_ref}</p>

        <div className="verdict panel">
          <div className="verdict-text">
            <RiskBadge size="lg" classification={art.current_classification} score={art.current_score} applicable={art.current_score_applicable} />
            <span>
              {latest
                ? `Latest is assessment ${latest.sequence} of ${art.assessment_count} recorded, using ${latest.evidence_count_used} of ${art.evidence_count} evidence item${art.evidence_count === 1 ? "" : "s"}.`
                : "Not assessed yet. Add evidence, then request an assessment."}
            </span>
            <button className="icon-btn push" onClick={load} aria-label="Refresh" title="Refresh" disabled={loading}><Icon name="refresh" size={16} /></button>
          </div>
          <RiskGauge classification={art.current_classification} score={art.current_score} applicable={art.current_score_applicable} />
        </div>

        <dl className="facts">
          <div><dt>Artifact id</dt><dd><code>{art.artifact_id}</code><CopyButton value={art.artifact_id} label="Copy artifact id" /></dd></div>
          <div><dt>Digest</dt><dd><code>{art.digest_sha256 || "not supplied"}</code><span className="chip">{nice(art.digest_status)}</span></dd></div>
          <div><dt>Owner</dt><dd><code>{art.owner}</code><CopyButton value={art.owner} label="Copy owner address" /></dd></div>
          <div><dt>Registered</dt><dd>{fmtDate(art.registered_at)}</dd></div>
        </dl>
      </header>

      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <a key={t.id} role="tab" aria-selected={current === t.id} className={current === t.id ? "on" : ""} href={hrefFor({ name: "artifact", id, tab: t.id })}>
            {t.label}
            {t.id === "assessments" && <b>{art.assessment_count}</b>}
            {t.id === "evidence" && <b>{art.evidence_count}</b>}
          </a>
        ))}
      </div>

      {current === "assessments" && (
        <section>
          {history.length === 0 ? (
            <Empty icon="shield" title="No assessments yet" action={<a className="btn primary" href={hrefFor({ name: "artifact", id, tab: "actions" })}>Take action</a>}>
              Submit evidence, then ask the validators for an assessment.
            </Empty>
          ) : (
            [...history].reverse().map((a, i) => <Assessment key={a.sequence} a={a} open={i === 0} />)
          )}
        </section>
      )}

      {current === "evidence" && (
        <section>
          {evidence.length === 0 ? (
            <Empty icon="file" title="No evidence yet" action={<a className="btn primary" href={hrefFor({ name: "artifact", id, tab: "actions" })}>Add evidence</a>}>
              Without evidence the result is always insufficient evidence.
            </Empty>
          ) : (
            <ol className="ledger">
              {evidence.map((e) => (
                <li key={e.sequence}>
                  <span className="n">{e.sequence}</span>
                  <div>
                    <p className="ev-head"><strong>{nice(e.evidence_type)}</strong><span className="chip">unverified claim</span></p>
                    <p>{e.description}</p>
                    <p className="meta">
                      {e.observed_at ? `Observed ${e.observed_at}. ` : ""}Added {fmtDate(e.submitted_at)} by <code>{short(e.reporter, 6, 4)}</code>.
                    </p>
                    {e.source_ref && <p className="meta ref">{e.source_ref}</p>}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>
      )}

      {current === "actions" && (
        <section className="action-grid">
          <EvidenceForm artifact={art} onDone={afterWrite} />
          <AssessPanel artifact={art} onDone={afterWrite} />
        </section>
      )}
    </div>
  );
}
