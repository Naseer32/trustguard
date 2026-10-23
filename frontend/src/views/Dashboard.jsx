import { useRegistry } from "../lib/store.jsx";
import { hrefFor } from "../lib/route";
import { CLASSES } from "../lib/stats";
import { LABEL, ago, nice } from "../normalize";
import { Icon } from "../ui/Icon.jsx";
import Donut from "../ui/Donut.jsx";
import RiskBadge from "../ui/RiskBadge.jsx";
import { Empty, ErrorNote, Skeleton } from "../ui/bits.jsx";

function Kpi({ label, value, sub, loading }) {
  return (
    <div className="kpi">
      <span className="kpi-label">{label}</span>
      {loading ? <Skeleton h={34} w={70} /> : <strong>{value}</strong>}
      {sub && <span className="kpi-sub">{sub}</span>}
    </div>
  );
}

function EventLine({ e }) {
  const link = hrefFor({ name: "artifact", id: e.artifact.artifact_id });
  const map = {
    registered: { icon: "plus", text: "Registered" },
    evidence: { icon: "file", text: "Evidence added to" },
    assessment: { icon: "shield", text: "Assessed" },
  }[e.kind];
  return (
    <li>
      <span className={"ev-icon " + e.kind}><Icon name={map.icon} size={15} /></span>
      <div>
        <p>
          {map.text} <a href={link}>{e.artifact.name}</a>
          {e.kind === "evidence" && <span className="muted"> ({nice(e.detail.evidence_type)})</span>}
          {e.kind === "assessment" && <> <RiskBadge size="xs" classification={e.detail.classification} score={e.detail.score} applicable={e.detail.score_applicable} /></>}
        </p>
        <time title={e.at}>{ago(e.at)}</time>
      </div>
    </li>
  );
}

export default function Dashboard() {
  const { status, stats, total, items, error, reload, loadedAt, capped, progress } = useRegistry();
  const loading = status === "loading";

  if (status === "error" && !items.length) return <ErrorNote message={error} onRetry={reload} />;

  const conf = stats.byConfidence;
  const confTotal = conf.HIGH + conf.MEDIUM + conf.LOW;

  return (
    <div className="stack">
      <section className="hero">
        <div className="hero-copy">
          <h1>See supply-chain risk, with the evidence behind it</h1>
          <p className="lede">
            TrustGuard records what people report about a package, repository or model, and asks independent
            validators to agree on a risk category. Nothing is scanned, and every result shows where it came from.
          </p>
          <div className="hero-actions">
            <a className="btn primary" href="#/register"><Icon name="plus" /> Register artifact</a>
            <a className="btn" href="#/registry">Browse registry <Icon name="arrow" /></a>
          </div>
        </div>
        <div className="hero-viz">
          {loading ? (
            <div className="donut-skel"><Skeleton h={170} w={170} r={999} /></div>
          ) : stats.total > 0 ? (
            <>
              <Donut byClass={stats.byClass} total={stats.total} />
              <ul className="legend">
                {CLASSES.filter((c) => stats.byClass[c] > 0).map((c) => (
                  <li key={c}><i className={"dot " + c} />{LABEL[c]}<b>{stats.byClass[c]}</b></li>
                ))}
              </ul>
            </>
          ) : (
            <Empty icon="shield" title="Nothing registered yet">Register an artifact to see the risk distribution here.</Empty>
          )}
        </div>
      </section>

      <section className="kpis" aria-label="Registry totals">
        <Kpi loading={loading} label="Artifacts" value={stats.total} sub={capped ? `Showing ${items.length} of ${total}` : "All registered"} />
        <Kpi loading={loading} label="Assessed" value={stats.assessed} sub={`${stats.unassessed} waiting`} />
        <Kpi loading={loading} label="Assessments recorded" value={stats.assessments} sub="Across all artifacts" />
        <Kpi loading={loading} label="Evidence items" value={stats.evidence} sub="Unverified claims" />
      </section>

      <div className="dash-cols">
        <section className="panel">
          <header className="panel-head"><h2>Needs attention</h2></header>
          {loading ? <Skeleton h={90} /> : stats.attention.length === 0 ? (
            <p className="muted">No artifact is currently rated high or critical.</p>
          ) : (
            <ul className="mini-list">
              {stats.attention.slice(0, 5).map((a) => (
                <li key={a.artifact_id}>
                  <a href={hrefFor({ name: "artifact", id: a.artifact_id })}>{a.name}<span className="muted"> {a.version}</span></a>
                  <RiskBadge classification={a.current_classification} score={a.current_score} applicable={a.current_score_applicable} />
                </li>
              ))}
            </ul>
          )}

          <header className="panel-head sub"><h2>Ready for reassessment</h2></header>
          {loading ? <Skeleton h={60} /> : stats.needsAssessment.length === 0 ? (
            <p className="muted">Every artifact has been assessed with all of its evidence.</p>
          ) : (
            <ul className="mini-list">
              {stats.needsAssessment.slice(0, 5).map((a) => (
                <li key={a.artifact_id}>
                  <a href={hrefFor({ name: "artifact", id: a.artifact_id, tab: "actions" })}>{a.name}<span className="muted"> {a.version}</span></a>
                  <span className="muted small">{a.evidence_count - (a.assessed_evidence_count || 0)} new evidence</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="panel">
          <header className="panel-head"><h2>Confidence in current assessments</h2></header>
          {loading ? <Skeleton h={90} /> : confTotal === 0 ? (
            <p className="muted">Confidence appears here once an artifact has a scored assessment.</p>
          ) : (
            <ul className="bars">
              {["HIGH", "MEDIUM", "LOW"].map((k) => (
                <li key={k}>
                  <span>{k.charAt(0) + k.slice(1).toLowerCase()}</span>
                  <div className="bar"><i style={{ width: (conf[k] / confTotal) * 100 + "%" }} /></div>
                  <b>{conf[k]}</b>
                </li>
              ))}
            </ul>
          )}
          <p className="fine">Confidence is the model's own statement. It is not a measure of accuracy.</p>
        </section>
      </div>

      <section className="panel">
        <header className="panel-head">
          <h2>Latest activity</h2>
          <button className="btn ghost" onClick={reload} disabled={status === "refreshing" || loading}>
            <Icon name="refresh" size={15} /> {status === "refreshing" ? "Refreshing" : "Refresh"}
          </button>
        </header>
        {loading ? (
          <div className="stack sm"><Skeleton h={38} /><Skeleton h={38} /><Skeleton h={38} /></div>
        ) : stats.events.length === 0 ? (
          <Empty icon="clock" title="No activity yet">Registrations, evidence and assessments will be listed here.</Empty>
        ) : (
          <ul className="feed">{stats.events.slice(0, 10).map((e, i) => <EventLine key={i} e={e} />)}</ul>
        )}
        <p className="fine">
          Shows the latest registration, evidence item and assessment of each artifact, read from the contract.
          {loadedAt && <> Loaded {ago(loadedAt)}. </>}
          Only finalized transactions appear, so new ones can take a while to show.
        </p>
        {loading && <div className="progress"><i style={{ width: Math.round(progress * 100) + "%" }} /></div>}
      </section>
    </div>
  );
}
