import { useEffect, useState } from "react";
import { read } from "../chain";
import { PAGE } from "../config";
import { friendlyError, short, LABEL } from "../normalize";
import RiskGauge from "./RiskGauge.jsx";
import RiskBadge from "./RiskBadge.jsx";

const ORDER = ["CRITICAL_RISK", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "INSUFFICIENT_EVIDENCE", "UNASSESSED"];

function Summary({ rows }) {
  const counts = {};
  rows.forEach(({ a }) => {
    if (!a) return;
    const k = a.current_classification || "UNASSESSED";
    counts[k] = (counts[k] || 0) + 1;
  });
  const total = rows.filter((r) => r.a).length;
  if (!total) return null;
  return (
    <div className="summary">
      <div className="dist" role="img" aria-label="Distribution of risk on this page">
        {ORDER.filter((k) => counts[k]).map((k) => (
          <span key={k} className={"seg " + k} style={{ flexGrow: counts[k] }} />
        ))}
      </div>
      <ul className="legend">
        {ORDER.filter((k) => counts[k]).map((k) => (
          <li key={k}><i className={"dot " + k} />{LABEL[k]} <b>{counts[k]}</b></li>
        ))}
      </ul>
    </div>
  );
}

export default function ArtifactList({ onOpen }) {
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [rows, setRows] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [lookup, setLookup] = useState("");

  async function load(off = offset) {
    setLoading(true);
    setError("");
    try {
      const page = await read("list_artifact_ids", [off, PAGE]);
      setTotal(page.total);
      const items = await Promise.all(
        page.items.map(async (id) => {
          try {
            return { id, a: await read("get_artifact", [id]) };
          } catch {
            return { id, a: null };
          }
        })
      );
      setRows(items);
    } catch (e) {
      setError(friendlyError(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load(offset);
  }, [offset]);

  return (
    <section>
      <header className="page-head">
        <h1>Registry</h1>
        <p className="lede">
          Every artifact registered on the contract, with the risk the validators agreed on. Open one to see the
          evidence behind it.
        </p>
      </header>

      <form className="finder" onSubmit={(e) => { e.preventDefault(); if (lookup) onOpen(lookup); }}>
        <input
          aria-label="Artifact id"
          placeholder="Find by artifact id (tg1-...)"
          value={lookup}
          onChange={(e) => setLookup(e.target.value.trim())}
          spellCheck={false}
        />
        <button className="primary" type="submit" disabled={!lookup}>Open</button>
        <button type="button" onClick={() => load(offset)} disabled={loading}>{loading ? "Loading" : "Refresh"}</button>
      </form>

      {error && <p className="error">{error}</p>}

      {!loading && <Summary rows={rows} />}

      {loading && rows.length === 0 && (
        <ul className="rows">
          {[0, 1, 2].map((i) => <li key={i} className="row skeleton" aria-hidden="true" />)}
        </ul>
      )}

      {!loading && !error && total === 0 && (
        <div className="empty">
          <h3>No artifacts yet</h3>
          <p>Register the first package, repository or model to start a risk record.</p>
        </div>
      )}

      {rows.length > 0 && (
        <ul className="rows">
          {rows.map(({ id, a }) => (
            <li key={id}>
              <button className="row" onClick={() => onOpen(id)}>
                <div className="row-main">
                  <strong>{a ? a.name : short(id, 12, 6)}</strong>
                  {a && <span className="muted">{a.artifact_type.replace(/_/g, " ").toLowerCase()} in {a.ecosystem}, version {a.version}</span>}
                </div>
                {a && (
                  <>
                    <div className="row-gauge">
                      <RiskGauge size="sm" classification={a.current_classification} score={a.current_score} applicable={a.current_score_applicable} />
                    </div>
                    <RiskBadge classification={a.current_classification} score={a.current_score} applicable={a.current_score_applicable} />
                  </>
                )}
              </button>
            </li>
          ))}
        </ul>
      )}

      {total > PAGE && (
        <div className="pager">
          <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
          <span>{offset + 1} to {Math.min(offset + PAGE, total)} of {total}</span>
          <button disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>Next</button>
        </div>
      )}
    </section>
  );
}
