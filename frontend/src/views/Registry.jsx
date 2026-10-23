import { useMemo, useState } from "react";
import { useRegistry } from "../lib/store.jsx";
import { CLASSES, filterArtifacts } from "../lib/stats";
import { ARTIFACT_TYPES } from "../config";
import { LABEL, nice } from "../normalize";
import { hrefFor } from "../lib/route";
import { Icon } from "../ui/Icon.jsx";
import ArtifactCard from "../ui/ArtifactCard.jsx";
import { Empty, ErrorNote, Skeleton } from "../ui/bits.jsx";

export default function Registry() {
  const { status, items, stats, error, reload, capped, total } = useRegistry();
  const [query, setQuery] = useState("");
  const [cls, setCls] = useState("ALL");
  const [type, setType] = useState("ALL");
  const [sort, setSort] = useState("newest");

  const artifacts = useMemo(() => items.map((i) => i.artifact).filter(Boolean), [items]);
  const shown = useMemo(() => filterArtifacts(artifacts, { query, cls, type, sort }), [artifacts, query, cls, type, sort]);
  const loading = status === "loading";
  const filtered = query || cls !== "ALL" || type !== "ALL";

  function clear() {
    setQuery(""); setCls("ALL"); setType("ALL");
  }

  if (status === "error" && !items.length) return <ErrorNote message={error} onRetry={reload} />;

  return (
    <div className="stack">
      <header className="page-head">
        <h1>Registry</h1>
        <p className="lede">Every registered artifact with the risk its validators agreed on. Search by name, ecosystem, version or id.</p>
      </header>

      <div className="toolbar">
        <div className="search">
          <Icon name="search" size={17} />
          <input aria-label="Search artifacts" placeholder="Search artifacts" value={query} onChange={(e) => setQuery(e.target.value)} spellCheck={false} />
          {query && <button className="icon-btn" aria-label="Clear search" onClick={() => setQuery("")}><Icon name="x" size={15} /></button>}
        </div>
        <select aria-label="Artifact type" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="ALL">All types</option>
          {ARTIFACT_TYPES.map((t) => <option key={t} value={t}>{nice(t)}</option>)}
        </select>
        <select aria-label="Sort" value={sort} onChange={(e) => setSort(e.target.value)}>
          <option value="newest">Newest first</option>
          <option value="risk">Highest risk first</option>
          <option value="evidence">Most evidence</option>
          <option value="name">Name</option>
        </select>
        <button className="btn" onClick={reload} disabled={status === "refreshing" || loading}>
          <Icon name="refresh" size={15} /> {status === "refreshing" ? "Refreshing" : "Refresh"}
        </button>
      </div>

      <div className="chips" role="group" aria-label="Filter by risk">
        <button className={"chip-btn" + (cls === "ALL" ? " on" : "")} onClick={() => setCls("ALL")}>All <b>{stats.total}</b></button>
        {CLASSES.filter((c) => stats.byClass[c] > 0 || cls === c).map((c) => (
          <button key={c} className={"chip-btn" + (cls === c ? " on" : "")} onClick={() => setCls(c)}>
            <i className={"dot " + c} />{LABEL[c]} <b>{stats.byClass[c]}</b>
          </button>
        ))}
      </div>

      {loading ? (
        <div className="grid-cards">{[0, 1, 2, 3].map((i) => <Skeleton key={i} h={130} r={14} />)}</div>
      ) : artifacts.length === 0 ? (
        <Empty icon="registry" title="No artifacts yet" action={<a className="btn primary" href="#/register">Register the first artifact</a>}>
          Registering an artifact creates its record. Evidence and assessments are added afterwards.
        </Empty>
      ) : shown.length === 0 ? (
        <Empty
          icon="search"
          title="No artifact matches"
          action={
            /^tg1-[0-9a-f]{64}$/.test(query.trim())
              ? <a className="btn primary" href={hrefFor({ name: "artifact", id: query.trim() })}>Open this id directly</a>
              : filtered ? <button className="btn" onClick={clear}>Clear filters</button> : null
          }
        >
          Try a different name, or remove a filter. A very recent registration may not be finalized yet.
        </Empty>
      ) : (
        <>
          <p className="fine">{shown.length} of {artifacts.length} shown{capped ? `. The contract holds ${total}; only the first ${items.length} are loaded.` : ""}</p>
          <div className="grid-cards">{shown.map((a) => <ArtifactCard key={a.artifact_id} a={a} />)}</div>
        </>
      )}
    </div>
  );
}
