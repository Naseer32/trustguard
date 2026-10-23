import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { read } from "../chain";
import { friendlyError } from "../normalize";
import { aggregate } from "./stats";

const Ctx = createContext(null);
export const useRegistry = () => useContext(Ctx);

const PAGE = 20;
const MAX_LOAD = 100; // upper bound on artifacts loaded into the dashboard
const BATCH = 5;

async function loadOne(id) {
  try {
    const artifact = await read("get_artifact", [id]);
    let current = null;
    let lastEvidence = null;
    const jobs = [];
    if (artifact.assessment_count > 0) {
      jobs.push(read("get_current_assessment", [id]).then((v) => { current = v; }).catch(() => {}));
    }
    if (artifact.evidence_count > 0) {
      jobs.push(
        read("get_evidence_page", [id, artifact.evidence_count - 1, 1])
          .then((v) => { lastEvidence = v.items && v.items[0] ? v.items[0] : null; })
          .catch(() => {})
      );
    }
    await Promise.all(jobs);
    return { artifact, current, lastEvidence };
  } catch {
    return { artifact: null, current: null, lastEvidence: null };
  }
}

export function RegistryProvider({ children }) {
  const [state, setState] = useState({ status: "loading", items: [], total: 0, loadedAt: null, error: "", progress: 0 });
  const running = useRef(false);

  const load = useCallback(async () => {
    if (running.current) return;
    running.current = true;
    setState((s) => ({ ...s, status: s.items.length ? "refreshing" : "loading", error: "", progress: 0 }));
    try {
      const ids = [];
      let total = 0;
      let off = 0;
      do {
        const page = await read("list_artifact_ids", [off, PAGE]);
        total = page.total;
        ids.push(...page.items);
        off += PAGE;
      } while (off < total && ids.length < MAX_LOAD);

      const items = [];
      for (let i = 0; i < ids.length; i += BATCH) {
        const chunk = await Promise.all(ids.slice(i, i + BATCH).map(loadOne));
        items.push(...chunk);
        setState((s) => ({ ...s, progress: Math.min(1, items.length / ids.length) }));
      }
      setState({ status: "ready", items, total, loadedAt: new Date(), error: "", progress: 1 });
    } catch (e) {
      setState((s) => ({ ...s, status: "error", error: friendlyError(e) }));
    } finally {
      running.current = false;
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const stats = aggregate(state.items);
  return <Ctx.Provider value={{ ...state, stats, reload: load, capped: state.total > state.items.length }}>{children}</Ctx.Provider>;
}
