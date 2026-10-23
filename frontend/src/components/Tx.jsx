import { useState } from "react";
import { friendlyError } from "../normalize";

// Small hook: runs an async action and tracks busy/status/error.
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  async function run(fn) {
    setBusy(true);
    setError("");
    setStatus("");
    try {
      const out = await fn(setStatus);
      setStatus("Accepted by the network.");
      return out;
    } catch (e) {
      setError(friendlyError(e));
      setStatus("");
      return null;
    } finally {
      setBusy(false);
    }
  }
  return { busy, status, error, run };
}

export function Feedback({ status, error }) {
  return (
    <>
      {status && <p className="status">{status}</p>}
      {error && <p className="error">{error}</p>}
    </>
  );
}
