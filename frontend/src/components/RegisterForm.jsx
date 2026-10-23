import { useEffect, useState } from "react";
import { read, write } from "../chain";
import { ARTIFACT_TYPES } from "../config";
import { useAction, Feedback } from "./Tx.jsx";

const empty = { artifact_type: "NPM_PACKAGE", name: "", ecosystem: "npm", source_ref: "", version: "", digest: "" };

export default function RegisterForm({ wallet, onRegistered }) {
  const [f, setF] = useState(empty);
  const [previewId, setPreviewId] = useState("");
  const act = useAction();
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value.trim() });

  useEffect(() => {
    setPreviewId("");
    if (!f.name || !f.version) return;
    const t = setTimeout(async () => {
      try {
        setPreviewId(await read("compute_artifact_id", [f.artifact_type, f.name, f.ecosystem, f.version, f.digest]));
      } catch {
        setPreviewId("");
      }
    }, 500);
    return () => clearTimeout(t);
  }, [f.artifact_type, f.name, f.ecosystem, f.version, f.digest]);

  async function submit(e) {
    e.preventDefault();
    const out = await act.run((st) =>
      write(wallet, "register_artifact", [f.artifact_type, f.name, f.ecosystem, f.source_ref, f.version, f.digest], st)
    );
    if (out && previewId) {
      const id = previewId;
      setF(empty);
      onRegistered(id);
    }
  }

  return (
    <section>
      <header className="page-head">
        <h1>Register artifact</h1>
        <p className="lede">
          An artifact is identified by its type, ecosystem, name, exact version and digest. Registering the same
          combination twice is rejected, so each version gets its own record.
        </p>
      </header>

      <form onSubmit={submit} className="panel form">
        <div className="grid2">
          <label>Type
            <select value={f.artifact_type} onChange={set("artifact_type")}>
              {ARTIFACT_TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, " ").toLowerCase()}</option>)}
            </select>
          </label>
          <label>Ecosystem
            <input value={f.ecosystem} onChange={set("ecosystem")} placeholder="npm" required />
            <small>Lowercase, for example npm, pypi or github.</small>
          </label>
        </div>
        <div className="grid2">
          <label>Name
            <input value={f.name} onChange={set("name")} placeholder="left-pad" required />
          </label>
          <label>Exact version
            <input value={f.version} onChange={set("version")} placeholder="1.3.0" required />
            <small>Names like latest or main are rejected.</small>
          </label>
        </div>
        <label>Source reference
          <input value={f.source_ref} onChange={set("source_ref")} placeholder="https://github.com/org/repo" required />
        </label>
        <label>SHA-256 digest
          <input className="mono" value={f.digest} onChange={set("digest")} placeholder="64 hexadecimal characters, or leave empty" />
          <small>The contract stores the digest but never checks it against the real artifact.</small>
        </label>

        <div className="idbox">
          <span>Artifact id</span>
          {previewId ? <code>{previewId}</code> : <em>Fill in name and version to see the id.</em>}
        </div>

        <div className="actions">
          <button className="primary" type="submit" disabled={act.busy || !wallet}>
            {act.busy ? "Registering" : wallet ? "Register artifact" : "Connect a wallet to register"}
          </button>
        </div>
        <Feedback status={act.status} error={act.error} />
      </form>
    </section>
  );
}
