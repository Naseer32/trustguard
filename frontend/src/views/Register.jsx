import { useEffect, useState } from "react";
import { read } from "../chain";
import { ARTIFACT_TYPES } from "../config";
import { validateRegistration, hasErrors } from "../lib/validate";
import { hrefFor } from "../lib/route";
import { useWallet } from "../lib/wallet.jsx";
import { useTx } from "../lib/useTx";
import { useRegistry } from "../lib/store.jsx";
import { nice } from "../normalize";
import { Icon } from "../ui/Icon.jsx";
import { CopyButton, Field, TxProgress } from "../ui/bits.jsx";

const empty = { artifact_type: "NPM_PACKAGE", name: "", ecosystem: "npm", source_ref: "", version: "", digest: "" };

export default function Register() {
  const { wallet, connect, busy: connecting } = useWallet();
  const { reload } = useRegistry();
  const [f, setF] = useState(empty);
  const [touched, setTouched] = useState({});
  const [previewId, setPreviewId] = useState("");
  const [created, setCreated] = useState("");
  const tx = useTx(wallet);
  const errors = validateRegistration(f);
  const show = (k) => (touched[k] ? errors[k] : "");
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const blur = (k) => () => setTouched((t) => ({ ...t, [k]: true }));

  useEffect(() => {
    setPreviewId("");
    if (hasErrors(errors)) return;
    let alive = true;
    const t = setTimeout(async () => {
      try {
        const id = await read("compute_artifact_id", [f.artifact_type, f.name.trim(), f.ecosystem.trim(), f.version.trim(), f.digest.trim()]);
        if (alive) setPreviewId(id);
      } catch {
        if (alive) setPreviewId("");
      }
    }, 450);
    return () => { alive = false; clearTimeout(t); };
  }, [f.artifact_type, f.name, f.ecosystem, f.version, f.digest, f.source_ref]);

  async function submit(e) {
    e.preventDefault();
    setTouched({ name: 1, ecosystem: 1, version: 1, source_ref: 1, digest: 1 });
    if (hasErrors(errors) || !wallet) return;
    const out = await tx.run(
      "register_artifact",
      [f.artifact_type, f.name.trim(), f.ecosystem.trim(), f.source_ref.trim(), f.version.trim(), f.digest.trim()],
      { success: { title: "Artifact registered", body: "It will appear in the registry once the network finalizes it." } }
    );
    if (out) {
      setCreated(previewId);
      setF(empty);
      setTouched({});
      reload();
    }
  }

  return (
    <div className="stack">
      <header className="page-head">
        <h1>Register artifact</h1>
        <p className="lede">Create the record that evidence and assessments attach to. Each exact version gets its own record.</p>
      </header>

      <div className="cols">
        <form onSubmit={submit} className="panel form" noValidate>
          <div className="grid2">
            <Field label="Type">
              <select value={f.artifact_type} onChange={set("artifact_type")}>
                {ARTIFACT_TYPES.map((t) => <option key={t} value={t}>{nice(t)}</option>)}
              </select>
            </Field>
            <Field label="Ecosystem" error={show("ecosystem")} hint="Lowercase, such as npm, pypi or github.">
              <input value={f.ecosystem} onChange={set("ecosystem")} onBlur={blur("ecosystem")} placeholder="npm" autoCapitalize="none" />
            </Field>
          </div>
          <div className="grid2">
            <Field label="Name" error={show("name")}>
              <input value={f.name} onChange={set("name")} onBlur={blur("name")} placeholder="left-pad" autoCapitalize="none" spellCheck={false} />
            </Field>
            <Field label="Exact version" error={show("version")} hint="Names like latest or main are not accepted.">
              <input value={f.version} onChange={set("version")} onBlur={blur("version")} placeholder="1.3.0" autoCapitalize="none" />
            </Field>
          </div>
          <Field label="Source reference" error={show("source_ref")} hint="Where the artifact comes from, for example a repository or registry page.">
            <input value={f.source_ref} onChange={set("source_ref")} onBlur={blur("source_ref")} placeholder="https://github.com/org/repo" inputMode="url" autoCapitalize="none" spellCheck={false} />
          </Field>
          <Field label="SHA-256 digest (optional)" error={show("digest")} hint="Stored as supplied. The contract never checks it against the real artifact.">
            <input className="mono" value={f.digest} onChange={set("digest")} onBlur={blur("digest")} placeholder="64 hexadecimal characters" autoCapitalize="none" spellCheck={false} />
          </Field>

          <div className="idbox">
            <span>Artifact id</span>
            {previewId ? <><code>{previewId}</code><CopyButton value={previewId} label="Copy artifact id" /></> : <em>Complete the form to see the id.</em>}
          </div>

          {!wallet ? (
            <button type="button" className="btn primary" onClick={connect} disabled={connecting}><Icon name="wallet" /> {connecting ? "Connecting" : "Connect wallet to register"}</button>
          ) : (
            <button type="submit" className="btn primary" disabled={tx.busy}>{tx.busy ? "Registering" : "Register artifact"}</button>
          )}
          <TxProgress step={tx.step} hash={tx.hash} />
          {tx.error && <p className="error">{tx.error}</p>}
        </form>

        <aside className="side-col">
          {created && (
            <div className="panel success">
              <h3><Icon name="check" /> Registered</h3>
              <p>Your artifact was accepted. It becomes readable after finalization, which can take a while.</p>
              <p className="idline"><code>{created}</code><CopyButton value={created} label="Copy artifact id" /></p>
              <a className="btn" href={hrefFor({ name: "artifact", id: created })}>Open case file <Icon name="arrow" /></a>
            </div>
          )}
          <div className="panel">
            <h3>How identity works</h3>
            <p className="muted">
              The id is computed from the type, ecosystem, name, exact version and digest. Who registers it does not
              change the id, and registering the same combination twice is rejected.
            </p>
            <p className="muted">Whoever registers first becomes the owner. The owner can update the source reference only. Nobody can edit or remove assessments.</p>
          </div>
        </aside>
      </div>
    </div>
  );
}
