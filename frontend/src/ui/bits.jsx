import { useState } from "react";
import { Icon } from "./Icon.jsx";
import { useToast } from "../lib/toast.jsx";

export function CopyButton({ value, label = "Copy" }) {
  const [done, setDone] = useState(false);
  const toast = useToast();
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } catch {
      toast.error("Could not copy", "Select the text and copy it manually.");
    }
  }
  return (
    <button type="button" className="icon-btn" onClick={copy} aria-label={label} title={label}>
      <Icon name={done ? "check" : "copy"} size={15} />
    </button>
  );
}

export function Empty({ icon = "file", title, children, action }) {
  return (
    <div className="empty">
      <span className="empty-icon"><Icon name={icon} size={22} /></span>
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function Skeleton({ h = 16, w = "100%", r = 8, className = "" }) {
  return <span className={"skel " + className} style={{ height: h, width: w, borderRadius: r }} aria-hidden="true" />;
}

export function ErrorNote({ message, onRetry }) {
  return (
    <div className="errbox" role="alert">
      <Icon name="alert" />
      <div>
        <strong>Could not load the data</strong>
        <p>{message}</p>
      </div>
      {onRetry && <button onClick={onRetry}>Try again</button>}
    </div>
  );
}

export function Field({ label, error, hint, children }) {
  return (
    <label className={"field" + (error ? " bad" : "")}>
      <span className="field-label">{label}</span>
      {children}
      {error ? <small className="field-error">{error}</small> : hint ? <small>{hint}</small> : null}
    </label>
  );
}

const STEPS = [
  { id: "wallet", label: "Confirm in wallet" },
  { id: "pending", label: "Validators agree" },
  { id: "done", label: "Accepted" },
];

export function TxProgress({ step, hash }) {
  if (step === "idle") return null;
  const idx = step === "failed" ? -1 : STEPS.findIndex((s) => s.id === step);
  return (
    <div className="tx" aria-live="polite">
      <ol>
        {STEPS.map((s, i) => (
          <li key={s.id} className={i < idx || step === "done" ? "done" : i === idx ? "now" : ""}>
            <span className="tx-dot">{i < idx || step === "done" ? <Icon name="check" size={12} /> : null}</span>
            {s.label}
          </li>
        ))}
      </ol>
      {hash && <p className="fine">Transaction <code>{hash}</code></p>}
      {step === "pending" && <p className="fine">Validators run the model on their own. This can take several minutes.</p>}
    </div>
  );
}
