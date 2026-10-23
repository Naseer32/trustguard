import { useEffect, useState } from "react";
import { LABEL } from "../normalize";

const BANDS = [
  { c: "LOW_RISK", from: 0, to: 19, name: "Low" },
  { c: "MEDIUM_RISK", from: 20, to: 39, name: "Medium" },
  { c: "HIGH_RISK", from: 40, to: 69, name: "High" },
  { c: "CRITICAL_RISK", from: 70, to: 100, name: "Critical" },
];

// Four risk bands on a 0-100 scale; the marker shows the stored score.
export default function RiskGauge({ classification, score, applicable, size = "lg" }) {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const t = requestAnimationFrame(() => setReady(true));
    return () => cancelAnimationFrame(t);
  }, []);
  const c = classification || "UNASSESSED";
  const scored = applicable && typeof score === "number";
  const pos = scored ? Math.min(100, Math.max(0, score)) : 0;

  return (
    <div className={"gauge " + size + (scored ? "" : " none")}>
      <div className="track">
        {BANDS.map((b) => (
          <span key={b.c} className={"seg " + b.c + (scored && b.c === c ? " on" : "")} style={{ flexGrow: b.to - b.from + 1 }} />
        ))}
        {scored && <span className="pointer" style={{ left: (ready ? pos : 0) + "%" }} />}
      </div>
      {size === "lg" && (
        <div className="scale">
          {BANDS.map((b) => <span key={b.c} style={{ flexGrow: b.to - b.from + 1 }}>{b.name}</span>)}
        </div>
      )}
      {!scored && size === "lg" && <p className="gauge-note">{LABEL[c]}. There is no score to place on the scale.</p>}
    </div>
  );
}
