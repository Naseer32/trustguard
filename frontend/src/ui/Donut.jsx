import { useEffect, useState } from "react";
import { LABEL } from "../normalize";
import { CLASSES } from "../lib/stats";

const R = 70;
const C = 2 * Math.PI * R;

// Distribution of current classifications across loaded artifacts.
export default function Donut({ byClass, total }) {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const t = requestAnimationFrame(() => setReady(true));
    return () => cancelAnimationFrame(t);
  }, []);

  let acc = 0;
  const parts = CLASSES.filter((c) => byClass[c] > 0).map((c) => {
    const len = (byClass[c] / total) * C;
    const part = { c, len, off: acc, n: byClass[c] };
    acc += len;
    return part;
  });

  return (
    <div className="donut">
      <svg viewBox="0 0 180 180" role="img" aria-label={"Risk distribution across " + total + " artifacts"}>
        <circle className="ring-bg" cx="90" cy="90" r={R} />
        {parts.map((p) => (
          <circle
            key={p.c}
            className={"ring " + p.c}
            cx="90" cy="90" r={R}
            strokeDasharray={`${ready ? Math.max(0, p.len - 2) : 0} ${C}`}
            strokeDashoffset={-p.off}
            transform="rotate(-90 90 90)"
          >
            <title>{LABEL[p.c]}: {p.n}</title>
          </circle>
        ))}
      </svg>
      <div className="donut-center">
        <strong>{total}</strong>
        <span>{total === 1 ? "artifact" : "artifacts"}</span>
      </div>
    </div>
  );
}
