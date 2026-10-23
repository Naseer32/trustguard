import { LABEL } from "../normalize";

export default function RiskBadge({ classification, score, applicable, size }) {
  const c = classification || "UNASSESSED";
  return (
    <span className={"badge " + c + (size ? " " + size : "")}>
      <i className="dot" />
      {LABEL[c] || c}
      {applicable && typeof score === "number" ? <b>{score}</b> : null}
    </span>
  );
}
