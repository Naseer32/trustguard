import { LABEL } from "../normalize";

export default function RiskBadge({ classification, score, applicable }) {
  const c = classification || "UNASSESSED";
  return (
    <span className={"badge " + c}>
      <i className="dot" />
      {LABEL[c] || c}
      {applicable && score !== undefined && score !== null ? <b>{score}</b> : null}
    </span>
  );
}
