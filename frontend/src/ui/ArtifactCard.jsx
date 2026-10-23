import { hrefFor } from "../lib/route";
import { nice, ago } from "../normalize";
import RiskBadge from "./RiskBadge.jsx";
import RiskGauge from "./RiskGauge.jsx";

export default function ArtifactCard({ a }) {
  return (
    <a className="acard" href={hrefFor({ name: "artifact", id: a.artifact_id })}>
      <div className="acard-top">
        <div className="acard-title">
          <strong>{a.name}</strong>
          <span>{nice(a.artifact_type)} in {a.ecosystem}, version {a.version}</span>
        </div>
        <RiskBadge classification={a.current_classification} score={a.current_score} applicable={a.current_score_applicable} />
      </div>
      <RiskGauge size="sm" classification={a.current_classification} score={a.current_score} applicable={a.current_score_applicable} />
      <div className="acard-foot">
        <span>{a.evidence_count} evidence</span>
        <span>{a.assessment_count} assessment{a.assessment_count === 1 ? "" : "s"}</span>
        <span>Registered {ago(a.registered_at)}</span>
      </div>
    </a>
  );
}
