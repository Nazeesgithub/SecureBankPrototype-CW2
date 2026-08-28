import { usePrefersReducedMotion } from "./usePrefersReducedMotion";

// The API reports each stage as completed / demo / skipped / failed.
const STATE_CLASS = {
  completed: "is-complete",
  verified: "is-complete",
  demo: "is-demo",
  skipped: "is-skipped",
  failed: "is-failed",
};

const STATE_LABEL = {
  completed: "Complete",
  verified: "Verified",
  demo: "Demo",
  skipped: "Skipped",
  failed: "Failed",
};

/**
 * The Pipeline Rail: the cryptographic stages of a transaction threaded on one
 * continuous gradient running deep -> mid -> accent, the same ramp as the
 * shield in the favicon.
 *
 * Purely presentational. It renders whatever stage list the API returns and
 * makes no assumption about how many stages there are, so adding a stage
 * server-side needs no change here.
 */
export default function PipelineRail({ steps, visibleCount, caption }) {
  const reducedMotion = usePrefersReducedMotion();
  if (!steps || steps.length === 0) return null;

  // With reduced motion the rail is drawn complete: no travel, no staggering.
  const shown = reducedMotion ? steps.length : Math.min(visibleCount, steps.length);
  const fill = steps.length === 0 ? 0 : (shown / steps.length) * 100;

  return (
    <div className="rail" style={{ "--rail-fill": `${fill}%` }}>
      <div className="rail-track" aria-hidden="true" />

      <ol className="rail-nodes">
        {steps.slice(0, shown).map((step, index) => {
          const stateClass = STATE_CLASS[step.status] || "is-skipped";
          const stateLabel = STATE_LABEL[step.status] || step.status;
          return (
            <li
              className={`rail-node ${stateClass}`}
              key={step.step ?? index}
              // The stagger is a CSS animation delay, which the reduced-motion
              // block in theme.css neutralises along with everything else.
              style={{ "--node-delay": reducedMotion ? "0ms" : `${index * 90}ms` }}
            >
              <span className="rail-marker" aria-hidden="true">
                {step.step ?? index + 1}
              </span>

              <div className="rail-body">
                <div className="rail-head">
                  <span className="rail-title">{step.title}</span>
                  {step.algorithm && (
                    <span className="rail-algorithm">{step.algorithm}</span>
                  )}
                  <span className="rail-status">{stateLabel}</span>
                </div>
                {step.value && <p className="rail-value">{step.value}</p>}
              </div>
            </li>
          );
        })}
      </ol>

      {caption && (
        <p className="text-soft" style={{ marginTop: "var(--sp-4)", marginBottom: 0, fontSize: "var(--fs-sm)" }}>
          {caption}
        </p>
      )}
    </div>
  );
}
