import { useEffect, useState } from "react";
import { api } from "../api";

function actionBadgeClass(action) {
  return action === "ALLOW" ? "badge badge-security on" : "badge badge-security";
}

export default function FirewallConnections() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [appOnly, setAppOnly] = useState(true);

  function load(nextAppOnly) {
    setError("");
    setLoading(true);
    api
      .firewallConnections(nextAppOnly)
      .then((response) => {
        if (!response.ok) {
          setError(response.message || "Unable to read firewall connection log.");
        }
        setData(response);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load(appOnly);
  }, [appOnly]);

  return (
    <div className="card h-100">
      <div className="d-flex justify-content-between align-items-center gap-3 mb-3">
        <div>
          <h2 className="section-title mb-1">Live Connection Log</h2>
          <p className="text-soft mb-0" style={{ fontSize: "0.85rem" }}>
            Real Windows Defender Firewall audit entries (pfirewall.log), read directly from this machine.
          </p>
        </div>
        <div className="d-flex align-items-center gap-2">
          <button
            className="btn btn-secondary"
            onClick={() => setAppOnly((prev) => !prev)}
            disabled={loading}
          >
            {appOnly ? "Show All Traffic" : "App Ports Only"}
          </button>
          <button className="btn btn-secondary" onClick={() => load(appOnly)} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </div>

      {error && <div className="alert alert-danger mb-3">{error}</div>}

      {data && data.ok && (
        <>
          {data.entries.length === 0 && (
            <div className="text-soft" style={{ fontSize: "0.82rem" }}>
              No matching entries found{appOnly ? " for ports 5000/5173 yet — try \"Show All Traffic\"." : "."}
            </div>
          )}
          {data.entries.length > 0 && (
            <div className="timeline-list">
              {data.entries.map((entry, idx) => (
                <div className="timeline-row" key={`${entry.timestamp}-${idx}`}>
                  <span className="timeline-time">{entry.timestamp}</span>
                  <div className="timeline-body">
                    <strong>
                      <span className={actionBadgeClass(entry.action)}>{entry.action}</span>{" "}
                      {entry.protocol} {entry.srcIp}:{entry.srcPort} &rarr; {entry.dstIp}:{entry.dstPort}
                    </strong>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
