import { useEffect, useState } from "react";
import { api } from "../api";

export default function SecurityLogs() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .securityLogs()
      .then(setData)
      .catch((err) => setError(err.message));
  }, []);

  return (
    <>
      <div className="topbar">
        <div>
          <p className="eyebrow mb-1">Security Timeline</p>
          <h1>Live log stream</h1>
        </div>
      </div>

      <div className="row g-4">
        <div className="col-lg-6">
          <div className="card h-100">
            <h2 className="section-title">Timeline</h2>
            {error && <div className="alert alert-danger">{error}</div>}
            <div className="timeline-list">
              {data?.timeline?.map((entry, idx) => (
                <div className="timeline-row" key={`${entry.time}-${idx}`}>
                  <span className="timeline-time">{entry.time}</span>
                  <div className="timeline-body">
                    <strong>{entry.event}</strong>
                    <div className="text-soft">{entry.detail}</div>
                  </div>
                </div>
              )) || <p className="text-soft mb-0">Loading timeline...</p>}
            </div>
          </div>
        </div>

        <div className="col-lg-6">
          <div className="card h-100">
            <h2 className="section-title">Security Logs</h2>
            <div className="log-box" style={{ maxHeight: 520 }}>
              {data?.recentLogs?.map((log, idx) => (
                <div key={`${log.timestamp}-${idx}`}>
                  [{log.timestamp}] {log.event}{" "}
                  {log.user ? `| user=${log.user}` : ""}{" "}
                  {log.details ? `| ${log.details}` : ""}
                </div>
              )) || <div>Loading logs...</div>}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
