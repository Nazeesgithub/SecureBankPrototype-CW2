import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import FirewallMonitor from "../components/FirewallMonitor";
import FirewallConnections from "../components/FirewallConnections";

function moduleBadgeClass(status) {
  return status === "Idle" || status === "Not Yet Tested" || status === "Certificate Ready" || status === "Disabled"
    ? "badge badge-security"
    : "badge badge-security on";
}

export default function SecurityCenter() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [traceIndex, setTraceIndex] = useState(0);
  const [traceRunning, setTraceRunning] = useState(false);

  useEffect(() => {
    api
      .securityOverview()
      .then(setData)
      .catch((err) => setError(err.message));
  }, []);

  const trace = useMemo(() => data?.networkTrace || [], [data]);

  useEffect(() => {
    if (!traceRunning || trace.length === 0) return undefined;
    const timers = trace.map((_, idx) =>
      setTimeout(() => {
        setTraceIndex(idx);
        if (idx === trace.length - 1) {
          setTraceRunning(false);
        }
      }, idx * 450),
    );
    return () => timers.forEach(clearTimeout);
  }, [traceRunning, trace]);

  function runTrace() {
    if (!trace.length) return;
    setTraceIndex(0);
    setTraceRunning(true);
  }

  if (error) return <div className="alert alert-danger">{error}</div>;
  if (!data) return null;

  const lastLogin = data.lastRealLogin;

  return (
    <>
      <div className="topbar">
        <div>
          <p className="eyebrow mb-1">Live Security Operations Center</p>
          <h1>Secure Banking Security Demonstration Platform</h1>
        </div>
        <button className="btn btn-primary" onClick={runTrace}>
          {traceRunning ? "Packet Moving..." : "Run Login Trace"}
        </button>
      </div>

      <div className="row g-4">
        <div className="col-lg-7">
          <div className="card soc-hero h-100">
            <div className="d-flex flex-wrap justify-content-between align-items-start gap-3 mb-3">
              <div>
                <span className="eyebrow">Animated Network Topology</span>
                <h2 className="section-title mb-1">
                  Customer to Database Trace
                </h2>
                <p className="text-soft mb-0">
                  {lastLogin?.username
                    ? `Replaying the real login path last used by ${lastLogin.username} at ${lastLogin.timestamp}.`
                    : "Each hop mirrors the login path from the customer browser to the protected data store."}
                </p>
              </div>
              <div className="security-inline-status">
                <span className={moduleBadgeClass(data.securityModules.find((m) => m.label === "Firewall")?.status)}>
                  Firewall {data.securityModules.find((m) => m.label === "Firewall")?.status}
                </span>
                <span className={moduleBadgeClass(data.securityModules.find((m) => m.label === "TLS")?.status)}>
                  TLS {data.securityModules.find((m) => m.label === "TLS")?.status}
                </span>
                <span className={moduleBadgeClass(data.securityModules.find((m) => m.label === "IDS")?.status)}>
                  IDS {data.securityModules.find((m) => m.label === "IDS")?.status}
                </span>
              </div>
            </div>

            <div className="topology-track">
              {trace.map((node, idx) => (
                <div
                  className={`topology-node${idx === traceIndex ? " active" : ""}`}
                  key={node}
                >
                  <span className="topology-dot" />
                  <div>
                    <div className="topology-label">{node}</div>
                    <div className="text-soft" style={{ fontSize: "0.78rem" }}>
                      {idx === traceIndex
                        ? "Packet moving"
                        : idx < traceIndex
                          ? "Completed"
                          : "Waiting"}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="security-pipeline-banner">
              <div>
                <span className="text-soft">Database</span>
                <div className="mono">Encrypted SQLite record</div>
              </div>
              <div>
                <span className="text-soft">Backup</span>
                <div className="mono">{data.database.backup}</div>
              </div>
              <div>
                <span className="text-soft">Transactions</span>
                <div className="mono">{data.database.transactions}</div>
              </div>
            </div>
          </div>
        </div>

        <div className="col-lg-5">
          <div className="card h-100">
            <h2 className="section-title">Security Status Dashboard</h2>
            <div className="security-module-grid">
              {data.securityModules.map((module) => (
                <div className="security-module-tile" key={module.label}>
                  <span className="text-soft" style={{ fontSize: "0.78rem" }}>
                    {module.label}
                  </span>
                  <span className={moduleBadgeClass(module.status)}>
                    {module.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="col-lg-6">
          <div className="card h-100">
            <div className="d-flex justify-content-between align-items-center gap-3 mb-3">
              <h2 className="section-title mb-0">Security Timeline</h2>
              <Link
                to="/security-logs"
                className="btn btn-secondary"
                style={{ padding: "8px 14px" }}
              >
                Open Logs
              </Link>
            </div>
            <div className="timeline-list">
              {data.timeline.map((entry, idx) => (
                <div className="timeline-row" key={`${entry.time}-${idx}`}>
                  <span className="timeline-time">{entry.time}</span>
                  <div className="timeline-body">
                    <strong>{entry.event}</strong>
                    <div className="text-soft">{entry.detail}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="col-lg-6">
          <div className="card h-100">
            <div className="d-flex justify-content-between align-items-center gap-3 mb-3">
              <h2 className="section-title mb-0">Threat Map</h2>
              <Link
                to="/attack-simulation"
                className="btn btn-secondary"
                style={{ padding: "8px 14px" }}
              >
                Simulate Attacks
              </Link>
            </div>
            <div className="threat-grid">
              {data.threats.map((threat) => (
                <div className="threat-card" key={threat.name}>
                  <div>
                    <strong>{threat.name}</strong>
                    <div className="text-soft" style={{ fontSize: "0.82rem" }}>
                      {threat.control}
                    </div>
                  </div>
                  <span className={moduleBadgeClass(threat.status)}>
                    {threat.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="col-12">
          <div className="card">
            <div className="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
              <h2 className="section-title mb-0">Security Modules</h2>
              <div className="d-flex flex-wrap gap-2">
                <Link to="/encryption-lab" className="btn btn-secondary">
                  Encryption Lab
                </Link>
                <Link to="/database-viewer" className="btn btn-secondary">
                  Database Viewer
                </Link>
                <Link to="/security-report" className="btn btn-secondary">
                  Interactive Report
                </Link>
                <Link to="/backup-center" className="btn btn-secondary">
                  Backup Center
                </Link>
              </div>
            </div>
            <div className="security-detail-panel">
              <div>
                <span className="text-soft">Database</span>
                <div className="mono">
                  {data.database.users} users / {data.database.transactions}{" "}
                  transactions
                </div>
              </div>
              <div>
                <span className="text-soft">Encryption</span>
                <div className="mono">{data.database.encryption}</div>
              </div>
              <div>
                <span className="text-soft">TLS</span>
                <div className="mono">HTTPS transport + handshake</div>
              </div>
              <div>
                <span className="text-soft">Logs</span>
                <div className="mono">
                  {data.recentLogs.length} recent security events
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="col-12">
          <FirewallMonitor />
        </div>

        <div className="col-12">
          <FirewallConnections />
        </div>
      </div>
    </>
  );
}
