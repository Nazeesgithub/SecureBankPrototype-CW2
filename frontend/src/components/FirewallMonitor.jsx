import { useEffect, useState } from "react";
import { api } from "../api";

function statusBadgeClass(isGood) {
  return isGood ? "badge badge-security on" : "badge badge-security";
}

function ProfileTile({ label, profile }) {
  if (!profile) {
    return (
      <div className="security-module-tile">
        <span className="text-soft" style={{ fontSize: "0.78rem" }}>
          {label}
        </span>
        <span className="badge badge-security">Unavailable</span>
      </div>
    );
  }
  return (
    <div className="security-module-tile">
      <span className="text-soft" style={{ fontSize: "0.78rem" }}>
        {label}
      </span>
      <span className={statusBadgeClass(profile.enabled)}>
        {profile.enabled ? "Enabled" : "Disabled"}
      </span>
      <div className="text-soft mono" style={{ fontSize: "0.72rem", marginTop: 4 }}>
        In: {profile.defaultInboundAction} / Out: {profile.defaultOutboundAction}
      </div>
    </div>
  );
}

export default function FirewallMonitor() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  function load() {
    setError("");
    setLoading(true);
    api
      .firewallStatus()
      .then((response) => {
        if (!response.ok) {
          setError(response.message || "Unable to read firewall status.");
        }
        setData(response);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="card h-100">
      <div className="d-flex justify-content-between align-items-center gap-3 mb-3">
        <div>
          <h2 className="section-title mb-1">Windows Defender Firewall</h2>
          <p className="text-soft mb-0" style={{ fontSize: "0.85rem" }}>
            Host-level protection, read directly from Windows on this machine.
          </p>
        </div>
        <button className="btn btn-secondary" onClick={load} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && <div className="alert alert-danger mb-3">{error}</div>}

      {data && (
        <>
          <div className="d-flex align-items-center gap-2 mb-3">
            <span className={statusBadgeClass(data.firewallEnabled)}>
              Firewall {data.firewallEnabled ? "Enabled" : "Disabled"}
            </span>
            <span className="text-soft" style={{ fontSize: "0.78rem" }}>
              Last updated: {data.lastUpdated}
            </span>
          </div>

          <div className="security-module-grid mb-3">
            <ProfileTile label="Domain Profile" profile={data.domainProfile} />
            <ProfileTile label="Private Profile" profile={data.privateProfile} />
            <ProfileTile label="Public Profile" profile={data.publicProfile} />
          </div>

          <div className="mb-3">
            <span className="text-soft" style={{ fontSize: "0.82rem" }}>
              Application Ports
            </span>
            <div className="security-detail-panel">
              {data.appPorts?.map((portInfo) => (
                <div key={portInfo.port}>
                  <span className="text-soft">{portInfo.purpose}</span>
                  <div className="mono">
                    {portInfo.protocol} {portInfo.port}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mb-3">
            <span className="text-soft" style={{ fontSize: "0.82rem" }}>
              Firewall Rules Matching This App (python/node)
            </span>
            {data.appRulesError && (
              <div className="text-soft" style={{ fontSize: "0.78rem" }}>
                {data.appRulesError}
              </div>
            )}
            {!data.appRulesError && (!data.appRules || data.appRules.length === 0) && (
              <div className="text-soft" style={{ fontSize: "0.78rem" }}>
                No matching rules found.
              </div>
            )}
            {data.appRules && data.appRules.length > 0 && (
              <div className="timeline-list">
                {data.appRules.map((rule, idx) => (
                  <div className="timeline-row" key={`${rule.name}-${rule.direction}-${idx}`}>
                    <span className="timeline-time">{rule.direction}</span>
                    <div className="timeline-body">
                      <strong>{rule.name}</strong>
                      <div className="text-soft">{rule.action}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="topology-track mb-3">
            {["Internet", "Windows Defender Firewall", "React Frontend", "Flask Backend", "SQLite Database"].map(
              (node) => (
                <div className="topology-node" key={node}>
                  <span className="topology-dot" />
                  <div>
                    <div className="topology-label">{node}</div>
                  </div>
                </div>
              ),
            )}
          </div>

          <p className="text-soft mb-0" style={{ fontSize: "0.8rem" }}>
            Windows Defender Firewall is the system-level security control on the host
            machine — it filters traffic before any request reaches the React frontend or
            Flask backend. This panel reads its live status directly from Windows; it never
            enables, disables, or modifies any firewall setting.
          </p>
        </>
      )}
    </div>
  );
}
