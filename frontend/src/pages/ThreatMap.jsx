import { useEffect, useState } from "react";
import { api } from "../api";

export default function ThreatMap() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .securityOverview()
      .then((overview) => setData(overview.threats))
      .catch((err) => setError(err.message));
  }, []);

  return (
    <>
      <div className="topbar">
        <div>
          <p className="eyebrow mb-1">Threat Map</p>
          <h1>Blocked attack surface</h1>
        </div>
      </div>

      <div className="card">
        {error && <div className="alert alert-danger">{error}</div>}
        <div className="threat-grid">
          {data ? (
            data.map((threat) => (
              <div className="threat-card" key={threat.name}>
                <div>
                  <strong>{threat.name}</strong>
                  <div className="text-soft" style={{ fontSize: "0.82rem" }}>
                    {threat.control}
                  </div>
                </div>
                <span className="badge badge-security on">{threat.status}</span>
              </div>
            ))
          ) : (
            <p className="text-soft mb-0">Loading threat map...</p>
          )}
        </div>
      </div>
    </>
  );
}
