import { useEffect, useState } from "react";
import { api } from "../api";

export default function SecurityReport() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    api
      .securityReport()
      .then(setData)
      .catch((err) => setError(err.message));
  }, []);

  async function downloadPdf() {
    setDownloading(true);
    setError("");
    try {
      const blob = await api.downloadSecurityReport();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "security-report.pdf";
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message);
    } finally {
      setDownloading(false);
    }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <p className="eyebrow mb-1">Interactive Security Report</p>
          <h1>Downloadable audit summary</h1>
        </div>
        <button
          className="btn btn-primary"
          onClick={downloadPdf}
          disabled={downloading}
        >
          {downloading ? "Preparing PDF..." : "Download PDF"}
        </button>
      </div>

      {error && <div className="alert alert-danger">{error}</div>}

      <div className="row g-4">
        <div className="col-lg-6">
          <div className="card h-100">
            <h2 className="section-title">Security Checks</h2>
            <div className="pipeline-steps">
              {data?.checks?.map((check) => (
                <div className="pipeline-step" key={check.label}>
                  <div className="pipeline-step-header">
                    <span className="pipeline-step-title">{check.label}</span>
                    <span
                      className={`badge badge-security ${check.status === "PASS" ? "on" : "off"}`}
                    >
                      {check.status}
                    </span>
                  </div>
                  <div className="text-soft">{check.detail}</div>
                </div>
              )) || <p className="text-soft mb-0">Loading report...</p>}
            </div>
          </div>
        </div>

        <div className="col-lg-6">
          <div className="card h-100">
            <h2 className="section-title">Threat Snapshot</h2>
            <div className="threat-grid">
              {data?.threats?.map((threat) => (
                <div className="threat-card" key={threat.name}>
                  <div>
                    <strong>{threat.name}</strong>
                    <div className="text-soft" style={{ fontSize: "0.82rem" }}>
                      {threat.control}
                    </div>
                  </div>
                  <span className="badge badge-security on">
                    {threat.status}
                  </span>
                </div>
              )) || <p className="text-soft mb-0">Loading threats...</p>}
            </div>
            <div className="security-detail-panel" style={{ marginTop: 18 }}>
              <div>
                <span className="text-soft">Report Date</span>
                <div className="mono">{data?.date || "N/A"}</div>
              </div>
              <div>
                <span className="text-soft">Users</span>
                <div className="mono">{data?.summary?.users ?? "-"}</div>
              </div>
              <div>
                <span className="text-soft">Transactions</span>
                <div className="mono">{data?.summary?.transactions ?? "-"}</div>
              </div>
              <div>
                <span className="text-soft">Backup</span>
                <div className="mono">{data?.summary?.backup ?? "-"}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
