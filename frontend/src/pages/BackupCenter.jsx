import { useState } from "react";
import { api } from "../api";

export default function BackupCenter() {
  const [message, setMessage] = useState("");
  const [running, setRunning] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [steps, setSteps] = useState([]);

  async function runBackup() {
    setMessage("");
    setRunning(true);
    setSteps([]);
    try {
      const response = await api.securityBackup();
      response.pipeline.forEach((step, idx) => {
        setTimeout(() => setSteps((prev) => [...prev, step]), idx * 300);
      });
      setMessage(response.message);
    } catch (err) {
      setMessage(err.message);
    } finally {
      setRunning(false);
    }
  }

  async function verifyBackup() {
    setMessage("");
    setVerifying(true);
    try {
      const response = await api.verifySecurityBackup();
      setMessage(response.message);
    } catch (err) {
      setMessage(err.message);
    } finally {
      setVerifying(false);
    }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <p className="eyebrow mb-1">Backup Center</p>
          <h1>Integrity-protected database backups</h1>
        </div>
      </div>

      <div className="row g-4">
        <div className="col-lg-5">
          <div className="card h-100">
            <div className="helper-box">
              The backup workflow reads the live database, AES-encrypts it,
              hashes it, and re-verifies integrity by decrypting and re-hashing
              the result.
            </div>
            <div className="d-flex gap-2">
              <button
                className="btn btn-primary flex-grow-1"
                onClick={runBackup}
                disabled={running || verifying}
              >
                {running ? "Backing up..." : "Run Backup"}
              </button>
              <button
                className="btn btn-secondary flex-grow-1"
                onClick={verifyBackup}
                disabled={running || verifying}
              >
                {verifying ? "Verifying..." : "Verify Backup"}
              </button>
            </div>
            {message && (
              <div className="alert alert-success mt-3 mb-0">{message}</div>
            )}
          </div>
        </div>

        <div className="col-lg-7">
          <div className="card h-100">
            <h2 className="section-title">Backup Pipeline</h2>
            <div className="pipeline-steps">
              {steps.map((step) => (
                <div className="pipeline-step" key={step.step}>
                  <div className="pipeline-step-title">
                    {step.step}. {step.title}
                    {step.status === "failed" && " — FAILED"}
                  </div>
                  {step.detail && (
                    <div className="text-soft" style={{ fontSize: "0.82rem" }}>
                      {step.detail}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
