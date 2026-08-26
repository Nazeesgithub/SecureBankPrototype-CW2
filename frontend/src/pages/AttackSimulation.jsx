import { useState } from "react";
import { api } from "../api";

const attacks = [
  { key: "sqlInjection", label: "Simulate SQL Injection" },
  { key: "bruteForce", label: "Simulate Brute Force" },
  { key: "unauthorizedAccess", label: "Simulate Unauthorized Access" },
  { key: "packetSniffing", label: "Simulate Packet Sniffing" },
  { key: "tamperedTransaction", label: "Simulate Tampered Transaction" },
  { key: "replayAttack", label: "Simulate Replay Attack" },
];

export default function AttackSimulation() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [running, setRunning] = useState("");
  const [visibleCount, setVisibleCount] = useState(0);
  const [resetMessage, setResetMessage] = useState("");
  const [resetting, setResetting] = useState(false);

  async function resetDemoTarget() {
    setError("");
    setResetMessage("");
    setResetting(true);
    try {
      const response = await api.resetDemoTarget();
      setResetMessage(response.message);
    } catch (err) {
      setError(err.message);
    } finally {
      setResetting(false);
    }
  }

  async function runAttack(attackType) {
    setError("");
    setRunning(attackType);
    setVisibleCount(0);
    try {
      const response = await api.securityAttack({ attackType });
      setData(response);
      response.sequence.forEach((_, idx) => {
        setTimeout(
          () => setVisibleCount((prev) => Math.max(prev, idx + 1)),
          idx * 350,
        );
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setRunning("");
    }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <p className="eyebrow mb-1">Threat Simulation Lab</p>
          <h1>Attack defense in motion</h1>
        </div>
      </div>

      <div className="row g-4">
        <div className="col-12">
          <p className="text-soft mb-0" style={{ fontSize: "0.82rem" }}>
            Note: these simulations demonstrate application-layer defenses (authentication
            lockout, parameterized queries, RBAC, digital signatures, OTP replay protection)
            running inside this app. Windows Defender Firewall operates independently at the
            network layer and is not expected to react to these simulations &mdash; it already
            allows the HTTPS connection carrying these requests, the same way it allows any
            other request to this app.
          </p>
        </div>

        <div className="col-lg-4">
          <div className="card h-100">
            <h2 className="section-title">Choose an attack</h2>
            <div className="d-grid gap-2">
              {attacks.map((attack) => (
                <button
                  key={attack.key}
                  className="btn btn-secondary"
                  onClick={() => runAttack(attack.key)}
                  disabled={running === attack.key}
                >
                  {running === attack.key ? "Running..." : attack.label}
                </button>
              ))}
            </div>
            <button
              className="btn btn-outline mt-3"
              onClick={resetDemoTarget}
              disabled={resetting}
            >
              {resetting ? "Resetting..." : "Reset Demo Target Account"}
            </button>
            {resetMessage && (
              <div className="alert alert-success mt-3 mb-0">{resetMessage}</div>
            )}
            {error && (
              <div className="alert alert-danger mt-3 mb-0">{error}</div>
            )}
          </div>
        </div>

        <div className="col-lg-8">
          <div className="card h-100">
            <h2 className="section-title">Defense Sequence</h2>
            {data ? (
              <>
                <div className="pipeline-steps">
                  {data.sequence.slice(0, visibleCount).map((line, idx) => (
                    <div className="pipeline-step" key={`${line}-${idx}`}>
                      <div className="pipeline-step-title">{line}</div>
                    </div>
                  ))}
                </div>
                <div
                  className="alert alert-success"
                  style={{ marginTop: 18, marginBottom: 0 }}
                >
                  {data.title}: {data.result}
                </div>
              </>
            ) : (
              <p className="text-soft mb-0">
                Pick a simulation to see the response chain.
              </p>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
