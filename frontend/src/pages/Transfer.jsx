import { useEffect, useState } from "react";
import { useLocation, Link } from "react-router-dom";
import { api } from "../api";

const initialForm = { receiver: "", amount: "", description: "", source: "card" };

export default function Transfer() {
  const location = useLocation();
  const [form, setForm] = useState(() => ({
    ...initialForm,
    receiver: location.state?.receiver || "",
  }));
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [monitor, setMonitor] = useState(null);
  const [pipeline, setPipeline] = useState(null);
  const [visibleSteps, setVisibleSteps] = useState(0);
  const [balances, setBalances] = useState(null);

  useEffect(() => {
    api
      .dashboard()
      .then((data) =>
        setBalances({ currentBalance: data.user.currentBalance, walletBalance: data.user.walletBalance })
      )
      .catch(() => {});
  }, []);

  function update(field) {
    return (event) =>
      setForm((prev) => ({ ...prev, [field]: event.target.value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setSuccess("");
    setSubmitting(true);
    setMonitor(null);
    setPipeline(null);
    setVisibleSteps(0);
    try {
      const data = await api.transfer(form);
      setSuccess(data.message);
      setMonitor(data.securityMonitor || null);
      setBalances({ currentBalance: data.currentBalance, walletBalance: data.walletBalance });
      const steps = data.securityPipeline?.steps || [];
      setPipeline(steps);
      steps.forEach((_, idx) => {
        setTimeout(
          () => setVisibleSteps((prev) => Math.max(prev, idx + 1)),
          idx * 350,
        );
      });
      setForm(initialForm);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <p className="eyebrow mb-1">Secure Transfer Pipeline</p>
          <h1>Transfer Money</h1>
        </div>
      </div>

      <div className="row g-4">
        <div className="col-lg-8">
          <div className="card h-100">
            <div className="helper-box">
              Watch the full transfer path: plaintext, SHA-256 hash, AES encryption,
              RSA key wrapping, digital signature, TLS transport, and encrypted
              storage.
            </div>

            {error && <div className="alert alert-danger">{error}</div>}
            {success && <div className="alert alert-success">{success}</div>}

            <form onSubmit={handleSubmit}>
              <div className="field">
                <label>Transfer From</label>
                <div className="source-toggle">
                  <button
                    type="button"
                    className={`source-toggle-option ${form.source === "card" ? "active" : ""}`}
                    onClick={() => setForm((prev) => ({ ...prev, source: "card" }))}
                  >
                    Current Account
                    {balances && (
                      <span className="source-toggle-balance">LKR {balances.currentBalance.toFixed(2)}</span>
                    )}
                  </button>
                  <button
                    type="button"
                    className={`source-toggle-option ${form.source === "wallet" ? "active" : ""}`}
                    onClick={() => setForm((prev) => ({ ...prev, source: "wallet" }))}
                  >
                    Digital Wallet
                    {balances && (
                      <span className="source-toggle-balance">LKR {balances.walletBalance.toFixed(2)}</span>
                    )}
                  </button>
                </div>
              </div>

              <div className="row g-3">
                <div className="col-md-6">
                  <div className="field">
                    <label htmlFor="receiver">Receiver Account Number</label>
                    <input
                      id="receiver"
                      className="mono"
                      placeholder="12-digit account number"
                      value={form.receiver}
                      onChange={update("receiver")}
                      maxLength={12}
                      required
                    />
                  </div>
                </div>
                <div className="col-md-6">
                  <div className="field">
                    <label htmlFor="amount">Amount (LKR)</label>
                    <input
                      id="amount"
                      type="number"
                      min="0"
                      step="0.01"
                      value={form.amount}
                      onChange={update("amount")}
                      required
                    />
                  </div>
                </div>
                <div className="col-12">
                  <div className="field">
                    <label htmlFor="description">Description</label>
                    <textarea
                      id="description"
                      rows={3}
                      value={form.description}
                      onChange={update("description")}
                      required
                    />
                  </div>
                </div>
              </div>
              <div className="d-flex gap-2">
                <button
                  className="btn btn-primary"
                  type="submit"
                  disabled={submitting}
                >
                  {submitting ? "Encrypting..." : "Transfer"}
                </button>
                <Link to="/dashboard" className="btn btn-secondary">
                  Cancel
                </Link>
              </div>
            </form>
          </div>
        </div>

        <div className="col-lg-4">
          <div className="card h-100">
            <h2 className="section-title">Before You Transfer</h2>
            <ul className="transfer-tips">
              <li>Transfers require the receiver's 12-digit account number, found on their Profile page.</li>
              <li>You can send from either your Current Account or Digital Wallet — choose the source above.</li>
              <li>Transfers to an unrecognized account number are rejected before any funds move.</li>
              <li>Every transfer is SHA-256 hashed, AES-encrypted, RSA key-wrapped, and digitally signed.</li>
            </ul>
            {balances && (
              <div className="transfer-tips-balances">
                <div>
                  <span className="text-soft">Current Account Balance</span>
                  <div className="mono">LKR {balances.currentBalance.toFixed(2)}</div>
                </div>
                <div>
                  <span className="text-soft">Digital Wallet Balance</span>
                  <div className="mono">LKR {balances.walletBalance.toFixed(2)}</div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {monitor && (
        <div className="card" style={{ maxWidth: 640, marginTop: 24 }}>
          <h2 className="section-title">Live Encryption Monitor</h2>
          <div className="encryption-flow">
            <div className="encryption-flow-item">
              <span className="text-soft">Plaintext</span>
              <div className="mono breakable">{monitor.plaintext}</div>
            </div>
            <div className="encryption-flow-arrow">↓ SHA-256</div>
            <div className="encryption-flow-item">
              <span className="text-soft">Hash</span>
              <div className="mono breakable">{monitor.hash}</div>
            </div>
            <div className="encryption-flow-arrow">↓ AES</div>
            <div className="encryption-flow-item">
              <span className="text-soft">Ciphertext</span>
              <div className="mono breakable">{monitor.ciphertext}</div>
            </div>
            <div className="encryption-flow-arrow">↓ RSA Key Encrypt</div>
            <div className="encryption-flow-item">
              <span className="text-soft">Encrypted AES Key</span>
              <div className="mono breakable">{monitor.encryptedAesKey}</div>
            </div>
            <div className="encryption-flow-arrow">↓ Digital Signature</div>
            <div className="encryption-flow-item">
              <span className="text-soft">Signature</span>
              <div className="mono breakable">{monitor.signature}</div>
            </div>
            <div className="encryption-flow-arrow">↓ TLS</div>
            <div className="encryption-flow-item">
              <span className="text-soft">Transport</span>
              <div className="mono">{monitor.transport}</div>
            </div>
            <div className="encryption-flow-arrow">↓ Database</div>
            <div className="encryption-flow-item">
              <span className="text-soft">Storage</span>
              <div className="mono">{monitor.storage}</div>
            </div>
          </div>
        </div>
      )}

      {pipeline && (
        <div className="card" style={{ maxWidth: 640, marginTop: 24 }}>
          <h2 className="section-title">Transaction Security Processing</h2>
          <div className="pipeline-steps">
            {pipeline.slice(0, visibleSteps).map((step) => (
              <div className="pipeline-step" key={step.step}>
                <div className="pipeline-step-header">
                  <span className="pipeline-step-number">Step {step.step}</span>
                  <span className="badge badge-security on">
                    {step.status === "verified" || step.status === "completed"
                      ? "✔"
                      : "…"}{" "}
                    {step.algorithm}
                  </span>
                </div>
                <div className="pipeline-step-title">{step.title}</div>
                {step.value && <div className="mono">{step.value}</div>}
              </div>
            ))}
          </div>
          {visibleSteps === pipeline.length && (
            <div
              className="alert alert-success"
              style={{ marginTop: 16, marginBottom: 0 }}
            >
              Transfer Successful — all security checks passed.
            </div>
          )}
        </div>
      )}
    </>
  );
}
