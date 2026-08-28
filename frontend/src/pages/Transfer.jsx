import { useEffect, useState } from "react";
import { useLocation, Link } from "react-router-dom";
import { api } from "../api";
import PipelineRail from "../components/PipelineRail";
import { usePrefersReducedMotion } from "../components/usePrefersReducedMotion";

const initialForm = { receiver: "", amount: "", description: "", source: "card" };

// Every failure the transfer endpoint can return, paired with the action that
// resolves it. An error that only reports a state leaves the user stuck.
function remedyFor(err) {
  const message = err?.message || "The transfer could not be completed.";
  if (/no account found/i.test(message)) {
    return `${message} Check the 12-digit account number with the recipient — it is shown on their dashboard.`;
  }
  if (/insufficient/i.test(message)) {
    return `${message} Lower the amount, or top up the wallet from your current account first.`;
  }
  if (/own account/i.test(message)) {
    return `${message} Enter the recipient's account number instead.`;
  }
  if (/positive number/i.test(message)) {
    return `${message} Enter an amount such as 250.00, using digits and at most two decimal places.`;
  }
  if (/csrf/i.test(message)) {
    return "Your session security token expired. Reload the page and try again.";
  }
  if (err?.status === 401 || /authentication required/i.test(message)) {
    return "Your session has timed out. Sign in again to continue.";
  }
  return `${message} If it keeps happening, sign out and back in, then retry.`;
}

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
  const reducedMotion = usePrefersReducedMotion();

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
      if (reducedMotion) {
        // No staged reveal: show the finished rail immediately.
        setVisibleSteps(steps.length);
      } else {
        steps.forEach((_, idx) => {
          setTimeout(
            () => setVisibleSteps((prev) => Math.max(prev, idx + 1)),
            idx * 260,
          );
        });
      }
      setForm(initialForm);
    } catch (err) {
      // Say what to do about it, not just what happened.
      setError(remedyFor(err));
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
        <div className="card" style={{ marginTop: "var(--sp-5)" }}>
          <div className="topbar" style={{ marginBottom: "var(--sp-2)" }}>
            <div>
              <p className="eyebrow mb-1">Proof of processing</p>
              <h2 className="section-title" style={{ marginBottom: 0 }}>
                Cryptographic pipeline
              </h2>
            </div>
          </div>
          <p className="text-soft" style={{ fontSize: "var(--fs-sm)", marginBottom: 0 }}>
            Each stage below ran on the server for this transfer. The values are the
            real hash, ciphertext, wrapped key and signature that were stored.
          </p>

          <PipelineRail steps={pipeline} visibleCount={visibleSteps} />

          {visibleSteps === pipeline.length && (
            <div
              className="alert alert-success"
              style={{ marginTop: "var(--sp-5)", marginBottom: 0 }}
            >
              Transfer complete — every stage of the pipeline succeeded and the
              signed record is stored.
            </div>
          )}
        </div>
      )}
    </>
  );
}
