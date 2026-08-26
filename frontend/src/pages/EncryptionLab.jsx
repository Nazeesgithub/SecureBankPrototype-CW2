import { useState } from "react";
import { api } from "../api";

const initialForm = {
  receiver: "demo-account",
  amount: "5000",
  message: "Transfer Rs.5000",
};

export default function EncryptionLab() {
  const [form, setForm] = useState(initialForm);
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [visibleSteps, setVisibleSteps] = useState(0);

  function update(field) {
    return (event) =>
      setForm((prev) => ({ ...prev, [field]: event.target.value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    setVisibleSteps(0);
    try {
      const response = await api.securityEncrypt(form);
      setData(response);
      response.pipeline.forEach((_, idx) => {
        setTimeout(
          () => setVisibleSteps((prev) => Math.max(prev, idx + 1)),
          idx * 300,
        );
      });
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
          <p className="eyebrow mb-1">Encryption Laboratory</p>
          <h1>Watch the crypto pipeline</h1>
        </div>
      </div>

      <div className="row g-4">
        <div className="col-lg-5">
          <div className="card h-100">
            <div className="helper-box">
              Enter a message and watch the platform produce plaintext, hash,
              ciphertext, encrypted AES key, signature, transport, and storage
              values.
            </div>
            {error && <div className="alert alert-danger">{error}</div>}
            <form onSubmit={handleSubmit}>
              <div className="field">
                <label htmlFor="receiver">Receiver</label>
                <input
                  id="receiver"
                  value={form.receiver}
                  onChange={update("receiver")}
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="amount">Amount</label>
                <input
                  id="amount"
                  value={form.amount}
                  onChange={update("amount")}
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="message">Message</label>
                <textarea
                  id="message"
                  rows={3}
                  value={form.message}
                  onChange={update("message")}
                  required
                />
              </div>
              <button
                className="btn btn-primary btn-block"
                type="submit"
                disabled={submitting}
              >
                {submitting ? "Encrypting..." : "Encrypt"}
              </button>
            </form>
          </div>
        </div>

        <div className="col-lg-7">
          <div className="card h-100">
            <h2 className="section-title">Output</h2>
            {data ? (
              <>
                <div className="encryption-flow">
                  {data.pipeline.slice(0, visibleSteps).map((step) => (
                    <div className="encryption-flow-item" key={step.step}>
                      <span className="text-soft">{step.title}</span>
                      <div className="mono breakable">{step.value}</div>
                    </div>
                  ))}
                </div>
                <div
                  className="security-detail-panel"
                  style={{ marginTop: 18 }}
                >
                  <div>
                    <span className="text-soft">Plaintext</span>
                    <div className="mono breakable">
                      {data.monitor.plaintext}
                    </div>
                  </div>
                  <div>
                    <span className="text-soft">Ciphertext</span>
                    <div className="mono breakable">
                      {data.monitor.ciphertext}
                    </div>
                  </div>
                  <div>
                    <span className="text-soft">Encrypted AES Key</span>
                    <div className="mono breakable">
                      {data.monitor.encryptedAesKey}
                    </div>
                  </div>
                  <div>
                    <span className="text-soft">Signature</span>
                    <div className="mono breakable">
                      {data.monitor.signature}
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <p className="text-soft mb-0">
                Run a sample encryption to populate the monitor.
              </p>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
