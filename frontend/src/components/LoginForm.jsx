import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { api } from "../api";

const COPY = {
  customer: {
    title: "Sign in",
    subtitle: "Enter your username, then verify with a one-time code.",
  },
  staff: {
    title: "Staff sign in",
    subtitle: "Restricted to Security and Admin roles. Verify with a one-time code.",
  },
};

export default function LoginForm() {
  const navigate = useNavigate();
  const [mode, setMode] = useState("customer");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [passwordVerified, setPasswordVerified] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const data = await api.login({ username, password, portal: mode === "staff" ? "staff" : "customer" });
      setPasswordVerified(true);
      setTimeout(() => {
        navigate("/otp", { state: { demoOtp: data.demoOtp } });
      }, 700);
    } catch (err) {
      setError(err.message);
      setSubmitting(false);
    }
  }

  const copy = COPY[mode];

  return (
    <div className="auth-shell auth-shell-split">
      <div className="auth-split">
        <div className="auth-brand-panel">
          <div className="auth-brand-mark">S</div>
          <h2>
            Banking, held to a<br />higher standard.
          </h2>
          <p>
            Every session on SecureBank is encrypted end to end and verified
            before it touches your account.
          </p>
          <div className="auth-brand-spacer" />
          <div className="auth-brand-features">
            <div className="auth-brand-feature">
              <span className="auth-brand-feature-label">
                <span className="auth-brand-feature-dot" />
                Session encrypted
              </span>
              <span className="auth-brand-feature-value">TLS 1.3</span>
            </div>
            <div className="auth-brand-feature">
              <span className="auth-brand-feature-label">
                <span className="auth-brand-feature-dot" />
                Identity verification
              </span>
              <span className="auth-brand-feature-value">Password + OTP</span>
            </div>
          </div>
        </div>

        <div className="auth-form-panel">
          <div className="auth-tabs">
            <button
              type="button"
              className={`auth-tab ${mode === "customer" ? "active" : ""}`}
              onClick={() => setMode("customer")}
            >
              Customer
            </button>
            <button
              type="button"
              className={`auth-tab ${mode === "staff" ? "active" : ""}`}
              onClick={() => setMode("staff")}
            >
              Staff and admin
            </button>
          </div>

          <div className="auth-card" style={{ boxShadow: "none", border: "none", padding: 0 }}>
            <h1 style={{ marginBottom: 8 }}>{copy.title}</h1>
            <p className="text-soft" style={{ marginBottom: 24 }}>
              {copy.subtitle}
            </p>

            {error && <div className="alert alert-danger">{error}</div>}

            {passwordVerified && (
              <div className="alert alert-success">✔ Password Verified (scrypt) — redirecting to OTP...</div>
            )}

            <form onSubmit={handleSubmit}>
              <div className="field">
                <label htmlFor="username">Username</label>
                <input
                  id="username"
                  placeholder="your.username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              <button className="btn btn-primary btn-block" type="submit" disabled={submitting}>
                {submitting ? "Verifying..." : "Continue to verification"}
              </button>
            </form>

            {mode === "customer" && (
              <p className="text-soft" style={{ marginTop: 20, marginBottom: 0, textAlign: "center" }}>
                No account? <Link to="/register">Open one</Link>
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
