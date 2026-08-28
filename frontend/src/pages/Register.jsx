import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { api } from "../api";

const initialForm = { name: "", username: "", email: "", password: "", confirmPassword: "" };

export default function Register() {
  const navigate = useNavigate();
  const [form, setForm] = useState(initialForm);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [hashResult, setHashResult] = useState(null);

  function update(field) {
    return (event) => setForm((prev) => ({ ...prev, [field]: event.target.value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const data = await api.register(form);
      setHashResult(data.security);
      setTimeout(() => navigate("/login", { state: { registered: true } }), 2200);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-shell">
      <div className="card auth-card" style={{ maxWidth: 520 }}>
        <p className="eyebrow">Secure Onboarding</p>
        <h1 style={{ marginTop: 8, marginBottom: 8 }}>Create your account</h1>
        <p className="text-soft" style={{ marginBottom: 24 }}>
          Passwords are hashed with salted scrypt and an OTP secret is generated per user.
        </p>

        {error && <div className="alert alert-danger">{error}</div>}

        {hashResult && (
          <div className="hash-demo">
            <div className="hash-demo-row">
              <span className="text-soft">Password</span>
              <span className="mono">••••••••</span>
            </div>
            <div className="hash-demo-arrow">↓ {hashResult.algorithm}</div>
            <div className="hash-demo-row">
              <span className="text-soft">Stored Hash</span>
              <span className="mono" style={{ wordBreak: "break-all" }}>{hashResult.passwordHash}</span>
            </div>
            <div className="alert alert-success" style={{ marginTop: 12, marginBottom: 0 }}>
              {hashResult.note}
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="grid grid-2">
            <div className="field">
              <label htmlFor="name">Full Name</label>
              <input id="name" value={form.name} onChange={update("name")} required />
            </div>
            <div className="field">
              <label htmlFor="username">Username</label>
              <input id="username" value={form.username} onChange={update("username")} required />
            </div>
          </div>
          <div className="field">
            <label htmlFor="email">Email</label>
            <input id="email" type="email" value={form.email} onChange={update("email")} required />
          </div>
          <div className="grid grid-2">
            <div className="field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                value={form.password}
                onChange={update("password")}
                required
              />
            </div>
            <div className="field">
              <label htmlFor="confirmPassword">Confirm Password</label>
              <input
                id="confirmPassword"
                type="password"
                value={form.confirmPassword}
                onChange={update("confirmPassword")}
                required
              />
            </div>
          </div>
          <div className="helper-box">
            Minimum 8 characters with upper, lower, number, and special character.
          </div>
          <button className="btn btn-primary btn-block" type="submit" disabled={submitting}>
            {submitting ? "Creating account..." : "Register"}
          </button>
        </form>

        <p className="text-soft" style={{ marginTop: 20, marginBottom: 0 }}>
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
