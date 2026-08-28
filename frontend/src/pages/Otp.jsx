import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../context/AuthContext";
import { homeForRole } from "../App";

export default function Otp() {
  const navigate = useNavigate();
  const location = useLocation();
  const { setUser } = useAuth();
  const [otp, setOtp] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [accessGranted, setAccessGranted] = useState(false);
  const demoOtp = location.state?.demoOtp;

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const data = await api.verifyOtp(otp);
      setUser(data.user);
      setAccessGranted(true);
      setTimeout(() => {
        // Accounts still on a shipped default password go straight to Settings
        // to choose their own, rather than into the application.
        if (data.user.mustChangePassword) {
          navigate("/settings", { replace: true });
        } else {
          navigate(homeForRole(data.user.role));
        }
      }, 700);
    } catch (err) {
      setError(err.message);
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-shell">
      <div className="card auth-card" style={{ textAlign: "center" }}>
        <p className="eyebrow">Step 2 of 2</p>
        <h1 style={{ marginTop: 8, marginBottom: 8 }}>Enter OTP</h1>
        <p className="text-soft" style={{ marginBottom: 20 }}>
          Use the 6-digit one-time password generated after login.
        </p>

        <div className="pipeline-inline">
          <span className="badge badge-security on">✔ Password Verified</span>
          <span>→</span>
          <span className="badge badge-security on">Generate OTP</span>
          <span>→</span>
          <span className={`badge badge-security ${accessGranted ? "on" : "off"}`}>
            {accessGranted ? "✔ Access Granted" : "OTP Verified"}
          </span>
        </div>

        {demoOtp && (
          <div className="alert alert-info">
            Demo OTP generated: <strong>{demoOtp}</strong>
          </div>
        )}
        {error && <div className="alert alert-danger">{error}</div>}
        {accessGranted && <div className="alert alert-success">✔ Access Granted — redirecting...</div>}

        <form onSubmit={handleSubmit}>
          <div className="field">
            <input
              className="otp-input"
              maxLength={6}
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              required
            />
          </div>
          <button className="btn btn-primary btn-block" type="submit" disabled={submitting}>
            {submitting ? "Verifying..." : "Verify OTP"}
          </button>
        </form>
      </div>
    </div>
  );
}
