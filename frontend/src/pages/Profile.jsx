import { useEffect, useState } from "react";
import { Wifi } from "lucide-react";
import { api } from "../api";

function maskAccountNumber(accountNumber) {
  if (!accountNumber) return "";
  return `**** **** ${accountNumber.slice(-4)}`;
}

export default function Profile() {
  const [data, setData] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [dashboardError, setDashboardError] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .profile()
      .then(setData)
      .catch((err) => setError(err.message));
    api
      .dashboard()
      .then(setDashboard)
      .catch((err) => setDashboardError(err.message));
  }, []);

  if (error) return <div className="alert alert-danger">{error}</div>;
  if (!data) return null;

  const { user, certificateStatus } = data;
  const isAdmin = user.role === "admin";
  const security = dashboard?.securityStatus || {};

  return (
    <>
      <div className="topbar">
        <h1>{isAdmin ? "Administrator Profile" : "User Profile"}</h1>
      </div>

      <div className="row g-4">
        <div className="col-lg-6">
          <div className="card">
            <h2 className="section-title">Account Details</h2>
            {isAdmin && (
              <div className="helper-box">
                This account has administrator privileges: full access to users, transactions, security
                logs, and database backups via the Admin Panel.
              </div>
            )}
            <dl className="row mb-0">
              <dt className="col-sm-4 text-soft">Name</dt>
              <dd className="col-sm-8">{user.name}</dd>

              <dt className="col-sm-4 text-soft">Username</dt>
              <dd className="col-sm-8">{user.username}</dd>

              <dt className="col-sm-4 text-soft">Email</dt>
              <dd className="col-sm-8">{user.email}</dd>

              <dt className="col-sm-4 text-soft">Account Number</dt>
              <dd className="col-sm-8">{user.accountNumber}</dd>

              <dt className="col-sm-4 text-soft">Role</dt>
              <dd className="col-sm-8 text-capitalize">{user.role}</dd>

              <dt className="col-sm-4 text-soft">Last Login</dt>
              <dd className="col-sm-8">{user.lastLogin || "N/A"}</dd>
            </dl>

            {!isAdmin && (
              <div className="profile-card-preview">
                <div className="profile-card-preview-top">
                  <span className="eyebrow">SecureBank</span>
                  <Wifi size={18} strokeWidth={1.5} className="dash-balance-wifi" aria-hidden="true" />
                </div>
                <div className="dash-balance-chip" aria-hidden="true" />
                <div className="profile-card-preview-number mono">
                  {maskAccountNumber(user.accountNumber)}
                </div>
                <div className="profile-card-preview-name">{user.name}</div>
              </div>
            )}
          </div>
        </div>

        <div className="col-lg-6">
          <div className="card mb-4">
            <h2 className="section-title">Digital Certificate</h2>
            <div className="security-badge-grid" style={{ marginBottom: 12 }}>
              <span className="badge badge-security on">✔ RSA 2048</span>
              <span className="badge badge-security on">✔ TLS Active</span>
              <span className="badge badge-security on">✔ Certificate Verified</span>
            </div>
            <p className="mb-0 text-soft">{certificateStatus}</p>
          </div>

          {!isAdmin && (
            <div className="card mb-4">
              <h2 className="section-title">Account Balances</h2>
              {dashboardError && (
                <div className="alert alert-danger mb-3">{dashboardError}</div>
              )}
              <dl className="row mb-0">
                <dt className="col-sm-6 text-soft">Current Account</dt>
                <dd className="col-sm-6 mono">
                  {dashboard ? `LKR ${dashboard.user.currentBalance.toFixed(2)}` : dashboardError ? "Unavailable" : "Loading..."}
                </dd>

                <dt className="col-sm-6 text-soft">Digital Wallet</dt>
                <dd className="col-sm-6 mono">
                  {dashboard ? `LKR ${dashboard.user.walletBalance.toFixed(2)}` : dashboardError ? "Unavailable" : "Loading..."}
                </dd>
              </dl>
            </div>
          )}

          <div className="card">
            <h2 className="section-title">Security &amp; Access</h2>
            <dl className="row mb-0">
              <dt className="col-sm-6 text-soft">Session</dt>
              <dd className="col-sm-6">
                {dashboard ? (
                  <span className={`badge ${security.sessionAuthenticated ? "badge-success" : "badge-danger"}`}>
                    {security.sessionAuthenticated ? "Authenticated" : "Not authenticated"}
                  </span>
                ) : (
                  <span className="badge">Unavailable</span>
                )}
              </dd>

              <dt className="col-sm-6 text-soft">Connection</dt>
              <dd className="col-sm-6">
                {dashboard ? (
                  <span className={`badge ${security.httpsConnection ? "badge-success" : "badge-danger"}`}>
                    {security.httpsConnection ? "HTTPS" : "Not secure"}
                  </span>
                ) : (
                  <span className="badge">Unavailable</span>
                )}
              </dd>

              <dt className="col-sm-6 text-soft">Password Hashing</dt>
              <dd className="col-sm-6">
                <span className="badge badge-success">{security.passwordHashing || "scrypt"}</span>
              </dd>

              <dt className="col-sm-6 text-soft">Login Verification</dt>
              <dd className="col-sm-6">
                <span className="badge badge-success">{security.otpAuthentication || "TOTP"}</span>
              </dd>
            </dl>
          </div>
        </div>
      </div>
    </>
  );
}
