import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Wifi, ShieldCheck, Lock, KeyRound, ScanFace } from "lucide-react";
import { api } from "../api";

function initials(name) {
  return name
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join("");
}

function maskAccountNumber(accountNumber) {
  if (!accountNumber) return "";
  return `**** **** ${accountNumber.slice(-4)}`;
}

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [revealAccount, setRevealAccount] = useState(false);
  const [topUpAmount, setTopUpAmount] = useState("");
  const [topUpError, setTopUpError] = useState("");
  const [topUpSuccess, setTopUpSuccess] = useState("");
  const [topUpSubmitting, setTopUpSubmitting] = useState(false);

  function loadDashboard() {
    return api
      .dashboard()
      .then(setData)
      .catch((err) => setError(err.message));
  }

  useEffect(() => {
    loadDashboard();
  }, []);

  async function handleTopUp(event) {
    event.preventDefault();
    setTopUpError("");
    setTopUpSuccess("");
    setTopUpSubmitting(true);
    try {
      await api.topUpWallet({ amount: topUpAmount });
      setTopUpSuccess("Wallet topped up successfully.");
      setTopUpAmount("");
      await loadDashboard();
    } catch (err) {
      setTopUpError(err.message);
    } finally {
      setTopUpSubmitting(false);
    }
  }

  const recentReceivers = useMemo(() => {
    if (!data) return [];
    const seen = new Map();
    for (const tx of data.recentTransactions) {
      if (!tx.receiverAccountNumber) continue;
      if (!seen.has(tx.receiverAccountNumber))
        seen.set(tx.receiverAccountNumber, tx.receiver);
    }
    return Array.from(seen.entries()).slice(0, 4);
  }, [data]);

  if (error) return <div className="alert alert-danger">{error}</div>;
  if (!data) return null;

  const security = data.securityStatus || {};

  return (
    <>
      <div className="topbar dash-topbar">
        <div>
          <p className="eyebrow mb-1">Welcome back</p>
          <h1>{data.user.name}</h1>
        </div>
        <Link to="/transfer" className="btn btn-primary">
          New Transfer
        </Link>
      </div>

      <div className="dash-grid">
        <div className="card dash-balance-card">
          <div className="dash-balance-top">
            <span className="eyebrow">Current Account Balance</span>
            <Wifi
              size={20}
              strokeWidth={1.5}
              className="dash-balance-wifi"
              aria-hidden="true"
            />
          </div>
          <div className="dash-balance-chip" aria-hidden="true" />
          <div className="dash-balance-amount mono">
            LKR {data.user.currentBalance.toFixed(2)}
          </div>
          <div className="dash-balance-meta">
            <div>
              <span className="text-soft">Account holder</span>
              <div>{data.user.name}</div>
            </div>
            <div>
              <span className="text-soft">Account number</span>
              <div
                className="mono"
                style={{ color: "inherit", cursor: "pointer" }}
                onClick={() => setRevealAccount((prev) => !prev)}
              >
                {revealAccount
                  ? data.user.accountNumber
                  : maskAccountNumber(data.user.accountNumber)}
              </div>
            </div>
          </div>
        </div>

        <div className="card dash-wallet-card">
          <div className="dash-balance-top">
            <span className="eyebrow">Digital Wallet Balance</span>
          </div>
          <div className="dash-wallet-amount mono">
            LKR {data.user.walletBalance.toFixed(2)}
          </div>
          <form onSubmit={handleTopUp} className="dash-topup-form">
            {topUpError && (
              <div className="alert alert-danger">{topUpError}</div>
            )}
            {topUpSuccess && (
              <div className="alert alert-success">{topUpSuccess}</div>
            )}
            <div className="dash-topup-row">
              <label htmlFor="wallet-topup-amount">Top-up amount (LKR)</label>
              <input
                id="wallet-topup-amount"
                type="number"
                min="0"
                step="0.01"
                placeholder="Enter amount"
                value={topUpAmount}
                onChange={(e) => setTopUpAmount(e.target.value)}
                required
              />
              <button
                className="btn btn-secondary"
                type="submit"
                disabled={topUpSubmitting}
              >
                {topUpSubmitting
                  ? "Processing..."
                  : "Top Up from Current Account"}
              </button>
            </div>
          </form>
        </div>

        <div className="card dash-profile-card">
          <h2 className="section-title">Profile</h2>
          <div className="dash-profile-row">
            <span className="text-soft">Email</span>
            <span>{data.user.email}</span>
          </div>
          <div className="dash-profile-row">
            <span className="text-soft">Role</span>
            <span style={{ textTransform: "capitalize" }}>
              {data.user.role}
            </span>
          </div>
          <div className="dash-profile-row">
            <span className="text-soft">Last login</span>
            <span>{data.user.lastLogin || "First login"}</span>
          </div>
          <Link
            to="/profile"
            className="btn btn-secondary btn-block"
            style={{ marginTop: 6, padding: "6px 12px", fontSize: "0.85rem" }}
          >
            View Profile
          </Link>
        </div>

        <div className="card dash-quick-card">
          <h2 className="section-title">Quick Transfer</h2>
          {recentReceivers.length === 0 ? (
            <p className="text-soft mb-0">No recent recipients yet.</p>
          ) : (
            <div className="dash-quick-list">
              {recentReceivers.map(([accountNumber, receiver]) => (
                <Link
                  key={accountNumber}
                  to="/transfer"
                  state={{ receiver: accountNumber }}
                  className="dash-quick-item"
                >
                  <span className="dash-quick-avatar">
                    {initials(receiver)}
                  </span>
                  <span>{receiver}</span>
                </Link>
              ))}
            </div>
          )}
        </div>

        <div className="card dash-security-card">
          <h2 className="section-title">Account Security</h2>
          <div className="dash-security-row">
            <span className="text-soft dash-security-label">
              <ShieldCheck size={15} strokeWidth={1.5} /> Session
            </span>
            <span
              className={`badge ${security.sessionAuthenticated ? "badge-success" : "badge-danger"}`}
            >
              {security.sessionAuthenticated
                ? "Authenticated"
                : "Not authenticated"}
            </span>
          </div>
          <div className="dash-security-row">
            <span className="text-soft dash-security-label">
              <Lock size={15} strokeWidth={1.5} /> Connection
            </span>
            <span
              className={`badge ${security.httpsConnection ? "badge-success" : "badge-danger"}`}
            >
              {security.httpsConnection ? "HTTPS" : "Not secure"}
            </span>
          </div>
          <div className="dash-security-row">
            <span className="text-soft dash-security-label">
              <KeyRound size={15} strokeWidth={1.5} /> Password hashing
            </span>
            <span className="badge badge-success">
              {security.passwordHashing || "scrypt"}
            </span>
          </div>
          <div className="dash-security-row">
            <span className="text-soft dash-security-label">
              <ScanFace size={15} strokeWidth={1.5} /> Login verification
            </span>
            <span className="badge badge-success">
              {security.otpAuthentication || "TOTP"}
            </span>
          </div>
        </div>

        <div className="card dash-transactions-card">
          <div className="d-flex justify-content-between align-items-center gap-3 mb-2">
            <h2 className="section-title mb-0">Recent Transactions</h2>
            <Link
              to="/history"
              className="btn btn-secondary"
              style={{ padding: "6px 12px" }}
            >
              View All
            </Link>
          </div>
          {data.recentTransactions.length === 0 ? (
            <p className="text-soft mb-0">No transactions yet.</p>
          ) : (
            <div className="timeline-list">
              {data.recentTransactions.map((tx, idx) => (
                <div className="timeline-row" key={`${tx.date}-${idx}`}>
                  <span className="timeline-time">{tx.date}</span>
                  <div className="timeline-body">
                    <strong>
                      {tx.direction === "sent"
                        ? `To ${tx.counterparty}`
                        : `From ${tx.counterparty}`}
                    </strong>
                    <div>
                      <span
                        className={`badge ${tx.status === "SUCCESS" ? "badge-success" : "badge-danger"}`}
                      >
                        {tx.status}
                      </span>
                    </div>
                  </div>
                  <div
                    className={`mono timeline-amount ${tx.direction === "sent" ? "timeline-amount-out" : "timeline-amount-in"}`}
                  >
                    {tx.amount === null || tx.amount === undefined
                      ? "unreadable"
                      : `${tx.direction === "sent" ? "-" : "+"}LKR ${tx.amount.toFixed(2)}`}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
