import { useEffect, useState } from "react";
import { api } from "../api";

export default function Admin() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [backupMessage, setBackupMessage] = useState("");
  const [backingUp, setBackingUp] = useState(false);

  function load() {
    api
      .adminOverview()
      .then(setData)
      .catch((err) => setError(err.message));
  }

  useEffect(load, []);

  async function handleBackup() {
    setBackingUp(true);
    setBackupMessage("");
    try {
      const res = await api.securityBackup();
      setBackupMessage(res.message);
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBackingUp(false);
    }
  }

  if (error) return <div className="alert alert-danger">{error}</div>;
  if (!data) return null;

  const { users, transactions, logLines, securityDashboard } = data;

  const dashboardTiles = [
    { label: "Firewall", value: securityDashboard.firewall, ok: false },
    { label: "HTTPS", value: securityDashboard.https, ok: securityDashboard.https === "Active" },
    { label: "TLS", value: securityDashboard.tls, ok: securityDashboard.tls === "Enabled" },
    { label: "AES", value: securityDashboard.aes, ok: true },
    { label: "RSA", value: securityDashboard.rsa, ok: true },
    { label: "Digital Signature", value: securityDashboard.digitalSignature, ok: true },
    { label: "OTP", value: securityDashboard.otp, ok: true },
    { label: "Database Backup", value: securityDashboard.databaseBackup, ok: securityDashboard.databaseBackup === "Completed" },
    { label: "Logs", value: `${securityDashboard.logEvents} events`, ok: true },
  ];

  return (
    <>
      <div className="topbar">
        <h1>Admin Panel</h1>
        <button className="btn btn-primary" onClick={handleBackup} disabled={backingUp}>
          {backingUp ? "Backing up..." : "Backup Database"}
        </button>
      </div>

      {backupMessage && <div className="alert alert-success">{backupMessage}</div>}

      <div className="card" style={{ marginBottom: 24 }}>
        <h2 className="section-title">Security Dashboard</h2>
        <div className="admin-security-grid">
          {dashboardTiles.map((tile) => (
            <div className="admin-security-tile" key={tile.label}>
              <span className="text-soft" style={{ fontSize: "0.78rem" }}>
                {tile.label}
              </span>
              <span className={`badge badge-security ${tile.ok ? "on" : "off"}`}>{tile.value}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="row g-4">
        <div className="col-lg-6">
          <div className="card h-100">
            <h2 className="section-title">Users</h2>
            <div className="table-responsive">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Last Login</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td>{u.id}</td>
                      <td>{u.username}</td>
                      <td className="text-capitalize">{u.role}</td>
                      <td>{u.lastLogin || "N/A"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="col-lg-6">
          <div className="card h-100">
            <h2 className="section-title">Transactions</h2>
            <div className="table-responsive">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Sender</th>
                    <th>Receiver</th>
                    <th>Date</th>
                  </tr>
                </thead>
                <tbody>
                  {transactions.map((tx) => (
                    <tr key={tx.id}>
                      <td>{tx.id}</td>
                      <td>{tx.sender}</td>
                      <td>{tx.receiver}</td>
                      <td>{tx.date}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="col-12">
          <div className="card">
            <h2 className="section-title">Recent Security Logs</h2>
            <div className="log-box">
              {logLines.length > 0 ? (
                logLines.map((line, idx) => <div key={idx}>{line}</div>)
              ) : (
                <div>No logs found.</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
