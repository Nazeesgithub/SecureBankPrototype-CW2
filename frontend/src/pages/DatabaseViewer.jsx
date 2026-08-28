import { useEffect, useState } from "react";
import { api } from "../api";

export default function DatabaseViewer() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .securityDatabase()
      .then(setData)
      .catch((err) => setError(err.message));
  }, []);

  return (
    <>
      <div className="topbar">
        <div>
          <p className="eyebrow mb-1">Database Viewer</p>
          <h1>Encrypted SQLite records</h1>
        </div>
      </div>

      {error && <div className="alert alert-danger">{error}</div>}

      <div className="card mb-4">
        <h2 className="section-title">Summary</h2>
        {data ? (
          <div className="security-detail-panel">
            <div>
              <span className="text-soft">Users</span>
              <div className="mono">{data.summary.users}</div>
            </div>
            <div>
              <span className="text-soft">Transactions</span>
              <div className="mono">{data.summary.transactions}</div>
            </div>
            <div>
              <span className="text-soft">Backup</span>
              <div className="mono">{data.summary.backup}</div>
            </div>
            <div>
              <span className="text-soft">Encryption</span>
              <div className="mono">AES-256-GCM</div>
            </div>
          </div>
        ) : (
          <p className="text-soft mb-0">Loading database summary...</p>
        )}
      </div>

      <div className="card mb-4">
        <h2 className="section-title">Users</h2>
        <div className="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Current Account Balance</th>
                <th>Digital Wallet Balance</th>
                <th>Last Login</th>
              </tr>
            </thead>
            <tbody>
              {data?.users?.map((user) => (
                <tr key={user.id}>
                  <td>{user.username}</td>
                  <td>{user.role}</td>
                  <td>LKR {Number(user.currentBalance).toFixed(2)}</td>
                  <td>LKR {Number(user.walletBalance).toFixed(2)}</td>
                  <td>{user.lastLogin || "N/A"}</td>
                </tr>
              )) || (
                <tr>
                  <td colSpan={5} className="text-soft text-center">
                    Loading records...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <h2 className="section-title">Recent Transactions</h2>
        <div className="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Sender</th>
                <th>Receiver</th>
                <th>Status</th>
                <th>Encrypted Amount</th>
              </tr>
            </thead>
            <tbody>
              {data?.transactions?.map((tx) => (
                <tr key={tx.id}>
                  <td>{tx.sender}</td>
                  <td>{tx.receiver}</td>
                  <td>{tx.status}</td>
                  <td className="mono breakable">{tx.encryptedAmount}</td>
                </tr>
              )) || (
                <tr>
                  <td colSpan={4} className="text-soft text-center">
                    Loading records...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
