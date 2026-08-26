import { useEffect, useState } from "react";
import { api } from "../api";

export default function TransactionHistory() {
  const [transactions, setTransactions] = useState(null);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    api
      .transactions()
      .then((data) => setTransactions(data.transactions))
      .catch((err) => setError(err.message));
  }, []);

  return (
    <>
      <div className="topbar">
        <h1>Transaction History</h1>
      </div>

      <div className="card">
        {error && <div className="alert alert-danger">{error}</div>}
        <div className="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Date</th>
                <th>Direction</th>
                <th>Counterparty</th>
                <th>Amount</th>
                <th>Encrypted Amount</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {transactions && transactions.length > 0 ? (
                transactions.map((tx, idx) => (
                  <>
                    <tr key={idx}>
                      <td>{tx.date}</td>
                      <td>
                        <span className={`badge ${tx.direction === "sent" ? "badge-danger" : "badge-success"}`}>
                          {tx.direction === "sent" ? "Sent" : "Received"}
                        </span>
                      </td>
                      <td>{tx.counterparty}</td>
                      <td className={`mono ${tx.direction === "sent" ? "timeline-amount-out" : "timeline-amount-in"}`}>
                        {tx.direction === "sent" ? "-" : "+"}LKR {tx.amount.toFixed(2)}
                      </td>
                      <td className="mono">{tx.encryptedAmount.slice(0, 20)}...</td>
                      <td>
                        <span className="badge badge-success">{tx.status}</span>
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: "6px 12px", fontSize: "0.82rem" }}
                          onClick={() => setExpanded(expanded === idx ? null : idx)}
                        >
                          {expanded === idx ? "Hide Security" : "View Security"}
                        </button>
                      </td>
                    </tr>
                    {expanded === idx && (
                      <tr key={`${idx}-details`}>
                        <td colSpan={7}>
                          <div className="security-detail-panel">
                            <div>
                              <span className="text-soft">AES</span>
                              <div>{tx.security.aes}</div>
                            </div>
                            <div>
                              <span className="text-soft">RSA</span>
                              <div>{tx.security.rsa}</div>
                              <div className="mono">{tx.security.encryptedAesKeyPreview}</div>
                            </div>
                            <div>
                              <span className="text-soft">Signature</span>
                              <div>{tx.security.signature}</div>
                              <div className="mono">{tx.security.signaturePreview}</div>
                            </div>
                            <div>
                              <span className="text-soft">Hash</span>
                              <div>SHA-256 (via signature)</div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="text-center text-soft">
                    {transactions ? "No transaction records found." : "Loading..."}
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
