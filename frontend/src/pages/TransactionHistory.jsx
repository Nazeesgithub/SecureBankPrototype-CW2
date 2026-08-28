import { Fragment, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

// Failures paired with the action that resolves them.
function remedyFor(err) {
  const message = err?.message || "The transaction history could not be loaded.";
  if (err?.status === 401 || /authentication required/i.test(message)) {
    return "Your session has timed out. Sign in again to see your transaction history.";
  }
  return `${message} Reload the page; if it keeps happening, sign out and back in.`;
}

export default function TransactionHistory() {
  const [transactions, setTransactions] = useState(null);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    api
      .transactions()
      .then((data) => setTransactions(data.transactions))
      .catch((err) => setError(remedyFor(err)));
  }, []);

  // A record whose signature no longer matches its stored fields. This is the
  // only condition in the interface that is allowed to be red.
  const tamperedCount = (transactions || []).filter(
    (tx) => tx.signatureValid === false,
  ).length;

  return (
    <>
      <div className="topbar">
        <div>
          <p className="eyebrow mb-1">Ledger</p>
          <h1>Transaction History</h1>
        </div>
      </div>

      {/* Announced to assistive technology, and placed above the table so it is
          seen before the rows it refers to. */}
      {tamperedCount > 0 && (
        <div className="alert-alarm" role="alert">
          <span className="alert-alarm-icon" aria-hidden="true">
            &#9888;
          </span>
          <div>
            <div className="alert-alarm-title">
              {tamperedCount === 1
                ? "1 record failed its integrity check"
                : `${tamperedCount} records failed their integrity check`}
            </div>
            <div className="alert-alarm-body">
              The stored data for {tamperedCount === 1 ? "this record" : "these records"}{" "}
              no longer matches the digital signature written when the transfer was
              made, so the amount shown cannot be trusted and has been withheld.
              This means the database was modified outside the application. Report
              it to your security team and do not act on the affected{" "}
              {tamperedCount === 1 ? "row" : "rows"}; every check is recorded in the
              security log as a SIGNATURE_INVALID event.
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}

      <div className="card">
        <div className="table-responsive">
          <table className="table-stack">
            <thead>
              <tr>
                <th>Date</th>
                <th>Direction</th>
                <th>Counterparty</th>
                <th>Amount</th>
                <th>Encrypted Amount</th>
                <th>Integrity</th>
                <th>
                  <span className="visually-hidden-label">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {transactions && transactions.length > 0 ? (
                transactions.map((tx, idx) => {
                  const tampered = tx.signatureValid === false;
                  return (
                    <Fragment key={idx}>
                      <tr className={tampered ? "row-tampered" : undefined}>
                        <td data-label="Date">{tx.date}</td>
                        <td data-label="Direction">
                          {/* Direction is information, not judgement. It used to
                              use badge-danger, which meant an outgoing transfer
                              looked exactly like a failure. */}
                          <span
                            className={`badge ${
                              tx.direction === "sent" ? "badge-outgoing" : "badge-incoming"
                            }`}
                          >
                            <span aria-hidden="true">
                              {tx.direction === "sent" ? "↑" : "↓"}
                            </span>
                            {tx.direction === "sent" ? "Sent" : "Received"}
                          </span>
                        </td>
                        <td data-label="Counterparty">{tx.counterparty}</td>
                        <td
                          data-label="Amount"
                          className={`mono ${
                            tx.direction === "sent"
                              ? "timeline-amount-out"
                              : "timeline-amount-in"
                          }`}
                        >
                          {tx.amount === null || tx.amount === undefined ? (
                            <span className="amount-unverifiable">
                              Unverifiable
                            </span>
                          ) : (
                            <>
                              {tx.direction === "sent" ? "-" : "+"}LKR{" "}
                              {tx.amount.toFixed(2)}
                            </>
                          )}
                        </td>
                        <td data-label="Encrypted Amount" className="mono">
                          {tx.encryptedAmount.slice(0, 20)}...
                        </td>
                        <td data-label="Integrity">
                          {tampered ? (
                            <span className="badge badge-alarm">
                              <span aria-hidden="true">&#9888;</span>
                              {tx.signatureStatus || "TAMPERED"}
                            </span>
                          ) : (
                            <span className="badge badge-success">
                              <span aria-hidden="true">&#10003;</span>
                              Verified
                            </span>
                          )}
                        </td>
                        <td data-label="Details">
                          <button
                            className="btn btn-secondary"
                            style={{
                              padding: "var(--sp-1) var(--sp-3)",
                              fontSize: "var(--fs-caption)",
                            }}
                            aria-expanded={expanded === idx}
                            onClick={() => setExpanded(expanded === idx ? null : idx)}
                          >
                            {expanded === idx ? "Hide security" : "View security"}
                          </button>
                        </td>
                      </tr>
                      {expanded === idx && (
                        <tr className={tampered ? "row-tampered" : undefined}>
                          <td colSpan={7} className="cell-full">
                            <div className="security-detail-panel">
                              <div>
                                <span className="text-soft">AES</span>
                                <div>{tx.security.aes}</div>
                              </div>
                              <div>
                                <span className="text-soft">RSA</span>
                                <div>{tx.security.rsa}</div>
                                <div className="mono">
                                  {tx.security.encryptedAesKeyPreview}
                                </div>
                              </div>
                              <div>
                                <span className="text-soft">Signature</span>
                                <div
                                  className={
                                    tampered ? "amount-unverifiable" : undefined
                                  }
                                >
                                  {tx.security.signature}
                                </div>
                                <div
                                  className="text-soft"
                                  style={{ fontSize: "var(--fs-micro)" }}
                                >
                                  {tx.security.signatureDetail}
                                </div>
                                <div className="mono">
                                  {tx.security.signaturePreview}
                                </div>
                              </div>
                              <div>
                                <span className="text-soft">Hash</span>
                                <div>SHA-256 (covered by the signature)</div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="cell-full">
                    {/* An empty state that names the next action. */}
                    <div className="empty-state">
                      {transactions ? (
                        <>
                          <div className="empty-state-title">No transactions yet</div>
                          <p className="empty-state-body">
                            Once you send or receive money, every transfer appears
                            here with its signature checked on the way out of the
                            database.{" "}
                            <Link to="/transfer">Make your first transfer</Link> to
                            see the cryptographic pipeline run.
                          </p>
                        </>
                      ) : (
                        <>
                          <div className="empty-state-title">Loading your history</div>
                          <p className="empty-state-body">
                            Verifying the digital signature on each stored record.
                          </p>
                        </>
                      )}
                    </div>
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
