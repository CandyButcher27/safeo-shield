import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { createJiraTicket, fetchFullStats } from "../api";

export default function Logs() {
  const [searchParams] = useSearchParams();
  const source = (searchParams.get("source") || "").toLowerCase();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [jiraByRequest, setJiraByRequest] = useState({});

  const loadRows = useCallback(() => {
    return fetchFullStats()
      .then((stats) => {
        let list = stats?.recent_decisions || [];
        if (source) {
          list = list.filter((r) => {
            const s = (r.source_system || "").toLowerCase();
            if (source === "odoo") return s === "odoo" || s.includes("odoo");
            return s === source || s.includes(source);
          });
        }
        setRows(list);
        setJiraByRequest((prev) => {
          const next = { ...prev };
          for (const row of list) {
            const id = row.request_id;
            if (!id) continue;
            if (row.jira_ticket_key && !next[id]?.ticket_key) {
              next[id] = {
                ticket_key: row.jira_ticket_key,
                ticket_url: row.jira_ticket_url,
                loading: false,
                error: "",
              };
            }
          }
          return next;
        });
      })
      .catch(() => setRows([]));
  }, [source]);

  useEffect(() => {
    setLoading(true);
    loadRows().finally(() => setLoading(false));
  }, [loadRows]);

  async function handleCreateTicket(requestId) {
    setJiraByRequest((prev) => ({
      ...prev,
      [requestId]: { ...prev[requestId], loading: true, error: "" },
    }));
    try {
      const data = await createJiraTicket(requestId);
      setJiraByRequest((prev) => ({
        ...prev,
        [requestId]: {
          ticket_key: data.ticket_key,
          ticket_url: data.ticket_url,
          loading: false,
          error: "",
        },
      }));
    } catch (err) {
      setJiraByRequest((prev) => ({
        ...prev,
        [requestId]: {
          ...prev[requestId],
          loading: false,
          error: err.message || "Ticket creation failed",
        },
      }));
    }
  }

  return (
    <div className="safeo-page">
      <div className="safeo-page-header">
        <h2>Risk Engine Logs</h2>
        <p>
          {source
            ? `Showing decisions from source: ${source}`
            : "All recent decisions from the SafeO engine"}
        </p>
      </div>
      <div className="safeo-card">
        {loading ? (
          <p className="safeo-muted">Loading…</p>
        ) : !rows.length ? (
          <p className="safeo-muted">No log entries for this filter.</p>
        ) : (
          <table className="safeo-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Request ID</th>
                <th>Source</th>
                <th>Tier</th>
                <th>Risk</th>
                <th>Decision</th>
                <th>Jira Ticket</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const requestId = row.request_id || "";
                const jira = jiraByRequest[requestId] || {};
                return (
                  <tr key={requestId || row.time}>
                    <td>{formatTime(row.time)}</td>
                    <td className="mono">{(requestId || "").slice(0, 12)}</td>
                    <td>{row.source_system || "—"}</td>
                    <td>T{row.tier_used || 1}</td>
                    <td>{Math.round((row.risk_score || 0) * 100)}%</td>
                    <td>
                      <span className={`decision-badge ${decisionClass(row.decision)}`}>{row.decision}</span>
                    </td>
                    <td className="safeo-jira-cell">
                      {jira.ticket_key ? (
                        <a
                          href={jira.ticket_url}
                          className="safeo-jira-link"
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          {jira.ticket_key}
                        </a>
                      ) : (
                        <>
                          <button
                            type="button"
                            className="safeo-jira-btn"
                            disabled={!requestId || jira.loading}
                            onClick={() => handleCreateTicket(requestId)}
                          >
                            {jira.loading ? "Creating…" : "Create Ticket"}
                          </button>
                          {jira.error ? (
                            <span className="safeo-jira-err" title={jira.error}>
                              {jira.error.length > 48 ? `${jira.error.slice(0, 48)}…` : jira.error}
                            </span>
                          ) : null}
                        </>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function formatTime(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts;
    return d.toLocaleString();
  } catch {
    return ts;
  }
}

function decisionClass(d) {
  const v = String(d || "").toLowerCase();
  if (v === "block") return "block";
  if (v === "warn") return "warn";
  return "allow";
}
