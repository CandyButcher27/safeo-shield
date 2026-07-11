import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchFullStats, fetchOdooHealth } from "../api";
import {
  countReachableConnections,
  loadConnections,
  seedOdooIfReachable,
} from "../utils/connections";

function StatCard({ label, value, accent }) {
  return (
    <div className={`safeo-stat-card${accent ? ` accent-${accent}` : ""}`}>
      <div className="safeo-stat-value">{value}</div>
      <div className="safeo-stat-label">{label}</div>
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [odooUp, setOdooUp] = useState(false);
  const [connectedCount, setConnectedCount] = useState(0);

  useEffect(() => {
    const refresh = async () => {
      try {
        const [full, odoo] = await Promise.all([fetchFullStats(), fetchOdooHealth()]);
        setStats(full);
        setOdooUp(odoo);
        const conns = seedOdooIfReachable(odoo);
        setConnectedCount(countReachableConnections(odoo, conns));
      } catch {
        setStats(null);
        const odoo = await fetchOdooHealth();
        setOdooUp(odoo);
        const conns = seedOdooIfReachable(odoo);
        setConnectedCount(countReachableConnections(odoo, conns));
      }
    };
    refresh();
    const t = setInterval(refresh, 8000);
    return () => clearInterval(t);
  }, []);

  const summary = stats?.summary || {};

  return (
    <div className="safeo-page">
      <div className="safeo-page-header">
        <h2>Business Risk Dashboard</h2>
        <p>Real-time business risk decisions — standalone view. Connect to Odoo for full ERP integration.</p>
      </div>

      <div className="safeo-stat-grid">
        <StatCard label="Total Scans" value={summary.total_scans ?? "—"} />
        <StatCard label="Blocked" value={summary.blocked ?? "—"} accent="danger" />
        <StatCard label="LLM Calls Saved" value={`${summary.llm_calls_saved_pct ?? 0}%`} />
        <StatCard label="Avg Risk Score" value={summary.avg_score ?? "—"} />
        <StatCard label="Open Investigations" value={summary.active_investigations ?? 0} />
      </div>

      <Link to="/connect" className="safeo-erp-banner">
        <span>
          SafeO is connected to <strong>{connectedCount}</strong> ERP system{connectedCount === 1 ? "" : "s"}
        </span>
        <span className="safeo-erp-banner-cta">Manage Connections →</span>
      </Link>

      <div className="safeo-card">
        <h3>Recent Decisions</h3>
        {!stats?.recent_decisions?.length ? (
          <p className="safeo-muted">No decisions yet. Run a scan from Sandbox or connect Odoo.</p>
        ) : (
          <table className="safeo-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Risk</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {stats.recent_decisions.slice(0, 8).map((row) => (
                <tr key={row.request_id || row.time}>
                  <td>{formatTime(row.time)}</td>
                  <td>{row.source_system || "—"}</td>
                  <td>{Math.round((row.risk_score || 0) * 100)}%</td>
                  <td>
                    <span className={`decision-badge ${decisionClass(row.decision)}`}>{row.decision}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="safeo-dashboard-footer">
        <div className="safeo-status-strip">
          <span>Backend API: {stats ? "Connected" : "Checking…"}</span>
          <span>Odoo ERP: {odooUp ? "Connected" : "Not running"}</span>
        </div>
      </div>
    </div>
  );
}

function formatTime(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts;
    return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
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
