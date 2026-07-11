/*
 * DEMO FLOW:
 * 1. Open http://localhost:5174 — standalone SafeO dashboard
 * 2. Click "Connect to Your ERP →" in nav or banner on dashboard
 * 3. /connect page loads — Odoo card shows green "Connected" badge
 *    with today's scan count and last blocked timestamp
 * 4. Click "Open SafeO in Odoo →"
 * 5. New tab opens at http://127.0.0.1:8069/odoo/safeo
 * 6. Judges see the same SafeO UI now running inside a real ERP
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import Drawer from "../components/Drawer";
import Modal from "../components/Modal";
import { useToast } from "../components/Toast";
import { fetchFullStats, fetchOdooHealth, odooMetricsFromStats, testEndpoint } from "../api";
import { getApiKey, markErpConnected, seedOdooIfReachable } from "../utils/connections";

const ODOO_SAFEO_URL = "http://127.0.0.1:8069/odoo/safeo";
const BACKEND_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8001";

const ODOO_SETUP = `cd /path/to/odoo
./venv/bin/python odoo-bin -c odoo.conf --http-port=8069

Install module: SafeO — ERP Risk Decision Engine (securec_odoo)
Set Settings → SafeO → API URL to ${BACKEND_URL}`;

function ErpCard({ icon, name, status, statusClass, children, primary, secondary }) {
  return (
    <div className="safeo-erp-card">
      <div className="safeo-erp-card-top">
        <div className="safeo-erp-icon">{icon}</div>
        <div>
          <h3>{name}</h3>
          <span className={`safeo-status-badge ${statusClass}`}>{status}</span>
        </div>
      </div>
      <div className="safeo-erp-card-body">{children}</div>
      <div className="safeo-erp-card-actions">
        {primary}
        {secondary}
      </div>
    </div>
  );
}

export default function Connect() {
  const { showToast } = useToast();
  const [odooUp, setOdooUp] = useState(false);
  const [odooMetrics, setOdooMetrics] = useState({ lastScan: null, blockedToday: 0 });
  const [drawer, setDrawer] = useState(null);
  const [setupOpen, setSetupOpen] = useState(false);
  const [testUrl, setTestUrl] = useState("");
  const [testResult, setTestResult] = useState(null);
  const apiKey = getApiKey();

  useEffect(() => {
    const poll = async () => {
      const up = await fetchOdooHealth();
      setOdooUp(up);
      seedOdooIfReachable(up);
      try {
        const stats = await fetchFullStats();
        setOdooMetrics(odooMetricsFromStats(stats));
      } catch {
        /* metrics optional */
      }
    };
    poll();
    const t = setInterval(poll, 8000);
    return () => clearInterval(t);
  }, []);

  const openOdoo = () => {
    showToast("Opening SafeO in Odoo...");
    window.open(ODOO_SAFEO_URL, "_blank", "noopener,noreferrer");
  };

  const closeDrawer = () => {
    setDrawer(null);
    setTestUrl("");
    setTestResult(null);
  };

  const runTest = async (erpId) => {
    if (!testUrl.trim()) {
      setTestResult({ ok: false, msg: "Enter an endpoint URL" });
      return;
    }
    const ok = await testEndpoint(testUrl.trim());
    setTestResult({ ok, msg: ok ? "Connection successful" : "Could not reach endpoint" });
    if (ok) markErpConnected(erpId, { endpoint: testUrl.trim() });
  };

  const copyKey = () => {
    navigator.clipboard?.writeText(apiKey);
    showToast("API key copied");
  };

  return (
    <div className="safeo-page">
      <div className="safeo-page-header">
        <h2>Connect to Your ERP System</h2>
        <p>
          SafeO works as a security layer in front of any ERP. Select a connected system to open it,
          or add a new integration.
        </p>
      </div>

      <div className="safeo-erp-grid">
        <ErpCard
          icon="Od"
          name="Odoo"
          status={odooUp ? "● Connected" : "○ Not running"}
          statusClass={odooUp ? "connected" : "idle"}
          primary={
            odooUp ? (
              <button type="button" className="sim-run-btn" onClick={openOdoo}>
                Open SafeO in Odoo →
              </button>
            ) : (
              <button type="button" className="sim-run-btn" onClick={() => setSetupOpen(true)}>
                Setup instructions
              </button>
            )
          }
          secondary={
            odooUp ? (
              <Link to="/logs?source=odoo" className="safeo-btn-muted">
                View Odoo logs
              </Link>
            ) : null
          }
        >
          {odooUp ? (
            <>
              <p>Last scan: {formatTime(odooMetrics.lastScan)}</p>
              <p>Blocked today: {odooMetrics.blockedToday}</p>
            </>
          ) : (
            <p className="safeo-muted">Start Odoo to connect</p>
          )}
        </ErpCard>

        <ErpCard
          icon="SAP"
          name="SAP"
          status="○ Not connected"
          statusClass="idle"
          primary={
            <button type="button" className="sim-run-btn" onClick={() => setDrawer("sap")}>
              Connect via REST API
            </button>
          }
        >
          <p className="safeo-muted">Enterprise SAP integration via SafeO REST API</p>
        </ErpCard>

        <ErpCard
          icon="SF"
          name="Salesforce"
          status="○ Not connected"
          statusClass="idle"
          primary={
            <button type="button" className="sim-run-btn" onClick={() => setDrawer("salesforce")}>
              Connect via Apex
            </button>
          }
        >
          <p className="safeo-muted">Salesforce Apex trigger integration</p>
        </ErpCard>

        <ErpCard
          icon="{ }"
          name="Custom ERP"
          status="○ Not connected"
          statusClass="idle"
          primary={
            <button type="button" className="sim-run-btn" onClick={() => setDrawer("custom")}>
              Connect via Python SDK
            </button>
          }
        >
          <p className="safeo-muted">Any system using the SafeO Python SDK</p>
        </ErpCard>

        <ErpCard
          icon="↯"
          name="Webhook (Any System)"
          status="○ Not connected"
          statusClass="idle"
          primary={
            <button type="button" className="sim-run-btn" onClick={() => setDrawer("webhook")}>
              Connect via Webhook
            </button>
          }
        >
          <p className="safeo-muted">Forward payloads to SafeO from any HTTP client</p>
        </ErpCard>
      </div>

      <Modal open={setupOpen} title="Start Odoo" onClose={() => setSetupOpen(false)}>
        <p className="safeo-muted">Run these commands from your Odoo install directory:</p>
        <pre className="safeo-code">{ODOO_SETUP}</pre>
        <p className="safeo-muted">Then open <a href={ODOO_SAFEO_URL} target="_blank" rel="noreferrer">{ODOO_SAFEO_URL}</a></p>
      </Modal>

      <Drawer open={drawer === "sap"} title="Connect SAP to SafeO" onClose={closeDrawer}>
        <p><strong>Step 1:</strong> Copy your API key</p>
        <div className="safeo-key-row">
          <code>{apiKey}</code>
          <button type="button" className="safeo-refresh-btn" onClick={copyKey}>Copy</button>
        </div>
        <p><strong>Step 2:</strong> Add this to your SAP system</p>
        <pre className="safeo-code">{`curl -X POST ${BACKEND_URL}/v1/scan \\
  -H "Authorization: Bearer ${apiKey}" \\
  -H "Content-Type: application/json" \\
  -d '{"input":"{{payload}}","context":{"source_system":"sap","user_id":"{{user}}"}}'`}</pre>
        <p><strong>Step 3:</strong> Test connection</p>
        <input
          className="safeo-input"
          placeholder="https://your-sap-gateway/health"
          value={testUrl}
          onChange={(e) => setTestUrl(e.target.value)}
        />
        <button type="button" className="sim-run-btn" onClick={() => runTest("sap")}>Test</button>
        {testResult && <p className={testResult.ok ? "safeo-ok" : "safeo-err"}>{testResult.msg}</p>}
      </Drawer>

      <Drawer open={drawer === "salesforce"} title="Connect Salesforce to SafeO" onClose={closeDrawer}>
        <p><strong>Step 1:</strong> Copy your API key</p>
        <div className="safeo-key-row">
          <code>{apiKey}</code>
          <button type="button" className="safeo-refresh-btn" onClick={copyKey}>Copy</button>
        </div>
        <p><strong>Step 2:</strong> Apex trigger snippet</p>
        <pre className="safeo-code">{`HttpRequest req = new HttpRequest();
req.setEndpoint('${BACKEND_URL}/v1/scan');
req.setMethod('POST');
req.setHeader('Authorization', 'Bearer ${apiKey}');
req.setHeader('Content-Type', 'application/json');
req.setBody('{"input":"' + input + '","context":{"source_system":"salesforce"}}');
HttpResponse res = new Http().send(req);`}</pre>
        <p><strong>Step 3:</strong> Test connection</p>
        <input className="safeo-input" placeholder="Salesforce endpoint URL" value={testUrl} onChange={(e) => setTestUrl(e.target.value)} />
        <button type="button" className="sim-run-btn" onClick={() => runTest("salesforce")}>Test</button>
        {testResult && <p className={testResult.ok ? "safeo-ok" : "safeo-err"}>{testResult.msg}</p>}
      </Drawer>

      <Drawer open={drawer === "custom"} title="Connect Custom ERP to SafeO" onClose={closeDrawer}>
        <p><strong>Step 1:</strong> Copy your API key</p>
        <div className="safeo-key-row">
          <code>{apiKey}</code>
          <button type="button" className="safeo-refresh-btn" onClick={copyKey}>Copy</button>
        </div>
        <p><strong>Step 2:</strong> Python SDK</p>
        <pre className="safeo-code">{`from safeo_sdk import SafeOClient

client = SafeOClient(api_key="${apiKey}", base_url="${BACKEND_URL}")
result = client.scan("user input", source_system="custom_erp")
print(result.decision, result.risk_score)`}</pre>
        <p><strong>Step 3:</strong> Test connection</p>
        <input className="safeo-input" placeholder="http://your-erp/health" value={testUrl} onChange={(e) => setTestUrl(e.target.value)} />
        <button type="button" className="sim-run-btn" onClick={() => runTest("custom")}>Test</button>
        {testResult && <p className={testResult.ok ? "safeo-ok" : "safeo-err"}>{testResult.msg}</p>}
      </Drawer>

      <Drawer open={drawer === "webhook"} title="Connect via Webhook" onClose={closeDrawer}>
        <p><strong>Step 1:</strong> Copy your API key</p>
        <div className="safeo-key-row">
          <code>{apiKey}</code>
          <button type="button" className="safeo-refresh-btn" onClick={copyKey}>Copy</button>
        </div>
        <p><strong>Step 2:</strong> Webhook curl</p>
        <pre className="safeo-code">{`curl -X POST ${BACKEND_URL}/v1/scan \\
  -H "Authorization: Bearer ${apiKey}" \\
  -H "Content-Type: application/json" \\
  -d '{"input":"PAYLOAD_FROM_YOUR_SYSTEM","context":{"source_system":"webhook"}}'`}</pre>
        <p><strong>Step 3:</strong> Test connection</p>
        <input className="safeo-input" placeholder="Webhook receiver URL" value={testUrl} onChange={(e) => setTestUrl(e.target.value)} />
        <button type="button" className="sim-run-btn" onClick={() => runTest("webhook")}>Test</button>
        {testResult && <p className={testResult.ok ? "safeo-ok" : "safeo-err"}>{testResult.msg}</p>}
      </Drawer>
    </div>
  );
}

function formatTime(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return "—";
    return d.toLocaleString();
  } catch {
    return "—";
  }
}
