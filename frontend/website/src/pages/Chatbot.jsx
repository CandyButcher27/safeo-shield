import { useCallback, useRef, useState } from "react";
import { runScan } from "../api";
import { ROLES, ROLE_BY_ID, inferSourceSystem } from "../chatbot/roles";
import { RoleResultView } from "../chatbot/ResultViews";
import {
  HOMOGRAPH_DEMO_URL,
  CHATGPT_DEMO_RESPONSE,
  buildSafeoDemoSummary,
} from "../chatbot/demoArtifact";
import "../styles/chatbot.css";

function ChatMessage({ role, children }) {
  return (
    <div className={`cb-msg ${role}`}>
      <div className="cb-msg-bubble">{children}</div>
    </div>
  );
}

export default function Chatbot() {
  const [roleId, setRoleId] = useState("non_technical");
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState([
    {
      id: "welcome",
      role: "assistant",
      text: "Paste anything you want SafeO to scan. I'll show the same forensic result tailored to your role.",
    },
  ]);
  const [loading, setLoading] = useState(false);
  const [demoScan, setDemoScan] = useState(null);
  const [showDemo, setShowDemo] = useState(false);
  const listRef = useRef(null);

  const role = ROLE_BY_ID[roleId];

  const appendMessage = useCallback((msg) => {
    setMessages((m) => [...m, { id: `${Date.now()}`, ...msg }]);
    setTimeout(() => {
      listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: "smooth" });
    }, 50);
  }, []);

  const handleScan = async (text) => {
    const payload = text.trim();
    if (!payload || loading) return;

    appendMessage({ role: "user", text: payload });
    setInput("");
    setLoading(true);

    try {
      const scan = await runScan(payload, {
        source_system: inferSourceSystem(roleId, payload),
        user_id: `chatbot_${roleId}`,
      });
      appendMessage({
        role: "assistant",
        scan,
        text: null,
      });
    } catch (err) {
      appendMessage({
        role: "assistant",
        text: `Scan failed: ${err.message}. Is the SafeO engine running on port 8001?`,
      });
    } finally {
      setLoading(false);
    }
  };

  const runHomographDemo = async () => {
    setShowDemo(true);
    setInput(HOMOGRAPH_DEMO_URL);
    setLoading(true);
    try {
      const scan = await runScan(HOMOGRAPH_DEMO_URL, { source_system: "url_scanner" });
      setDemoScan(scan);
      setMessages([
        { id: "demo-user", role: "user", text: HOMOGRAPH_DEMO_URL },
        { id: "demo-bot", role: "assistant", scan, text: null },
      ]);
    } catch (err) {
      setDemoScan(null);
      appendMessage({ role: "assistant", text: `Demo scan failed: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const safeoDemo = buildSafeoDemoSummary(demoScan);

  return (
    <div className="cb-page">
      <div className="cb-page-header">
        <div>
          <h2>SafeO Assistant</h2>
          <p>Same forensic engine for everyone — depth adapts to who's asking. Not a generic chatbot.</p>
        </div>
        <div className="cb-role-select">
          <label htmlFor="role">Your role</label>
          <select id="role" value={roleId} onChange={(e) => setRoleId(e.target.value)}>
            {ROLES.map((r) => (
              <option key={r.id} value={r.id}>{r.label}</option>
            ))}
          </select>
          <span className="cb-role-tagline">{role.tagline}</span>
        </div>
      </div>

      <div className="cb-demo-banner">
        <div>
          <strong>Demo: ChatGPT vs SafeO on IDN homograph phishing</strong>
          <p>Arabic-script look-alike URL that generic LLMs often call "valid"</p>
        </div>
        <button type="button" className="cb-demo-btn" onClick={runHomographDemo} disabled={loading}>
          Run homograph demo
        </button>
      </div>

      {showDemo && (
        <div className="cb-compare">
          <div className="cb-compare-panel chatgpt">
            <div className="cb-compare-title">{CHATGPT_DEMO_RESPONSE.title}</div>
            <div className="cb-compare-sub">{CHATGPT_DEMO_RESPONSE.subtitle}</div>
            <div className={`cb-compare-verdict ${CHATGPT_DEMO_RESPONSE.verdictClass}`}>
              {CHATGPT_DEMO_RESPONSE.verdict}
            </div>
            <ul>
              {CHATGPT_DEMO_RESPONSE.body.map((line, i) => <li key={i}>{line}</li>)}
            </ul>
          </div>
          <div className="cb-compare-panel safeo">
            <div className="cb-compare-title">{safeoDemo?.title || "SafeO"}</div>
            <div className="cb-compare-sub">{safeoDemo?.subtitle || "Live scan result"}</div>
            {safeoDemo ? (
              <>
                <div className={`cb-compare-verdict ${safeoDemo.verdictClass}`}>{safeoDemo.verdict}</div>
                <p><strong>Host:</strong> <code>{safeoDemo.host || HOMOGRAPH_DEMO_URL}</code></p>
                {safeoDemo.flagged_chars.length > 0 && (
                  <table className="cb-table compact">
                    <thead><tr><th>Char</th><th>Codepoint</th><th>Looks like</th></tr></thead>
                    <tbody>
                      {safeoDemo.flagged_chars.map((f, i) => (
                        <tr key={i}><td><code>{f.char}</code></td><td>{f.codepoint}</td><td>{f.looks_like}</td></tr>
                      ))}
                    </tbody>
                  </table>
                )}
                <div className="cb-tags">
                  {(safeoDemo.mitre || []).map((t) => <span key={t} className="cb-tag mitre">{t}</span>)}
                </div>
                <p className="cb-muted">Risk {Math.round((safeoDemo.risk_score || 0) * 100)}% · Uncertainty {safeoDemo.uncertainty_score}</p>
                <code className="cb-hash">{safeoDemo.audit_hash}</code>
              </>
            ) : (
              <p className="cb-muted">Run the demo to populate SafeO side…</p>
            )}
          </div>
        </div>
      )}

      <div className="cb-chat">
        <div className="cb-messages" ref={listRef}>
          {messages.map((m) => (
            <ChatMessage key={m.id} role={m.role}>
              {m.scan ? <RoleResultView roleId={roleId} scan={m.scan} /> : m.text}
            </ChatMessage>
          ))}
          {loading && (
            <ChatMessage role="assistant">
              <span className="cb-loading">Scanning with Tier 1 pipeline…</span>
            </ChatMessage>
          )}
        </div>

        <form
          className="cb-input-row"
          onSubmit={(e) => {
            e.preventDefault();
            handleScan(input);
          }}
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={role.placeholder}
            disabled={loading}
          />
          <button type="submit" disabled={loading || !input.trim()}>Scan</button>
        </form>
        <p className="cb-input-hint">{role.inputHint}</p>
      </div>
    </div>
  );
}
