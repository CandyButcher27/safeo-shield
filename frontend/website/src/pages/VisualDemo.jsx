import { useState } from "react";
import { getApiKey } from "../utils/connections";
import "../styles/visual.css";

const API = import.meta.env.VITE_API_URL || "/api";

const DEMO_URL = "https://ọpen-ạccess.com/login";
const DEMO_GITHUB = "https://github.com/pallets/flask";

export default function VisualDemo() {
  const [input, setInput] = useState(DEMO_URL);
  const [inputType, setInputType] = useState("url");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const runScan = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${API}/v1/scan/visual`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${getApiKey()}`,
        },
        body: JSON.stringify({ input, input_type: inputType, context: { source_system: inputType } }),
      });
      if (!res.ok) throw new Error(`Scan failed (${res.status})`);
      setResult(await res.json());
    } catch (e) {
      setError(e.message);
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const imgUrl = (path) => (path ? path : null);

  const shots = result?.visual_evidence?.screenshots?.length
    ? result.visual_evidence.screenshots
    : result?.screenshot_url
      ? [result.screenshot_url]
      : [];

  return (
    <div className="vis-page">
      <div className="vis-header">
        <h2>Visual Evidence Capture</h2>
        <p>Headless screenshot + annotated highlight regions from SafeO Tier 1 scan.</p>
      </div>

      <div className="vis-controls">
        <select value={inputType} onChange={(e) => setInputType(e.target.value)}>
          <option value="url">URL</option>
          <option value="github">GitHub repo</option>
        </select>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={inputType === "url" ? "https://..." : "https://github.com/..."}
        />
        <button type="button" onClick={() => { setInput(DEMO_URL); setInputType("url"); }}>Homograph demo</button>
        <button type="button" onClick={() => { setInput(DEMO_GITHUB); setInputType("github"); }}>GitHub demo</button>
        <button type="button" className="primary" onClick={runScan} disabled={loading}>
          {loading ? "Capturing…" : "Scan + capture"}
        </button>
      </div>

      {error && <div className="vis-error">{error}</div>}

      {result && (
        <div className="vis-result">
          <div className="vis-meta">
            <span className={`vis-decision ${result.decision?.toLowerCase()}`}>{result.decision}</span>
            <span>Risk {Math.round((result.risk_score || 0) * 100)}%</span>
            <span>Scan {result.scan_id}</span>
          </div>
          <div className="vis-patterns">
            {(result.matched_patterns || []).map((p) => (
              <span key={p} className="vis-tag">{p}</span>
            ))}
          </div>
          {(result.highlighted_regions || []).length > 0 && (
            <ul className="vis-regions">
              {result.highlighted_regions.map((r, i) => (
                <li key={i}>{r.label} <em>({r.severity})</em></li>
              ))}
            </ul>
          )}
          <div className="vis-shots">
            {shots.map((s) => (
              <a key={s} href={imgUrl(s)} target="_blank" rel="noreferrer">
                <img src={imgUrl(s)} alt="Annotated screenshot" />
              </a>
            ))}
          </div>
          {result.visual_evidence?.github?.findings?.length > 0 && (
            <div className="vis-gh-findings">
              <h4>GitHub line findings</h4>
              <ul>
                {result.visual_evidence.github.findings.map((f, i) => (
                  <li key={i}>
                    <code>{f.file_path}:{f.line_number}</code> — {f.category} ({f.severity})
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
