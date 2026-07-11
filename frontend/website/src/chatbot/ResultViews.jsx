function verdictColor(decision) {
  if (decision === "BLOCK") return "unsafe";
  if (decision === "WARN") return "warn";
  return "safe";
}

function plainVerdict(decision) {
  if (decision === "BLOCK") return "UNSAFE";
  if (decision === "WARN") return "USE CAUTION";
  return "SAFE";
}

export function NonTechnicalView({ scan }) {
  const v = plainVerdict(scan.decision);
  const main = scan.explanations?.[0]
    || (scan.decision === "BLOCK"
      ? "This input matches known attack patterns. Do not open or submit it."
      : "No serious threats detected in this input.");

  return (
    <div className="cb-result cb-result-simple">
      <div className={`cb-verdict-big ${verdictColor(scan.decision)}`}>{v}</div>
      <p className="cb-plain">{main}</p>
      {scan.url_analysis?.homograph_detected && (
        <p className="cb-plain warn">
          The link uses look-alike characters designed to trick you into thinking it's a trusted site.
        </p>
      )}
    </div>
  );
}

export function SecurityAnalystView({ scan }) {
  const ge = scan.graph_evidence || {};
  return (
    <div className="cb-result cb-result-analyst">
      <div className="cb-result-header">
        <span className={`cb-pill ${verdictColor(scan.decision)}`}>{scan.decision}</span>
        <span>Risk {Math.round((scan.risk_score || 0) * 100)}%</span>
        <span>Uncertainty {scan.uncertainty_score ?? "—"}</span>
        <span>Tier {scan.tier_used}</span>
      </div>

      {ge.mitre_techniques?.length > 0 && (
        <section>
          <h4>MITRE ATT&CK</h4>
          <div className="cb-tags">
            {ge.mitre_techniques.map((t) => (
              <span key={t} className="cb-tag mitre">{t}</span>
            ))}
          </div>
          <p className="cb-muted">{ge.description}</p>
        </section>
      )}

      <section>
        <h4>Per-pattern evidence</h4>
        <ul className="cb-evidence-list">
          {(scan.matched_patterns || []).map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      </section>

      {scan.url_analysis?.flagged_chars?.length > 0 && (
        <section>
          <h4>Flagged Unicode characters</h4>
          <table className="cb-table">
            <thead>
              <tr><th>Char</th><th>Codepoint</th><th>Resembles</th><th>Script</th></tr>
            </thead>
            <tbody>
              {scan.url_analysis.flagged_chars.map((f, i) => (
                <tr key={i}>
                  <td><code>{f.char}</code></td>
                  <td>{f.codepoint}</td>
                  <td>{f.looks_like}</td>
                  <td>{f.script}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section>
        <h4>Explanations</h4>
        <ul className="cb-evidence-list">
          {(scan.explanations || []).map((e, i) => <li key={i}>{e}</li>)}
        </ul>
      </section>

      <div className="cb-audit">
        <span>Audit hash</span>
        <code>{scan.audit_hash || "—"}</code>
      </div>
      <div className="cb-audit">
        <span>Scan ID</span>
        <code>{scan.scan_id}</code>
      </div>
    </div>
  );
}

export function ErpManagerView({ scan }) {
  const erpPatterns = (scan.matched_patterns || []).filter((p) =>
    /erp_|fraud|invoice|wire|vendor|privilege/i.test(p)
  );
  const hasErp = erpPatterns.length > 0;

  return (
    <div className="cb-result cb-result-erp">
      <div className={`cb-verdict-big ${verdictColor(scan.decision)}`}>
        {scan.decision === "BLOCK" ? "Hold transaction" : scan.decision === "WARN" ? "Review required" : "Clear to process"}
      </div>
      <p className="cb-plain">
        {hasErp
          ? "This memo matches ERP fraud or policy-risk indicators."
          : scan.decision === "BLOCK"
            ? "This content is too risky to persist in Odoo without analyst review."
            : "No critical ERP fraud signals in this memo."}
      </p>
      <div className="cb-erp-grid">
        <div><label>Risk score</label><strong>{Math.round((scan.risk_score || 0) * 100)}%</strong></div>
        <div><label>Decision</label><strong>{scan.decision}</strong></div>
        <div><label>Attack class</label><strong>{scan.attack_class || "—"}</strong></div>
      </div>
      {erpPatterns.length > 0 && (
        <section>
          <h4>Business-risk signals</h4>
          <ul className="cb-evidence-list">{erpPatterns.map((p) => <li key={p}>{p}</li>)}</ul>
        </section>
      )}
      {(scan.explanations || []).slice(0, 3).map((e, i) => (
        <p key={i} className="cb-muted">{e}</p>
      ))}
    </div>
  );
}

export function DeveloperView({ scan }) {
  return (
    <div className="cb-result cb-result-dev">
      <div className="cb-result-header">
        <span className={`cb-pill ${verdictColor(scan.decision)}`}>{scan.decision}</span>
        <span>score={scan.risk_score}</span>
        <span>threshold={scan.block_threshold}</span>
        <span>tier={scan.tier_used}</span>
      </div>
      <pre className="cb-json">{JSON.stringify({
        scan_id: scan.scan_id,
        decision: scan.decision,
        risk_score: scan.risk_score,
        attack_class: scan.attack_class,
        matched_patterns: scan.matched_patterns,
        script_detected: scan.script_detected,
        url_analysis: scan.url_analysis,
        graph_evidence: scan.graph_evidence,
      }, null, 2)}</pre>
    </div>
  );
}

export function RoleResultView({ roleId, scan }) {
  if (!scan) return null;
  switch (roleId) {
    case "security_analyst": return <SecurityAnalystView scan={scan} />;
    case "erp_manager": return <ErpManagerView scan={scan} />;
    case "developer": return <DeveloperView scan={scan} />;
    default: return <NonTechnicalView scan={scan} />;
  }
}
