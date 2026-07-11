import { CATALOG_BY_ID } from "./nodeCatalog";

function nodesByType(nodes) {
  const map = { input: [], detection: [], output: [], decision: [], control: [] };
  for (const n of nodes) {
    const cat = CATALOG_BY_ID[n.type]?.category;
    if (cat && map[cat]) map[cat].push(n);
  }
  return map;
}

function adjacency(edges) {
  const out = {};
  const inn = {};
  for (const e of edges) {
    out[e.from] = out[e.from] || [];
    out[e.from].push(e.to);
    inn[e.to] = inn[e.to] || [];
    inn[e.to].push(e.from);
  }
  return { out, inn };
}

export function validatePipeline(pipeline) {
  const errors = [];
  const warnings = [];
  const nodes = pipeline?.nodes || [];
  const edges = pipeline?.edges || [];
  const byType = nodesByType(nodes);
  const { out, inn } = adjacency(edges);

  const riskNodes = nodes.filter((n) => n.type === "risk_score");
  if (riskNodes.length !== 1) {
    errors.push("Pipeline must contain exactly one Risk score + decision node.");
  }

  if (byType.input.length < 1) {
    errors.push("Add at least one Input node.");
  }
  if (byType.output.length < 1) {
    errors.push("Add at least one Output node.");
  }

  const hasStart = nodes.some((n) => n.type === "start");
  const hasEnd = nodes.some((n) => n.type === "end");
  if (!hasStart) warnings.push("Consider adding a Start node.");
  if (!hasEnd) warnings.push("Consider adding an End node.");

  const riskId = riskNodes[0]?.id;
  if (riskId) {
    const inputsReachRisk = byType.input.some((n) => {
      const visited = new Set();
      const q = [n.id];
      while (q.length) {
        const cur = q.shift();
        if (cur === riskId) return true;
        if (visited.has(cur)) continue;
        visited.add(cur);
        for (const next of out[cur] || []) q.push(next);
      }
      return false;
    });
    if (!inputsReachRisk && byType.input.length) {
      errors.push("At least one Input node must connect to Risk score (directly or via Detection).");
    }

    const outputsFromRisk = byType.output.some((n) => (inn[n.id] || []).includes(riskId) || pathExists(out, riskId, n.id));
    if (!outputsFromRisk && byType.output.length) {
      errors.push("At least one Output node must be reachable from Risk score.");
    }
  }

  for (const n of nodes) {
    const meta = CATALOG_BY_ID[n.type];
    if (!meta) errors.push(`Unknown node type: ${n.type}`);
    if (meta?.status === "mock" && pipeline.observe_mode === false) {
      warnings.push(`${meta.label} is mock-only — pipeline may not execute that step in action mode.`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

function pathExists(out, from, to) {
  const visited = new Set();
  const q = [from];
  while (q.length) {
    const cur = q.shift();
    if (cur === to) return true;
    if (visited.has(cur)) continue;
    visited.add(cur);
    for (const next of out[cur] || []) q.push(next);
  }
  return false;
}
