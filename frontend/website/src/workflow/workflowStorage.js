const STORAGE_KEY = "safeo_workflow_pipelines";
const API = import.meta.env.VITE_API_URL || "/api";

export function loadPipelines() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function savePipeline(pipeline) {
  const all = loadPipelines();
  const idx = all.findIndex((p) => p.id === pipeline.id);
  const next = { ...pipeline, updated_at: new Date().toISOString() };
  if (idx >= 0) all[idx] = next;
  else all.push({ ...next, created_at: next.updated_at });
  localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
  return next;
}

export async function savePipelineRemote(pipeline) {
  const res = await fetch(`${API}/workflows`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(pipeline),
  });
  if (!res.ok) throw new Error("Failed to save workflow");
  return res.json();
}

export async function runPipelineRemote(pipeline, sampleInput, context = {}) {
  const res = await fetch(`${API}/workflows/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      pipeline,
      sample_input: sampleInput,
      context,
      observe_mode: pipeline.observe_mode,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Pipeline run failed");
  }
  return res.json();
}
