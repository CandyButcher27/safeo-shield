import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  CATALOG_BY_ID,
  NODE_CATALOG,
  PALETTE_SECTIONS,
  emptyPipeline,
  examplePipeline,
  isComingSoon,
  isFixedNode,
  statusLabel,
} from "./nodeCatalog";
import { validatePipeline } from "./workflowValidation";
import { savePipeline, savePipelineRemote, runPipelineRemote, loadPipelines } from "./workflowStorage";
import "../styles/workflow.css";

const CANVAS_W = 3200;
const CANVAS_H = 1800;
const NODE_W = 210;
const NODE_H = 76;
const HANDLE_R = 9; // handle radius

/* ─── geometry ─────────────────────────────────────────────── */
function cubicPath(x1, y1, x2, y2) {
  const dx = Math.max(Math.abs(x2 - x1) * 0.5, 80);
  return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
}

function nodeRight(n)  { return { x: n.x + NODE_W, y: n.y + NODE_H / 2 }; }
function nodeLeft(n)   { return { x: n.x,          y: n.y + NODE_H / 2 }; }
function nodeBottom(n) { return { x: n.x + NODE_W / 2, y: n.y + NODE_H }; }
function nodeTop(n)    { return { x: n.x + NODE_W / 2, y: n.y }; }

/* pick best source/target sides based on relative position */
function bestPorts(from, to) {
  const fc = { x: from.x + NODE_W / 2, y: from.y + NODE_H / 2 };
  const tc = { x: to.x   + NODE_W / 2, y: to.y   + NODE_H / 2 };
  const dx = tc.x - fc.x;
  const dy = tc.y - fc.y;
  if (Math.abs(dx) >= Math.abs(dy)) {
    // mostly horizontal
    if (dx >= 0) return [nodeRight(from), nodeLeft(to)];
    return [nodeLeft(from), nodeRight(to)];
  }
  // mostly vertical
  if (dy >= 0) return [nodeBottom(from), nodeTop(to)];
  return [nodeTop(from), nodeBottom(to)];
}

/* ─── component ─────────────────────────────────────────────── */
export default function WorkflowBuilder() {
  const [pipeline, setPipeline] = useState(() => {
    const saved = loadPipelines();
    return saved.length ? saved[saved.length - 1] : emptyPipeline();
  });
  const [selectedId,     setSelectedId]     = useState(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState(null);
  const [connectDrag,    setConnectDrag]    = useState(null); // { fromId, sx, sy, cx, cy }
  const [draggingNode,   setDraggingNode]   = useState(null);
  const [dragOffset,     setDragOffset]     = useState({ x: 0, y: 0 });
  const [panning,        setPanning]        = useState(false);
  const [panStart,       setPanStart]       = useState({ x: 0, y: 0 });
  const [sampleInput,    setSampleInput]    = useState("١=١ UNION SELECT password FROM users");
  const [runResult,      setRunResult]      = useState(null);
  const [saveMsg,        setSaveMsg]        = useState("");
  const canvasRef = useRef(null);

  const validation = useMemo(() => validatePipeline(pipeline), [pipeline]);

  const updatePipeline = useCallback((patch) =>
    setPipeline((p) => ({ ...p, ...patch })), []);

  const screenToCanvas = useCallback((cx, cy) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return { x: 0, y: 0 };
    const { x: vx, y: vy, zoom: vz } = pipeline.viewport;
    return { x: (cx - rect.left - vx) / vz, y: (cy - rect.top - vy) / vz };
  }, [pipeline.viewport]);

  /* ─── canvas events ─────────────────────────────────────── */
  const onCanvasDrop = (e) => {
    e.preventDefault();
    const type = e.dataTransfer.getData("application/safeo-node");
    if (!type || !CATALOG_BY_ID[type] || isFixedNode(type)) return;
    const pos = screenToCanvas(e.clientX, e.clientY);
    const id = `n_${type}_${Date.now()}`;
    updatePipeline({ nodes: [...pipeline.nodes, { id, type, x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 }] });
  };

  const onNodePointerDown = (e, node) => {
    if (e.target.classList.contains("wf-handle")) return;
    e.stopPropagation();
    const pos = screenToCanvas(e.clientX, e.clientY);
    setDraggingNode(node.id);
    setDragOffset({ x: pos.x - node.x, y: pos.y - node.y });
    setSelectedId(node.id);
    setSelectedEdgeId(null);
    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const onCanvasPointerMove = (e) => {
    if (connectDrag) {
      const pos = screenToCanvas(e.clientX, e.clientY);
      setConnectDrag((d) => d ? { ...d, cx: pos.x, cy: pos.y } : null);
      return;
    }
    if (panning) {
      const { x: vx, y: vy, zoom: vz } = pipeline.viewport;
      updatePipeline({
        viewport: { x: vx + e.movementX, y: vy + e.movementY, zoom: vz },
      });
      return;
    }
    if (!draggingNode) return;
    const pos = screenToCanvas(e.clientX, e.clientY);
    updatePipeline({
      nodes: pipeline.nodes.map((n) =>
        n.id === draggingNode
          ? { ...n, x: Math.max(0, pos.x - dragOffset.x), y: Math.max(0, pos.y - dragOffset.y) }
          : n
      ),
    });
  };

  const onCanvasPointerUp = (e) => {
    if (connectDrag) {
      // hit-test: find the node the cursor is over and wire the edge
      const pos = screenToCanvas(e.clientX, e.clientY);
      const target = pipeline.nodes.find((n) => {
        if (n.id === connectDrag.fromId) return false;
        // generous hit zone includes the handle area outside the node
        return (
          pos.x >= n.x - 16 && pos.x <= n.x + NODE_W + 16 &&
          pos.y >= n.y - 16 && pos.y <= n.y + NODE_H + 16
        );
      });
      if (target) {
        const exists = pipeline.edges.some(
          (ed) => ed.from === connectDrag.fromId && ed.to === target.id
        );
        if (!exists) {
          updatePipeline({
            edges: [
              ...pipeline.edges,
              { id: `e_${Date.now()}`, from: connectDrag.fromId, to: target.id },
            ],
          });
        }
      }
      setConnectDrag(null);
    }
    setDraggingNode(null);
    setPanning(false);
    try { canvasRef.current?.releasePointerCapture(e.pointerId); } catch {}
  };

  const onCanvasPointerDown = (e) => {
    const cls = e.target.classList;
    // handle drags are initiated via onHandlePointerDown, which sets pointer capture itself
    if (cls.contains("wf-handle")) return;
    // edge hit area
    if (e.target.tagName.toLowerCase() === "path") return;
    // node body: node's own pointerDown handles it
    if (cls.contains("wf-node") || cls.contains("wf-node-inner") || cls.contains("wf-node-body") ||
        cls.contains("wf-node-title") || cls.contains("wf-node-sub") || cls.contains("wf-node-icon") ||
        cls.contains("wf-node-text") || cls.contains("pill") || cls.contains("wf-pills") || cls.contains("wf-soon-tag")) return;
    setPanning(true);
    setSelectedId(null);
    setSelectedEdgeId(null);
    canvasRef.current?.setPointerCapture(e.pointerId);
  };

  const onWheel = (e) => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 0.92 : 1.08;
    const { x: vx, y: vy, zoom: vz } = pipeline.viewport;
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const nextZoom = Math.min(2, Math.max(0.3, vz * factor));
    const scale = nextZoom / vz;
    updatePipeline({
      viewport: {
        x: mx - scale * (mx - vx),
        y: my - scale * (my - vy),
        zoom: nextZoom,
      },
    });
  };

  /* ─── handle drag-to-connect ────────────────────────────── */
  const onHandlePointerDown = (e, nodeId, side) => {
    e.stopPropagation();
    e.preventDefault();
    const node = pipeline.nodes.find((n) => n.id === nodeId);
    if (!node) return;
    const p = side === "right" ? nodeRight(node) : nodeLeft(node);
    setConnectDrag({ fromId: nodeId, fromSide: side, sx: p.x, sy: p.y, cx: p.x, cy: p.y });
    setSelectedEdgeId(null);
    // Redirect capture to the canvas so onCanvasPointerMove/Up always receive the events
    // even when the pointer moves fast over other elements
    try {
      if (canvasRef.current) {
        e.target.releasePointerCapture(e.pointerId);
        canvasRef.current.setPointerCapture(e.pointerId);
      }
    } catch {}
  };

  const onHandlePointerUp = (e, nodeId) => {
    e.stopPropagation();
    if (connectDrag?.fromId && connectDrag.fromId !== nodeId) {
      const exists = pipeline.edges.some(
        (ed) => ed.from === connectDrag.fromId && ed.to === nodeId
      );
      if (!exists) {
        updatePipeline({
          edges: [...pipeline.edges, { id: `e_${Date.now()}`, from: connectDrag.fromId, to: nodeId }],
        });
      }
    }
    setConnectDrag(null);
  };

  /* ─── delete ────────────────────────────────────────────── */
  const deleteSelected = useCallback(() => {
    if (selectedEdgeId) {
      updatePipeline({ edges: pipeline.edges.filter((e) => e.id !== selectedEdgeId) });
      setSelectedEdgeId(null);
      return;
    }
    if (!selectedId) return;
    const node = pipeline.nodes.find((n) => n.id === selectedId);
    if (!node || isFixedNode(node.type)) return;
    updatePipeline({
      nodes: pipeline.nodes.filter((n) => n.id !== selectedId),
      edges: pipeline.edges.filter((e) => e.from !== selectedId && e.to !== selectedId),
    });
    setSelectedId(null);
  }, [selectedEdgeId, selectedId, pipeline.edges, pipeline.nodes, updatePipeline]);

  useEffect(() => {
    const k = (e) => { if (e.key === "Delete" || e.key === "Backspace") deleteSelected(); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [deleteSelected]);

  /* ─── save / run ────────────────────────────────────────── */
  const handleSave = async () => {
    const saved = savePipeline(pipeline);
    updatePipeline(saved);
    try { await savePipelineRemote(saved); setSaveMsg("Saved."); }
    catch { setSaveMsg("Saved locally (backend offline)."); }
    setTimeout(() => setSaveMsg(""), 3000);
  };

  const handleRun = async () => {
    if (!validation.valid) return;
    try {
      const result = await runPipelineRemote(pipeline, sampleInput, {
        source_system: pipeline.nodes.find((n) => n.type === "whatsapp_message") ? "whatsapp" : "api",
        jurisdiction: "UAE",
      });
      setRunResult(result);
    } catch (err) {
      setRunResult({ error: String(err.message || err) });
    }
  };

  const resetPipeline = () => {
    setPipeline(emptyPipeline()); setSelectedId(null);
    setSelectedEdgeId(null); setConnectDrag(null); setRunResult(null);
  };
  const loadExample = () => {
    setPipeline(examplePipeline()); setSelectedId(null);
    setSelectedEdgeId(null); setConnectDrag(null); setRunResult(null);
  };

  const nodesById     = Object.fromEntries(pipeline.nodes.map((n) => [n.id, n]));
  const hasUserNodes  = pipeline.nodes.some((n) => !isFixedNode(n.type));
  const { x: vpx, y: vpy, zoom: vpz } = pipeline.viewport;

  return (
    <div className="wf-root">
      {/* ── toolbar ─────────────────────────────────────────── */}
      <div className="wf-bar">
        <div className="wf-bar-left">
          <input
            className="wf-name-input"
            value={pipeline.name}
            onChange={(e) => updatePipeline({ name: e.target.value })}
            placeholder="e.g. Arabic threat pipeline"
          />
          <label className="wf-observe-toggle">
            <input
              type="checkbox"
              checked={pipeline.observe_mode}
              onChange={(e) => updatePipeline({ observe_mode: e.target.checked })}
            />
            <span>{pipeline.observe_mode ? "Observe" : "Action"}</span>
          </label>
        </div>
        <div className="wf-bar-right">
          <input
            className="wf-sample-input"
            value={sampleInput}
            onChange={(e) => setSampleInput(e.target.value)}
            placeholder="Sample input for test run…"
          />
          <button className="wf-btn outline" onClick={handleRun} disabled={!validation.valid}>▶ Run</button>
          <button className="wf-btn ghost"   onClick={resetPipeline}>New</button>
          <button className="wf-btn ghost"   onClick={loadExample}>Example</button>
          <button className="wf-btn primary" onClick={handleSave}>Save</button>
        </div>
      </div>

      {saveMsg && <div className="wf-toast ok">{saveMsg}</div>}
      {!validation.valid && (
        <div className="wf-toast warn">{validation.errors.join("  ·  ")}</div>
      )}

      {/* ── body ────────────────────────────────────────────── */}
      <div className="wf-body">
        {/* left palette */}
        <aside className="wf-panel">
          <p className="wf-panel-sub">Drag nodes onto the canvas, then connect handles</p>

          {PALETTE_SECTIONS.map((sec) => (
            <div key={sec.key} className="wf-section">
              <div className="wf-section-title">{sec.title}</div>
              {NODE_CATALOG.filter((n) => n.category === sec.key).map((meta) => (
                <div
                  key={meta.id}
                  className={`wf-chip ${meta.locked ? "wf-chip-locked" : ""}`}
                  draggable={!meta.locked}
                  onDragStart={(e) => {
                    if (meta.locked) { e.preventDefault(); return; }
                    e.dataTransfer.setData("application/safeo-node", meta.id);
                    e.dataTransfer.effectAllowed = "copy";
                  }}
                >
                  <span className="wf-chip-dot" style={{ background: meta.color }} />
                  <div className="wf-chip-text">
                    <span className="wf-chip-label">{meta.label}</span>
                    {statusLabel(meta.status) && (
                      <span className="wf-chip-soon">🔒 {statusLabel(meta.status)}</span>
                    )}
                    <span className="wf-chip-sub">{meta.subtitle}</span>
                  </div>
                </div>
              ))}
            </div>
          ))}

          <div className="wf-section wf-section-fixed">
            <div className="wf-section-title">Fixed on canvas</div>
            {NODE_CATALOG.filter((n) => isFixedNode(n.type)).map((meta) => (
              <div key={meta.id} className="wf-chip wf-chip-fixed">
                <span className="wf-chip-dot" style={{ background: meta.color }} />
                <div className="wf-chip-text">
                  <span className="wf-chip-label">{meta.label}</span>
                  <span className="wf-chip-sub">{meta.subtitle}</span>
                </div>
              </div>
            ))}
          </div>

          <p className="wf-panel-hint">
            Drag <b>right ○</b> of a node to <b>left ○</b> of another to connect.
            <br />Click a line then Delete to remove it.
          </p>
        </aside>

        {/* canvas */}
        <div
          className="wf-canvas"
          ref={canvasRef}
          onDragOver={(e) => e.preventDefault()}
          onDrop={onCanvasDrop}
          onPointerDown={onCanvasPointerDown}
          onPointerMove={onCanvasPointerMove}
          onPointerUp={onCanvasPointerUp}
          onPointerLeave={onCanvasPointerUp}
          onWheel={onWheel}
          style={{ cursor: panning ? "grabbing" : connectDrag ? "crosshair" : "default" }}
        >
          {/* empty hint */}
          {!hasUserNodes && (
            <div className="wf-empty">
              <div className="wf-empty-card">
                <h4>Build your scan pipeline</h4>
                <p>Start & End are placed. Drag Input → Detection → Output nodes in between, then draw connections.</p>
              </div>
            </div>
          )}

          {/* zoom controls */}
          <div className="wf-zoom">
            <button onClick={() => updatePipeline({ viewport: { x: vpx, y: vpy, zoom: Math.min(2, vpz * 1.15) } })}>+</button>
            <span>{Math.round(vpz * 100)}%</span>
            <button onClick={() => updatePipeline({ viewport: { x: vpx, y: vpy, zoom: Math.max(0.3, vpz * 0.87) } })}>−</button>
            <button title="Reset view" onClick={() => updatePipeline({ viewport: { x: 40, y: 40, zoom: 1 } })}>⊡</button>
          </div>

          {/* the transforming surface */}
          <div
            className="wf-surface"
            style={{ transform: `translate(${vpx}px,${vpy}px) scale(${vpz})` }}
          >
            {/* SVG edges layer */}
            <svg
              className="wf-svg"
              width={CANVAS_W}
              height={CANVAS_H}
              style={{ overflow: "visible" }}
            >
              <defs>
                <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                  <path d="M0,0 L0,6 L8,3 z" fill="#6b7280" />
                </marker>
                <marker id="arr-sel" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                  <path d="M0,0 L0,6 L8,3 z" fill="#818cf8" />
                </marker>
                <marker id="arr-pre" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                  <path d="M0,0 L0,6 L8,3 z" fill="#a5b4fc" />
                </marker>
              </defs>

              {pipeline.edges.map((edge) => {
                const f = nodesById[edge.from];
                const t = nodesById[edge.to];
                if (!f || !t) return null;
                const [p1, p2] = bestPorts(f, t);
                const sel = selectedEdgeId === edge.id;
                return (
                  <g key={edge.id}>
                    {/* fat invisible hit area */}
                    <path
                      d={cubicPath(p1.x, p1.y, p2.x, p2.y)}
                      fill="none" stroke="transparent" strokeWidth={16}
                      style={{ cursor: "pointer", pointerEvents: "stroke" }}
                      onClick={(e) => { e.stopPropagation(); setSelectedEdgeId(edge.id); setSelectedId(null); }}
                    />
                    {/* visible line */}
                    <path
                      d={cubicPath(p1.x, p1.y, p2.x, p2.y)}
                      fill="none"
                      stroke={sel ? "#818cf8" : "#6b7280"}
                      strokeWidth={sel ? 2.5 : 2}
                      markerEnd={sel ? "url(#arr-sel)" : "url(#arr)"}
                      style={{ pointerEvents: "none" }}
                    />
                    {/* dot at source */}
                    <circle cx={p1.x} cy={p1.y} r={4} fill={sel ? "#818cf8" : "#6b7280"} style={{ pointerEvents: "none" }} />
                  </g>
                );
              })}

              {/* live preview wire while dragging */}
              {connectDrag && (
                <g style={{ pointerEvents: "none" }}>
                  <path
                    d={cubicPath(connectDrag.sx, connectDrag.sy, connectDrag.cx, connectDrag.cy)}
                    fill="none"
                    stroke="#6366f1"
                    strokeWidth={2}
                    strokeDasharray="6 4"
                    markerEnd="url(#arr-pre)"
                    opacity={0.85}
                  />
                  <circle cx={connectDrag.sx} cy={connectDrag.sy} r={5} fill="#6366f1" />
                </g>
              )}
            </svg>

            {/* nodes */}
            {pipeline.nodes.map((node) => {
              const meta    = CATALOG_BY_ID[node.type] || {};
              const sel     = selectedId === node.id;
              const fixed   = isFixedNode(node.type);
              const isRisk  = node.type === "risk_score";
              const isStart = node.type === "start";
              const isEnd   = node.type === "end";

              return (
                <div
                  key={node.id}
                  className={[
                    "wf-node",
                    sel   ? "wf-node-sel"   : "",
                    fixed ? "wf-node-fixed" : "",
                    isRisk  ? "wf-node-risk"  : "",
                    isStart ? "wf-node-start" : "",
                    isEnd   ? "wf-node-end"   : "",
                  ].join(" ").trim()}
                  style={{
                    left: node.x,
                    top:  node.y,
                    "--nc": meta.color || "#6b7280",
                  }}
                  onPointerDown={(e) => onNodePointerDown(e, node)}
                >
                  {/* left handle */}
                  <div
                    className={`wf-handle wf-h-left ${connectDrag ? "wf-h-target" : ""}`}
                    onPointerDown={(e) => { e.stopPropagation(); }}
                    onPointerUp={(e) => onHandlePointerUp(e, node.id)}
                  />

                  <div className="wf-node-inner">
                    <div className="wf-node-icon" style={{ color: meta.color || "#6b7280" }}>
                      {isStart ? "▶" : isEnd ? "■" : isRisk ? "⬡" : "●"}
                    </div>
                    <div className="wf-node-text">
                      <div className="wf-node-title">{meta.label || node.type}</div>
                      <div className="wf-node-sub">{meta.subtitle}</div>
                      {isRisk && (
                        <div className="wf-pills">
                          <span className="pill allow">ALLOW</span>
                          <span className="pill warn">WARN</span>
                          <span className="pill block">BLOCK</span>
                        </div>
                      )}
                      {statusLabel(meta.status) && (
                        <span className="wf-soon-tag">🔒 {statusLabel(meta.status)}</span>
                      )}
                    </div>
                  </div>

                  {/* right handle */}
                  <div
                    className="wf-handle wf-h-right"
                    onPointerDown={(e) => onHandlePointerDown(e, node.id, "right")}
                    onPointerUp={(e) => onHandlePointerUp(e, node.id)}
                  />
                </div>
              );
            })}
          </div>

          {/* minimap */}
          <div className="wf-minimap">
            {pipeline.nodes.map((n) => {
              const meta = CATALOG_BY_ID[n.type];
              return (
                <div
                  key={n.id}
                  className="wf-mm-node"
                  style={{
                    left:   `${(n.x / CANVAS_W) * 100}%`,
                    top:    `${(n.y / CANVAS_H) * 100}%`,
                    background: meta?.color || "#94a3b8",
                  }}
                />
              );
            })}
          </div>
        </div>
      </div>

      {runResult && (
        <div className="wf-run-panel">
          <h4>Test run result
            <button className="wf-run-close" onClick={() => setRunResult(null)}>✕</button>
          </h4>
          <pre>{JSON.stringify(runResult, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
