import { Link, useNavigate } from "react-router-dom";
import { useEffect, useRef } from "react";

function FadeLink({ to, className, children }) {
  const navigate = useNavigate();
  const onClick = (e) => {
    if (!document.startViewTransition) return;
    e.preventDefault();
    document.startViewTransition(() => navigate(to));
  };
  return (
    <Link to={to} className={className} onClick={onClick}>
      {children}
    </Link>
  );
}

function useReveal() {
  const ref = useRef(null);
  useEffect(() => {
    const els = ref.current.querySelectorAll(".reveal");
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("in-view");
            io.unobserve(e.target);
          }
        });
      },
      { threshold: 0.15, rootMargin: "0px 0px -60px 0px" }
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);
  return ref;
}

const NODE_COLORS = ["232,32,42", "99,102,241", "148,163,184"];
const LINK_DIST = 150;

function useParticleNetwork(canvasRef) {
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const ctx = canvas.getContext("2d");
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    let w = 0, h = 0, docH = 0, scrollY = 0, raf = null, running = true;
    let nodes = [];

    const count = () => Math.min(70, Math.max(28, Math.round((w * docH) / 55000)));

    const resize = () => {
      w = window.innerWidth;
      docH = document.documentElement.scrollHeight;
      canvas.width = w * dpr;
      canvas.height = docH * dpr;
      canvas.style.width = w + "px";
      canvas.style.height = docH + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const n = count();
      nodes = Array.from({ length: n }, (_, i) => ({
        x: Math.random() * w,
        y: Math.random() * docH,
        vx: (Math.random() - 0.5) * 0.18,
        vy: (Math.random() - 0.5) * 0.18,
        r: 1.4 + Math.random() * 1.8,
        c: NODE_COLORS[i % NODE_COLORS.length],
        parY: 0.15 + Math.random() * 0.35,
        drift: Math.random() * Math.PI * 2,
      }));
    };

    const onScroll = () => { scrollY = window.scrollY; };

    const draw = () => {
      ctx.clearRect(0, 0, w, docH);
      const viewTop = scrollY - 200;
      const viewBottom = scrollY + window.innerHeight + 200;

      for (const p of nodes) {
        p.x += p.vx;
        p.y += p.vy + Math.sin(p.drift + scrollY * 0.002) * 0.02;
        p.drift += 0.002;
        if (p.x < 0) p.x = w; else if (p.x > w) p.x = 0;
        if (p.y < 0) p.y = docH; else if (p.y > docH) p.y = 0;
      }

      const visible = nodes.filter((p) => p.y > viewTop && p.y < viewBottom);

      ctx.lineWidth = 1;
      for (let i = 0; i < visible.length; i++) {
        for (let j = i + 1; j < visible.length; j++) {
          const a = visible[i], b = visible[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < LINK_DIST) {
            ctx.strokeStyle = `rgba(${a.c},${0.12 * (1 - d / LINK_DIST)})`;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }
      for (const p of visible) {
        ctx.beginPath();
        ctx.fillStyle = `rgba(${p.c},0.75)`;
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }

      if (running) raf = requestAnimationFrame(draw);
    };

    resize();
    onScroll();
    window.addEventListener("resize", resize);
    window.addEventListener("scroll", onScroll, { passive: true });

    const onVisibility = () => {
      running = document.visibilityState === "visible" && !reduced;
      if (running && !raf) raf = requestAnimationFrame(draw);
    };
    document.addEventListener("visibilitychange", onVisibility);

    if (!reduced) {
      raf = requestAnimationFrame(draw);
    } else {
      draw();
      running = false;
    }

    return () => {
      running = false;
      if (raf) cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("scroll", onScroll);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [canvasRef]);
}

function useMouseParallax(orbitRef, maxOffset = 60) {
  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) return;
    let raf = null;
    let tx = 0, ty = 0;
    const onMove = (e) => {
      const nx = (e.clientX / window.innerWidth - 0.5) * 2;
      const ny = (e.clientY / window.innerHeight - 0.5) * 2;
      tx = nx * maxOffset;
      ty = ny * maxOffset;
      if (raf) return;
      raf = requestAnimationFrame(() => {
        if (orbitRef.current) {
          orbitRef.current.style.transform = `translate(calc(-50% + ${tx}px), calc(-50% + ${ty}px))`;
        }
        raf = null;
      });
    };
    window.addEventListener("mousemove", onMove, { passive: true });
    return () => window.removeEventListener("mousemove", onMove);
  }, [orbitRef, maxOffset]);
}

function useScrollSpin(spinRef, degPerPx = 0.08) {
  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) return;
    let raf = null;
    const onScroll = () => {
      if (raf) return;
      raf = requestAnimationFrame(() => {
        if (spinRef.current) {
          spinRef.current.style.transform = `rotate(${window.scrollY * degPerPx}deg)`;
        }
        raf = null;
      });
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, [spinRef, degPerPx]);
}

const DIFFERENCES = [
  ["WAF", "Perimeter-focused, weak business context", "Scans inside ERP/API workflows before persistence"],
  ["SIEM", "Post-hoc detection after logs arrive", "Inline decisioning before data is saved"],
  ["Generic LLM guardrails", "English-first, hard to audit", "Arabic/Arabizi normalization + graph-grounded evidence"],
  ["Basic moderation APIs", "Usually ALLOW/BLOCK only", "5-agent investigation with policy, forensics, verifier, remediation"],
  ["Static thresholds", "Drift and false positives over time", "Bayesian threshold adaptation from human feedback"],
];

const AGENTS = [
  ["Multilingual", "Normalizes Arabic, Arabizi, and mixed-script obfuscation before scoring"],
  ["Policy", "Checks input against enterprise policy and compliance rules"],
  ["Forensics", "Matches payloads against MITRE-tagged attack-pattern graph"],
  ["Verifier", "Cross-checks policy and forensics findings for consensus"],
  ["Remediation", "Selects a playbook and drafts the response action"],
];

const STATS = [
  ["5", "specialist agents"],
  ["3", "decisions — ALLOW / WARN / BLOCK"],
  ["15", "attack-pattern graph nodes"],
  ["0", "OpenAI keys required"],
];

export default function Landing() {
  const ref = useReveal();
  const canvasRef = useRef(null);
  const orbitRef = useRef(null);
  const spinRef = useRef(null);
  useParticleNetwork(canvasRef);
  useMouseParallax(orbitRef, 70);
  useScrollSpin(spinRef, 0.08);
  return (
    <div className="land" ref={ref}>
      <div className="land-orbit-wrap" aria-hidden="true">
        <div className="land-orbit" ref={orbitRef}>
          <div className="land-orbit-spin" ref={spinRef}>
            <svg className="land-orbit-lines" viewBox="-650 -650 1300 1300">
              <line x1="560" y1="0" x2="-280" y2="485" />
              <line x1="-280" y1="485" x2="-280" y2="-485" />
              <line x1="-280" y1="-485" x2="560" y2="0" />
            </svg>
            <div className="land-orbit-blob land-orbit-blob-1" />
            <div className="land-orbit-blob land-orbit-blob-2" />
            <div className="land-orbit-blob land-orbit-blob-3" />
          </div>
        </div>
      </div>
      <div className="land-blobs" aria-hidden="true">
        <div className="land-blob land-blob-1" />
        <div className="land-blob land-blob-2" />
      </div>
      <canvas className="land-network" ref={canvasRef} aria-hidden="true" />
      <header className="land-nav">
        <div className="land-brand">
          <div className="land-brand-mark">S</div>
          <span>SafeO</span>
        </div>
        <nav className="land-nav-links">
          <a href="#how">How it works</a>
          <a href="#agents">Agents</a>
          <a href="#stack">Stack</a>
        </nav>
        <FadeLink to="/app" className="land-nav-cta">Open Dashboard →</FadeLink>
      </header>

      <section className="land-hero">
        <div className="land-hero-glow" aria-hidden="true" />
        <p className="reveal land-eyebrow">AMD Developer Hackathon · ACT II</p>
        <h1 className="reveal">
          Stop malicious input <span className="land-accent">before</span> it becomes a breach.
        </h1>
        <p className="reveal land-sub">
          SafeO is an Arabic-aware, multi-agent cybersecurity decision engine that scans ERP forms,
          APIs, and messages in real time — then returns ALLOW, WARN, or BLOCK before the data is
          ever saved.
        </p>
        <div className="reveal land-hero-actions">
          <FadeLink to="/app" className="land-btn-primary">Open Dashboard</FadeLink>
          <FadeLink to="/connect" className="land-btn-ghost">Connect your ERP</FadeLink>
        </div>
        <div className="reveal land-decisions">
          <span className="land-pill allow">ALLOW · safe input</span>
          <span className="land-pill warn">WARN · needs review</span>
          <span className="land-pill block">BLOCK · malicious</span>
        </div>
      </section>

      <section className="land-stats reveal">
        {STATS.map(([n, l]) => (
          <div className="land-stat" key={l}>
            <div className="land-stat-num">{n}</div>
            <div className="land-stat-label">{l}</div>
          </div>
        ))}
      </section>

      <section className="land-section" id="how">
        <h2 className="reveal">The gap SafeO closes</h2>
        <p className="reveal land-section-sub">
          Perimeter tools and post-hoc logs miss attacks that happen inside the business workflow
          itself — inside the form, before anything is stored.
        </p>
        <div className="land-table reveal">
          <div className="land-table-row land-table-head">
            <span>Existing approach</span>
            <span>Limitation</span>
            <span>SafeO difference</span>
          </div>
          {DIFFERENCES.map(([a, b, c]) => (
            <div className="land-table-row" key={a}>
              <span>{a}</span>
              <span>{b}</span>
              <span>{c}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="land-section" id="agents">
        <h2 className="reveal">Five agents, one investigation</h2>
        <p className="reveal land-section-sub">
          When input scores as WARN or BLOCK, a LangGraph-style investigation room runs — every
          step logged into a SHA-256 audit chain.
        </p>
        <div className="land-agent-grid">
          {AGENTS.map(([name, desc], i) => (
            <div className="land-agent-card reveal" key={name} style={{ transitionDelay: `${i * 60}ms` }}>
              <div className="land-agent-num">{String(i + 1).padStart(2, "0")}</div>
              <h3>{name}</h3>
              <p>{desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="land-section land-stack" id="stack">
        <h2 className="reveal">Built for AMD, runs without OpenAI</h2>
        <p className="reveal land-section-sub">
          Default path is fully local: deterministic heuristics, DistilBERT/TF-IDF, and
          deterministic Python agents. Optional cloud path uses Fireworks AI on AMD-hosted
          inference for faster agent reasoning.
        </p>
        <div className="land-stack-grid">
          <div className="land-stack-card reveal">
            <h3>AMD AI Developer Cloud</h3>
            <p>ROCm-compatible inference and LoRA fine-tuning workflows</p>
          </div>
          <div className="land-stack-card reveal">
            <h3>bf16 LoRA</h3>
            <p>Avoids fp16 instability on AMD ROCm during fine-tuning</p>
          </div>
          <div className="land-stack-card reveal">
            <h3>Fireworks AI (optional)</h3>
            <p>Fast agent reasoning on AMD-hosted models, no OpenAI key needed</p>
          </div>
        </div>
      </section>

      <section className="land-cta reveal">
        <h2>Protect the workflow, not just the perimeter.</h2>
        <p>Connect your ERP or explore the live dashboard in minutes.</p>
        <div className="land-hero-actions">
          <FadeLink to="/connect" className="land-btn-primary">Connect your ERP</FadeLink>
          <FadeLink to="/app" className="land-btn-ghost">View Dashboard</FadeLink>
        </div>
      </section>

      <footer className="land-footer">
        <span>SafeO — ERP Protection Layer</span>
        <span>AMD Developer Hackathon · ACT II</span>
      </footer>
    </div>
  );
}
