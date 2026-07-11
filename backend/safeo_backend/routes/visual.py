"""
Visual scan route — combines Tier 1 scan with annotated screenshot evidence.
"""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from ..core.visual_evidence import (
    GitHubScanner,
    URLScreenshotter,
    enrich_patterns_from_visual,
)
from ..core.ml.url_scanner import analyze_url
from .universal import ScanContext, _run_scan

router = APIRouter(prefix="/v1", tags=["Visual Evidence"])


class VisualScanContext(BaseModel):
    user_id: str = "anonymous"
    source_system: str = "visual_scan"


class VisualScanRequest(BaseModel):
    input: str
    input_type: Literal["url", "github"] = "url"
    context: VisualScanContext = Field(default_factory=VisualScanContext)


DEMO_PHISHING_HTML = """<!DOCTYPE html>
<html lang="ar">
<head>
  <meta charset="UTF-8">
  <title>فتح Access — Open Access Portal تسجيل الدخول</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #f0f4f8; }
    .chrome {
      background: #e8eaed; padding: 10px 16px; border-bottom: 1px solid #ccc;
      display: flex; align-items: center; gap: 12px;
    }
    .dots { display: flex; gap: 6px; }
    .dot { width: 12px; height: 12px; border-radius: 50%; }
    .dot.r { background: #ff5f57; } .dot.y { background: #febc2e; } .dot.g { background: #28c840; }
    .address {
      flex: 1; background: #fff; border: 1px solid #ccc; border-radius: 20px;
      padding: 8px 16px; font-size: 14px; color: #333; font-family: monospace;
    }
    .lock { color: #34a853; }
    .page { max-width: 420px; margin: 60px auto; background: #fff;
      border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,.1); padding: 32px; }
    h1 { font-size: 22px; margin-bottom: 8px; color: #1a1a2e; }
    .sub { color: #666; font-size: 14px; margin-bottom: 24px; }
    label { display: block; font-size: 13px; color: #444; margin-bottom: 6px; }
    input { width: 100%; padding: 10px 12px; border: 1px solid #ddd;
      border-radius: 8px; font-size: 15px; margin-bottom: 16px; }
    button { width: 100%; padding: 12px; background: #2563eb; color: #fff;
      border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; }
    .warn { margin-top: 16px; font-size: 11px; color: #9ca3af; text-align: center; }
  </style>
</head>
<body>
  <div class="chrome" id="address-bar">
    <div class="dots"><div class="dot r"></div><div class="dot y"></div><div class="dot g"></div></div>
    <span class="lock">🔒</span>
    <div class="address" id="display-url">https://open-access.com/login</div>
  </div>
  <div class="page">
    <h1>فتح Access Portal</h1>
    <p class="sub">Open Access — sign in to continue / تسجيل الدخول للمتابعة</p>
    <form id="login-form">
      <label for="email">Email address</label>
      <input type="email" id="email" placeholder="you@university.edu" />
      <label for="password">Password</label>
      <input type="password" id="password" placeholder="Enter your password" />
      <button type="submit">Sign in / دخول</button>
    </form>
    <p class="warn">SafeO visual evidence demo page — not a real phishing site</p>
  </div>
  <script>
    const params = new URLSearchParams(window.location.search);
    const display = params.get('display_url');
    if (display) {
      document.getElementById('display-url').textContent = decodeURIComponent(display);
    }
  </script>
</body>
</html>
"""


@router.post("/scan/visual")
async def scan_visual(req: VisualScanRequest):
    """
    Run Tier 1 scan plus headless visual evidence capture.

    Returns scan result merged with annotated screenshot URLs and highlight regions.
    """
    text = (req.input or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="input is required")

    ctx = ScanContext(
        user_id=req.context.user_id,
        source_system=req.context.source_system or req.input_type,
    )
    scan_result = await _run_scan(text, ctx)
    scan_id = scan_result.get("scan_id", "unknown")
    matched = list(scan_result.get("matched_patterns") or [])
    url_meta = analyze_url(text) if req.input_type == "url" else None

    visual_evidence: Dict[str, Any] = {
        "screenshot_url": None,
        "highlighted_regions": [],
        "screenshots": [],
    }
    url_visual: Optional[Dict[str, Any]] = None
    gh_visual: Optional[Dict[str, Any]] = None

    if req.input_type == "url":
        url_visual = await URLScreenshotter.capture_url(text, matched, scan_id)
        visual_evidence["screenshot_url"] = url_visual.get("screenshot_url")
        visual_evidence["highlighted_regions"] = url_visual.get("highlighted_regions") or []
        visual_evidence["page_title"] = url_visual.get("page_title")
        visual_evidence["final_url"] = url_visual.get("final_url")
        if url_visual.get("error"):
            visual_evidence["error"] = url_visual["error"]
        if url_visual.get("screenshot_url"):
            visual_evidence["screenshots"] = [url_visual["screenshot_url"]]

    elif req.input_type == "github":
        gh_visual = await GitHubScanner.capture_github(text, matched, scan_id)
        visual_evidence["github"] = gh_visual
        visual_evidence["screenshots"] = gh_visual.get("screenshot_urls") or []
        visual_evidence["screenshot_url"] = (
            gh_visual["screenshot_urls"][0] if gh_visual.get("screenshot_urls") else None
        )
        if gh_visual.get("error"):
            visual_evidence["error"] = gh_visual["error"]

    extra_patterns = enrich_patterns_from_visual(
        url_visual if req.input_type == "url" else None,
        gh_visual if req.input_type == "github" else None,
        url_meta,
    )
    merged_patterns = list(dict.fromkeys(matched + extra_patterns))

    # Re-evaluate decision if visual evidence adds high-severity signals
    decision = scan_result.get("decision", "ALLOW")
    if extra_patterns and decision == "ALLOW":
        if "arabic_unicode_homograph" in extra_patterns or "phishing_login_form" in extra_patterns:
            decision = "BLOCK"
            scan_result["risk_score"] = max(float(scan_result.get("risk_score", 0)), 0.85)
            scan_result["risk_score_pct"] = round(scan_result["risk_score"] * 100)

    response: Dict[str, Any] = {
        **scan_result,
        "decision": decision,
        "matched_patterns": merged_patterns,
        "screenshot_url": visual_evidence.get("screenshot_url"),
        "highlighted_regions": visual_evidence.get("highlighted_regions") or [],
        "visual_evidence": visual_evidence,
    }
    if url_meta:
        response["url_analysis"] = url_meta

    return response
