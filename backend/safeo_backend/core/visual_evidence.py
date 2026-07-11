"""
Visual evidence capture — headless screenshots with annotated highlight regions.

Uses Playwright (Chromium) for URL capture and Pillow for annotation overlays.
GitHub repos are fetched via API and rendered as dark-theme code images.
"""
from __future__ import annotations

import io
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, unquote, urlparse

import aiohttp
from PIL import Image, ImageDraw, ImageFont

from .ml.url_scanner import analyze_url

logger = logging.getLogger("safeo.visual")

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = PACKAGE_ROOT / "static"
SCREENSHOTS_DIR = STATIC_DIR / "screenshots"

SEVERITY_COLORS = {
    "HIGH": "#E24B4A",
    "MEDIUM": "#EF9F27",
    "LOW": "#378ADD",
}

CODE_EXT = {".py", ".js", ".ts", ".env", ".yml", ".yaml", ".json"}
MAX_GITHUB_FILES = 10
MAX_CODE_WIDTH = 800
LINE_HEIGHT = 20
CODE_FONT_SIZE = 13
GUTTER_WIDTH = 40
CODE_PADDING = 20

# ── GitHub line heuristics (Tier 1) ──────────────────────────────────────────

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(AKIA[0-9A-Z]{16})"), "hardcoded_secret", "HIGH"),
    (re.compile(r"(?i)(api[_-]?key\s*[:=]\s*['\"][^'\"]{8,}['\"])"), "hardcoded_secret", "HIGH"),
    (re.compile(r"(?i)(password\s*[:=]\s*['\"][^'\"]{4,}['\"])"), "hardcoded_secret", "HIGH"),
    (re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), "hardcoded_secret", "HIGH"),
    (re.compile(r"(?i)(secret[_-]?key\s*[:=]\s*['\"][^'\"]{6,}['\"])"), "hardcoded_secret", "MEDIUM"),
]

_EXEC_PATTERNS = [
    (re.compile(r"\bos\.system\s*\("), "dangerous_exec", "HIGH"),
    (re.compile(r"\beval\s*\("), "dangerous_exec", "HIGH"),
    (re.compile(r"\bexec\s*\("), "dangerous_exec", "HIGH"),
    (re.compile(r"subprocess\.[^(]+\([^)]*shell\s*=\s*True"), "dangerous_exec", "HIGH"),
    (re.compile(r"child_process\.exec\s*\("), "dangerous_exec", "HIGH"),
]

_PROMPT_INJ_PATTERNS = [
    (re.compile(r"(?i)(ignore\s+previous|system\s+prompt|you\s+are\s+now|disregard)"), "prompt_injection", "MEDIUM"),
]

_ARABIC_IN_STRING = re.compile(r"['\"][^'\"]*[\u0600-\u06FF][^'\"]*['\"]")


def _ensure_dirs() -> None:
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


def _load_font(size: int, mono: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = []
    if mono:
        candidates = [
            "/System/Library/Fonts/Menlo.ttc",
            "/System/Library/Fonts/SFNSMono.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
            "C:/Windows/Fonts/consola.ttf",
        ]
    else:
        candidates = [
            "/System/Library/Fonts/Helvetica.ttc",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]
    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                continue
    return ImageFont.load_default()


COLOR_NAME_MAP = {
    "red": "#E24B4A",
    "amber": "#EF9F27",
    "blue": "#378ADD",
}


def _resolve_color(color: str, severity: str = "HIGH") -> str:
    if color in COLOR_NAME_MAP:
        return COLOR_NAME_MAP[color]
    if color and color.startswith("#"):
        return color
    return SEVERITY_COLORS.get(severity, SEVERITY_COLORS["HIGH"])


def _hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))  # type: ignore


class ImageAnnotator:
    """Draw highlight boxes, severity badges, and header banners on screenshots."""

    @staticmethod
    def annotate(
        image_bytes: bytes,
        regions: List[Dict[str, Any]],
        header_text: Optional[str] = None,
        header_severity: str = "HIGH",
    ) -> bytes:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGBA")
        draw = ImageDraw.Draw(img)
        font = _load_font(11)
        header_font = _load_font(12)

        if header_text:
            color = _resolve_color("", header_severity)
            rgb = _hex_to_rgb(color)
            banner_h = 36
            overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
            odraw = ImageDraw.Draw(overlay)
            odraw.rectangle([0, 0, img.width, banner_h], fill=(*rgb, 230))
            img = Image.alpha_composite(img, overlay)
            draw = ImageDraw.Draw(img)
            draw.text((img.width // 2, 10), header_text, fill="white", font=header_font, anchor="mm")

        y_offset = 36 if header_text else 0

        for region in regions:
            bbox = region.get("bbox") or {}
            x = int(bbox.get("x", 0))
            y = int(bbox.get("y", 0)) + y_offset
            w = int(bbox.get("width", 0))
            h = int(bbox.get("height", 0))
            severity = region.get("severity", "HIGH")
            color = _resolve_color(region.get("color") or "", severity)
            rgb = _hex_to_rgb(color)
            label = region.get("label", "")

            draw.rectangle([x, y, x + w, y + h], outline=rgb, width=3)

            if label:
                tb = draw.textbbox((0, 0), label, font=font)
                tw, th = tb[2] - tb[0] + 8, tb[3] - tb[1] + 6
                ly = max(y_offset, y - th - 2)
                draw.rectangle([x, ly, x + tw, ly + th], fill=rgb)
                draw.text((x + 4, ly + 2), label, fill="white", font=font)

        out = io.BytesIO()
        img.convert("RGB").save(out, format="PNG")
        return out.getvalue()

    @staticmethod
    def render_code_image(
        file_path: str,
        lines: List[str],
        flagged: Dict[int, Dict[str, str]],
        max_width: int = MAX_CODE_WIDTH,
    ) -> bytes:
        """Render source file as dark-theme image with highlighted lines."""
        font = _load_font(CODE_FONT_SIZE, mono=True)
        num_lines = len(lines)
        img_h = num_lines * LINE_HEIGHT + CODE_PADDING * 2
        img_w = max_width

        img = Image.new("RGB", (img_w, img_h), "#1e1e1e")
        draw = ImageDraw.Draw(img, "RGBA")

        for i, line in enumerate(lines):
            y = CODE_PADDING + i * LINE_HEIGHT
            line_no = str(i + 1)

            if i in flagged:
                info = flagged[i]
                sev = info.get("severity", "HIGH")
                color = SEVERITY_COLORS.get(sev, "#E24B4A")
                rgb = _hex_to_rgb(color)
                draw.rectangle(
                    [GUTTER_WIDTH, y, img_w - CODE_PADDING, y + LINE_HEIGHT],
                    fill=(*rgb, 60),
                )
                draw.rectangle(
                    [GUTTER_WIDTH, y, GUTTER_WIDTH + 4, y + LINE_HEIGHT],
                    fill=rgb,
                )
                cat = info.get("category", "")
                if cat:
                    draw.text((img_w - CODE_PADDING - 140, y + 2), cat, fill=rgb, font=font)

            draw.text((8, y + 2), line_no.rjust(4), fill="#6b7280", font=font)
            display = line[: (img_w - GUTTER_WIDTH - CODE_PADDING - 150) // 7]
            draw.text((GUTTER_WIDTH + 8, y + 2), display, fill="#d4d4d4", font=font)

        draw.text((CODE_PADDING, 4), file_path, fill="#9ca3af", font=font)

        out = io.BytesIO()
        img.save(out, format="PNG")
        return out.getvalue()


def _arabic_in_text(text: str) -> bool:
    return bool(re.search(r"[\u0600-\u06FF]", text or ""))


def _demo_base() -> str:
    return os.getenv("SAFEO_VISUAL_DEMO_BASE", "http://127.0.0.1:8001").rstrip("/")


def _resolve_nav_url(url: str) -> Tuple[str, Dict[str, Any]]:
    """Return Playwright navigation URL; homograph URLs use local demo page."""
    meta = analyze_url(url)
    if meta.get("homograph_detected") or meta.get("mixed_script") or meta.get("arabic_digits"):
        encoded = quote(url, safe="")
        return f"{_demo_base()}/demo/visual-phishing?display_url={encoded}", meta
    return url, meta


class URLScreenshotter:
    """Headless Chromium capture with DOM-based highlight regions."""

    @staticmethod
    async def capture_url(url: str, findings: List[str], scan_id: str) -> Dict[str, Any]:
        _ensure_dirs()
        url_meta = analyze_url(url)
        nav_url, _ = _resolve_nav_url(url)
        highlighted: List[Dict[str, Any]] = []
        page_title = ""
        final_url = url
        error: Optional[str] = None

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {
                "screenshot_url": None,
                "highlighted_regions": [],
                "page_title": "",
                "final_url": url,
                "error": "Playwright not installed. Run: pip install playwright && playwright install chromium",
            }

        screenshot_bytes: Optional[bytes] = None
        header_text: Optional[str] = None
        header_severity = "HIGH"

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 900},
                    ignore_https_errors=True,
                )
                page = await context.new_page()
                try:
                    await page.goto(nav_url, timeout=15000, wait_until="networkidle")
                except Exception:
                    try:
                        await page.goto(nav_url, timeout=15000, wait_until="domcontentloaded")
                    except Exception as exc:
                        error = f"Page did not load within 15s: {exc}"
                        await browser.close()
                        return {
                            "screenshot_url": None,
                            "highlighted_regions": [],
                            "page_title": "",
                            "final_url": url,
                            "error": error,
                        }

                page_title = await page.title()
                final_url = page.url
                screenshot_bytes = await page.screenshot(full_page=True, type="png")

                # Homograph banner region (top address bar area)
                if url_meta.get("homograph_detected"):
                    flagged = url_meta.get("flagged_chars") or []
                    cps = ", ".join(f"{f['char']} ({f['codepoint']})" for f in flagged[:6])
                    header_text = f"⚠ Arabic Unicode homograph detected in domain — {cps}"
                    highlighted.append({
                        "label": "IDN homograph domain",
                        "bbox": {"x": 0, "y": 0, "width": 1280, "height": 60},
                        "severity": "HIGH",
                        "color": "red",
                    })

                # Arabic in page title
                if _arabic_in_text(page_title):
                    highlighted.append({
                        "label": "Mixed Arabic/Latin page title",
                        "bbox": {"x": 0, "y": 60, "width": 1280, "height": 40},
                        "severity": "MEDIUM",
                        "color": "amber",
                    })

                # Password login forms
                password_inputs = await page.query_selector_all('input[type="password"]')
                for inp in password_inputs:
                    box = await inp.bounding_box()
                    if box:
                        highlighted.append({
                            "label": "Phishing login form detected",
                            "bbox": {
                                "x": max(0, int(box["x"] - 10)),
                                "y": int(box["y"] - 30),
                                "width": int(box["width"] + 20),
                                "height": int(box["height"] + 50),
                            },
                            "severity": "HIGH",
                            "color": "red",
                        })
                        break

                # Match findings text in DOM
                for finding in (findings or [])[:5]:
                    snippet = finding.split("'")
                    search = snippet[1] if len(snippet) > 1 else finding[:40]
                    if len(search) < 3:
                        continue
                    try:
                        el = await page.query_selector(f"text={search[:30]}")
                        if el:
                            box = await el.bounding_box()
                            if box:
                                highlighted.append({
                                    "label": finding[:50],
                                    "bbox": {
                                        "x": int(box["x"]),
                                        "y": int(box["y"]),
                                        "width": int(box["width"]),
                                        "height": int(box["height"]),
                                    },
                                    "severity": "MEDIUM",
                                    "color": "amber",
                                })
                    except Exception:
                        pass

                await browser.close()

        except Exception as exc:
            logger.exception("URL screenshot failed")
            return {
                "screenshot_url": None,
                "highlighted_regions": [],
                "page_title": page_title,
                "final_url": final_url,
                "error": str(exc),
            }

        if not screenshot_bytes:
            return {
                "screenshot_url": None,
                "highlighted_regions": highlighted,
                "page_title": page_title,
                "final_url": final_url,
                "error": error or "Screenshot capture failed",
            }

        # Always annotate — border + summary if no regions
        if not highlighted:
            highlighted.append({
                "label": "Scan complete — no DOM threats",
                "bbox": {"x": 10, "y": 80, "width": 1260, "height": 40},
                "severity": "LOW",
                "color": "blue",
            })
            header_text = header_text or f"SafeO visual scan — decision pending review"

        annotated = ImageAnnotator.annotate(
            screenshot_bytes,
            highlighted,
            header_text=header_text,
            header_severity=header_severity,
        )

        out_path = SCREENSHOTS_DIR / f"{scan_id}.png"
        out_path.write_bytes(annotated)

        return {
            "screenshot_url": f"/static/screenshots/{scan_id}.png",
            "highlighted_regions": highlighted,
            "page_title": page_title,
            "final_url": final_url,
            "error": None,
        }


class GitHubScanner:
    """Fetch public repo files and render annotated code screenshots."""

    @staticmethod
    def _parse_github_url(url: str) -> Optional[Dict[str, str]]:
        url = url.strip().rstrip("/")
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)(?:/blob/([^/]+)/(.+))?", url)
        if not m:
            return None
        owner, repo, branch, path = m.group(1), m.group(2), m.group(3), m.group(4)
        if repo.endswith(".git"):
            repo = repo[:-4]
        return {
            "owner": owner,
            "repo": repo,
            "branch": branch or "main",
            "path": path or "",
        }

    @staticmethod
    def _scan_line(line: str, line_no: int) -> Optional[Dict[str, str]]:
        for pat, category, severity in _SECRET_PATTERNS + _EXEC_PATTERNS + _PROMPT_INJ_PATTERNS:
            if pat.search(line):
                return {
                    "line_number": line_no,
                    "line_content": line.strip()[:200],
                    "category": category,
                    "severity": severity,
                }
        if _ARABIC_IN_STRING.search(line):
            return {
                "line_number": line_no,
                "line_content": line.strip()[:200],
                "category": "arabic_obfuscation",
                "severity": "MEDIUM",
            }
        return None

    @staticmethod
    async def capture_github(github_url: str, findings: List[str], scan_id: str) -> Dict[str, Any]:
        _ensure_dirs()
        parsed = GitHubScanner._parse_github_url(github_url)
        if not parsed:
            return {
                "files_scanned": 0,
                "findings": [],
                "total_findings": 0,
                "screenshot_urls": [],
                "error": "Invalid GitHub URL",
            }

        owner, repo = parsed["owner"], parsed["repo"]
        branch = parsed["branch"]
        single_path = parsed["path"]

        if not branch:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"https://api.github.com/repos/{owner}/{repo}",
                        headers={"Accept": "application/vnd.github+json"},
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 200:
                            info = await resp.json()
                            branch = info.get("default_branch", "main")
                        else:
                            branch = "main"
            except Exception:
                branch = "main"

        file_paths: List[str] = []
        if single_path:
            file_paths = [single_path]
        else:
            api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        api_url,
                        headers={"Accept": "application/vnd.github+json"},
                        timeout=aiohttp.ClientTimeout(total=20),
                    ) as resp:
                        if resp.status == 404:
                            return {
                                "files_scanned": 0,
                                "findings": [],
                                "total_findings": 0,
                                "screenshot_urls": [],
                                "error": "Repository not found or private",
                            }
                        if resp.status != 200:
                            return {
                                "files_scanned": 0,
                                "findings": [],
                                "total_findings": 0,
                                "screenshot_urls": [],
                                "error": f"GitHub API error: HTTP {resp.status}",
                            }
                        data = await resp.json()
                        for item in data.get("tree", []):
                            if item.get("type") != "blob":
                                continue
                            p = item.get("path", "")
                            ext = Path(p).suffix.lower()
                            if ext in CODE_EXT:
                                file_paths.append(p)
                            if len(file_paths) >= MAX_GITHUB_FILES:
                                break
            except Exception as exc:
                return {
                    "files_scanned": 0,
                    "findings": [],
                    "total_findings": 0,
                    "screenshot_urls": [],
                    "error": str(exc),
                }

        if not file_paths:
            return {
                "files_scanned": 0,
                "findings": [],
                "total_findings": 0,
                "screenshot_urls": [],
                "error": "No scannable files found in repository",
            }

        all_findings: List[Dict[str, Any]] = []
        screenshot_urls: List[str] = []

        async with aiohttp.ClientSession() as session:
            for fpath in file_paths[:MAX_GITHUB_FILES]:
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{fpath}"
                try:
                    async with session.get(raw_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status != 200:
                            continue
                        content = await resp.text(errors="replace")
                except Exception:
                    continue

                lines = content.splitlines()
                flagged_lines: Dict[int, Dict[str, str]] = {}
                for i, line in enumerate(lines):
                    hit = GitHubScanner._scan_line(line, i + 1)
                    if hit:
                        flagged_lines[i] = hit
                        all_findings.append({
                            "file_path": fpath,
                            "line_number": hit["line_number"],
                            "line_content": hit["line_content"],
                            "category": hit["category"],
                            "severity": hit["severity"],
                        })

                safe_name = re.sub(r"[^\w.\-]", "_", Path(fpath).name)[:40]
                img_bytes = ImageAnnotator.render_code_image(fpath, lines[:80], flagged_lines)
                out_name = f"{scan_id}_{safe_name}.png"
                (SCREENSHOTS_DIR / out_name).write_bytes(img_bytes)
                url = f"/static/screenshots/{out_name}"
                screenshot_urls.append(url)

                for f in all_findings:
                    if f["file_path"] == fpath and "screenshot_url" not in f:
                        f["screenshot_url"] = url

        # Attach screenshot_url to each finding
        for f in all_findings:
            if "screenshot_url" not in f:
                for u in screenshot_urls:
                    if Path(f["file_path"]).name.replace(".", "_") in u:
                        f["screenshot_url"] = u
                        break
                if "screenshot_url" not in f and screenshot_urls:
                    f["screenshot_url"] = screenshot_urls[0]

        return {
            "files_scanned": len(file_paths[:MAX_GITHUB_FILES]),
            "findings": all_findings,
            "total_findings": len(all_findings),
            "screenshot_urls": screenshot_urls,
            "error": None,
        }


def enrich_patterns_from_visual(
    url_result: Optional[Dict[str, Any]],
    github_result: Optional[Dict[str, Any]],
    url_meta: Optional[Dict[str, Any]],
) -> List[str]:
    """Add visual-grounded pattern tags for scan response."""
    extra: List[str] = []
    if url_meta and url_meta.get("homograph_detected"):
        extra.append("arabic_unicode_homograph")
    if url_result:
        for r in url_result.get("highlighted_regions") or []:
            label = (r.get("label") or "").lower()
            if "login" in label or "password" in label:
                extra.append("phishing_login_form")
            if "arabic" in label or "homograph" in label:
                extra.append("arabic_unicode_homograph")
    if github_result:
        for f in github_result.get("findings") or []:
            extra.append(f"github_{f.get('category', 'finding')}")
    return list(dict.fromkeys(extra))
