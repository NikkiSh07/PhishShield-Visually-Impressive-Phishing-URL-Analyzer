"""
PhishShield Backend — Flask
============================
Replaces FastAPI with Flask. Same heuristics + WHOIS + ML model.
Adds MySQL persistence via db.py and Java feature extraction via subprocess.

Run:
    pip install -r requirements.txt
    python app.py

Then open:  http://localhost:5000
API docs:   http://localhost:5000/api/health
"""

import re
import json
import socket
import logging
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, jsonify, render_template, send_from_directory, abort
from flask_cors import CORS

# ── Optional dependencies ──────────────────────────────────────────────────────
try:
    import whois as _whois_mod
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    # ML model lives alongside this file
    _here = Path(__file__).parent
    sys.path.insert(0, str(_here))
    import ml_model as _ml
    HAS_ML = _ml.available()
    ml_model = _ml if HAS_ML else None
except Exception:
    HAS_ML = False
    ml_model = None

# ── DB layer ───────────────────────────────────────────────────────────────────
try:
    import db as _db
    HAS_DB = _db.db_available()
except Exception:
    _db = None
    HAS_DB = False

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger("phishshield")

# ── Flask app ──────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent  # project root
app = Flask(__name__,
            template_folder=str(BASE_DIR / "templates"),
            static_folder=str(BASE_DIR / "static"))
CORS(app)

# ── Heuristic config ───────────────────────────────────────────────────────────
SUSPICIOUS_TLDS  = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".work",".date",
                    ".party",".click",".country",".stream",".download",".review",
                    ".zip",".mov"}
SHORTENERS       = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd",
                    "buff.ly","adf.ly","shorturl.at","tiny.cc","rebrand.ly","cutt.ly"}
LOGIN_KEYWORDS   = ["login","signin","sign-in","verify","verification","account",
                    "secure","banking","update","confirm","webscr","session",
                    "authenticate","password","credential"]
POPULAR_DOMAINS  = ["google","facebook","apple","paypal","amazon","microsoft",
                    "netflix","instagram","twitter","linkedin","github","yahoo",
                    "whatsapp","tiktok","adobe"]

JAVA_DIR = Path(__file__).parent / "java"
JAVA_CLASS = "PhishAnalyzer"


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(m+1): dp[i][0] = i
    for j in range(n+1): dp[0][j] = j
    for i in range(1, m+1):
        for j in range(1, n+1):
            dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1,
                           dp[i-1][j-1] + (0 if a[i-1]==b[j-1] else 1))
    return dp[m][n]


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty URL")
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw
    return raw


def whois_age_days(hostname: str):
    """Returns (age_days, creation_date_str, error)"""
    if not HAS_WHOIS:
        return None, None, "python-whois not installed"
    try:
        domain = hostname.split(":")[0]
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            return None, None, "IP host"
        w = _whois_mod.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if not cd:
            return None, None, "No creation_date"
        if cd.tzinfo is None:
            cd = cd.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - cd).days
        return age, cd.isoformat(), None
    except Exception as e:
        return None, None, str(e)[:120]


def dns_exists(hostname: str):
    try:
        socket.gethostbyname(hostname.split(":")[0])
        return True
    except Exception:
        return False


def call_java_analyzer(url: str) -> dict:
    """
    Call the compiled Java PhishAnalyzer via subprocess.
    Returns parsed JSON dict, or empty dict on failure.
    """
    class_file = JAVA_DIR / (JAVA_CLASS + ".class")
    java_src   = JAVA_DIR / (JAVA_CLASS + ".java")

    # Auto-compile if .class missing or older than .java
    if not class_file.exists() or (
        java_src.exists() and java_src.stat().st_mtime > class_file.stat().st_mtime
    ):
        try:
            result = subprocess.run(
                ["javac", str(java_src)],
                capture_output=True, text=True, timeout=30, cwd=str(JAVA_DIR)
            )
            if result.returncode != 0:
                logger.warning(f"Java compile failed: {result.stderr}")
                return {}
            logger.info("Java PhishAnalyzer compiled successfully.")
        except FileNotFoundError:
            logger.warning("javac not found — Java features disabled.")
            return {}
        except Exception as e:
            logger.warning(f"Java compile error: {e}")
            return {}

    # Run the Java analyzer
    try:
        result = subprocess.run(
            ["java", "-cp", str(JAVA_DIR), JAVA_CLASS, url],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout.strip())
        else:
            logger.warning(f"Java run failed: {result.stderr}")
            return {}
    except FileNotFoundError:
        logger.warning("java not found — Java features disabled.")
        return {}
    except json.JSONDecodeError:
        logger.warning("Java output not valid JSON")
        return {}
    except Exception as e:
        logger.warning(f"Java execution error: {e}")
        return {}


# ═══════════════════════════════════════════════════════════════════════════════
# Core analysis engine (ported from FastAPI)
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_url(raw_input: str) -> dict:
    raw = normalize_url(raw_input)
    try:
        parsed = urlparse(raw)
    except Exception:
        return {"error": "Invalid URL", "score": 0}
    if not parsed.hostname:
        return {"error": "Invalid URL: no hostname", "score": 0}

    hostname = parsed.hostname.lower()
    full     = raw.lower()
    reasons  = []
    breakdown= []
    score    = 0

    def add_breakdown(name, pts, max_pts):
        breakdown.append({"name": name, "pts": pts, "max": max_pts})

    def add_reason(text, points, type_, icon):
        nonlocal score
        reasons.append({"text": text, "points": points, "type": type_, "icon": icon})
        if type_ == "triggered":
            score += points

    # ── 1. Transport ──────────────────────────────────────────────────────────
    if parsed.scheme == "http":
        add_reason("<strong>Unencrypted HTTP</strong> — no TLS", 10, "triggered", "!")
        add_breakdown("Transport Security", 10, 10)
    else:
        add_reason("<strong>HTTPS enabled</strong>", 0, "safe", "✓")
        add_breakdown("Transport Security", 0, 10)

    # ── 2. IP host ────────────────────────────────────────────────────────────
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    if is_ip:
        add_reason("<strong>IP address as hostname</strong>", 25, "triggered", "✕")
        add_breakdown("Host Identity", 25, 25)
    else:
        add_reason("<strong>Domain-based host</strong>", 0, "safe", "✓")
        add_breakdown("Host Identity", 0, 25)

    # ── 3. @ trick ────────────────────────────────────────────────────────────
    if "@" in raw:
        add_reason('<strong>"@" in URL</strong> — masks true destination', 18, "triggered", "✕")
        add_breakdown("URL Obfuscation", 18, 35)
    else:
        add_breakdown("URL Obfuscation", 0, 35)

    # ── 4. Punycode ───────────────────────────────────────────────────────────
    obf = next(b for b in breakdown if b["name"] == "URL Obfuscation")
    if "xn--" in hostname:
        add_reason("<strong>Punycode / IDN homograph</strong>", 25, "triggered", "✕")
        obf["pts"] += 25
    else:
        add_reason("<strong>No punycode</strong>", 0, "safe", "✓")

    # ── 5. URL length ─────────────────────────────────────────────────────────
    if len(raw) > 150:
        add_reason(f"<strong>Abnormal URL length ({len(raw)} chars)</strong>", 15, "triggered", "!")
        obf["pts"] += 15
    elif len(raw) > 75:
        add_reason(f"<strong>Long URL ({len(raw)} chars)</strong>", 7, "triggered", "!")
        obf["pts"] += 7
    else:
        add_reason(f"<strong>Normal URL length</strong> ({len(raw)} chars)", 0, "safe", "✓")

    # ── 6. Encoding ───────────────────────────────────────────────────────────
    pct = raw.count("%")
    if pct >= 5:
        add_reason(f"<strong>Heavy encoding ({pct} %)</strong>", 12, "triggered", "!")
        obf["pts"] += 12
    elif pct >= 2:
        add_reason(f"<strong>Encoded chars ({pct} %)</strong>", 5, "triggered", "!")
        obf["pts"] += 5
    else:
        add_reason("<strong>No suspicious encoding</strong>", 0, "neutral", "—")

    # ── 7. Subdomains ─────────────────────────────────────────────────────────
    dots = hostname.count(".")
    if dots >= 4:
        add_reason(f"<strong>Excessive subdomains ({dots} dots)</strong>", 15, "triggered", "!")
        add_breakdown("Subdomain Depth", 15, 15)
    elif dots == 3:
        add_reason(f"<strong>Multiple subdomains ({dots} dots)</strong>", 6, "triggered", "!")
        add_breakdown("Subdomain Depth", 6, 15)
    else:
        add_reason("<strong>Normal subdomain depth</strong>", 0, "safe", "✓")
        add_breakdown("Subdomain Depth", 0, 15)

    # ── 8. Hyphens ────────────────────────────────────────────────────────────
    if "-" in hostname:
        hyphens = hostname.count("-")
        pts = 12 if hyphens >= 2 else 8
        add_reason(f"<strong>Hyphens in domain ({hyphens})</strong>", pts, "triggered", "!")
        add_breakdown("Domain Pattern", pts, 25)
    else:
        add_reason("<strong>No hyphens in domain</strong>", 0, "safe", "✓")
        add_breakdown("Domain Pattern", 0, 25)

    # ── 9. Suspicious TLD ─────────────────────────────────────────────────────
    tld = "." + hostname.split(".")[-1]
    dp = next(b for b in breakdown if b["name"] == "Domain Pattern")
    if tld in SUSPICIOUS_TLDS:
        add_reason(f"<strong>Suspicious TLD ({tld})</strong>", 18, "triggered", "✕")
        dp["pts"] += 18
    else:
        add_reason(f"<strong>TLD ({tld})</strong> — not high-risk", 0, "safe", "✓")

    # ── 10. URL Shortener ─────────────────────────────────────────────────────
    if any(s in hostname for s in SHORTENERS):
        add_reason("<strong>URL shortener</strong>", 20, "triggered", "!")
        add_breakdown("Redirection Risk", 20, 20)
    else:
        add_breakdown("Redirection Risk", 0, 20)
        add_reason("<strong>No shortener</strong>", 0, "safe", "✓")

    # ── 11. Login keywords ────────────────────────────────────────────────────
    found = [k for k in LOGIN_KEYWORDS if k in full]
    if found:
        pts = min(15, 8 + len(found) * 3)
        add_reason(f"<strong>Login keywords</strong> — {', '.join(found[:4])}", pts, "triggered", "!")
        add_breakdown("Keyword Trap", pts, 15)
    else:
        add_reason("<strong>No login bait keywords</strong>", 0, "safe", "✓")
        add_breakdown("Keyword Trap", 0, 15)

    # ── 12. Typosquat ─────────────────────────────────────────────────────────
    domain_part = hostname.split(".")[0]
    typosquat   = None
    for pop in POPULAR_DOMAINS:
        d = levenshtein(domain_part, pop)
        if d <= 2 and domain_part != pop:
            typosquat = pop; break
        if pop in hostname and not hostname.endswith(pop+".com") and not hostname.endswith(pop+".net"):
            base = ".".join(hostname.split(".")[-2:])
            if base != pop+".com" and base != pop+".net" and pop in hostname:
                typosquat = pop; break
    if typosquat:
        add_reason(f"<strong>Possible typosquat of {typosquat}</strong>", 22, "triggered", "✕")
        add_breakdown("Brand Impersonation", 22, 25)
    else:
        hyphen_brand = next((p for p in POPULAR_DOMAINS if f"{p}-" in hostname or f"-{p}" in hostname), None)
        if hyphen_brand:
            add_reason(f"<strong>Brand + hyphen ({hyphen_brand})</strong>", 14, "triggered", "!")
            add_breakdown("Brand Impersonation", 14, 25)
        else:
            add_reason("<strong>No typosquat</strong>", 0, "safe", "✓")
            add_breakdown("Brand Impersonation", 0, 25)

    # ── 13. Port ─────────────────────────────────────────────────────────────
    port = parsed.port
    if port and port not in (80, 443):
        add_reason(f"<strong>Non-standard port :{port}</strong>", 10, "triggered", "!")
        add_breakdown("Network Anomaly", 10, 10)
    else:
        add_breakdown("Network Anomaly", 0, 10)
        add_reason("<strong>Standard port</strong>", 0, "neutral", "—")

    # ── 14. WHOIS domain age ──────────────────────────────────────────────────
    age_days, creation_str, whois_err = whois_age_days(hostname)
    if age_days is not None:
        if age_days < 30:
            add_reason(f"<strong>Very recently registered ({age_days} days ago)</strong>", 20, "triggered", "✕")
            add_breakdown("Domain Age (WHOIS)", 20, 20)
        elif age_days < 90:
            add_reason(f"<strong>Recently registered ({age_days} days)</strong>", 12, "triggered", "!")
            add_breakdown("Domain Age (WHOIS)", 12, 20)
        elif age_days < 365:
            add_reason(f"<strong>Young domain ({age_days} days)</strong>", 5, "triggered", "!")
            add_breakdown("Domain Age (WHOIS)", 5, 20)
        else:
            add_reason(f"<strong>Established domain ({age_days} days)</strong>", 0, "safe", "✓")
            add_breakdown("Domain Age (WHOIS)", 0, 20)
    else:
        has_nums = bool(re.search(r"\d", hostname))
        heuristic = len(hostname) > 20 or (has_nums and "-" in hostname)
        if heuristic:
            add_reason(f"<strong>Recently registered pattern (WHOIS: {whois_err})</strong>", 10, "triggered", "!")
            add_breakdown("Domain Age (WHOIS)", 10, 20)
        else:
            add_reason(f"<strong>Domain age unknown</strong> (WHOIS: {whois_err})", 0, "neutral", "—")
            add_breakdown("Domain Age (WHOIS)", 0, 20)

    # ── 15. URL structure ─────────────────────────────────────────────────────
    path_depth = len([p for p in parsed.path.split("/") if p])
    has_q = bool(parsed.query)
    if path_depth >= 4 or (has_q and len(raw) > 80):
        add_reason("<strong>Abnormal URL structure</strong> — deep path / complex query", 8, "triggered", "!")
        add_breakdown("Structure Anomaly", 8, 10)
    else:
        add_reason("<strong>Normal URL structure</strong>", 0, "safe", "✓")
        add_breakdown("Structure Anomaly", 0, 10)

    # ── DNS check ─────────────────────────────────────────────────────────────
    dns = dns_exists(hostname)
    if dns is False and not is_ip:
        add_reason("<strong>Domain does not resolve (NXDOMAIN)</strong>", 8, "triggered", "!")
        net = next((b for b in breakdown if b["name"] == "Network Anomaly"), None)
        if net:
            net["pts"] = min(net["max"], net["pts"] + 8)

    # ── Java feature extraction ───────────────────────────────────────────────
    java_data = call_java_analyzer(raw)
    if java_data:
        # Add Java-specific signals to reasons
        for detail in java_data.get("details", []):
            if detail.get("flagged"):
                add_reason(
                    f"<strong>[Java] {detail['name']}</strong> — {detail['message']} ({detail['value']})",
                    5, "triggered", "⚙"
                )
        # Add Java breakdown entry
        java_risk_pts = int(java_data.get("riskScore", 0) * 20)
        add_breakdown("Java Feature Analysis", java_risk_pts, 20)

    # ── ML ensemble ───────────────────────────────────────────────────────────
    ml = None
    ml_score_val = None
    heuristic_before = score
    if HAS_ML and ml_model is not None:
        try:
            ml = ml_model.predict(raw)
            ml_score_val = ml["score"] if ml else None
            if ml_score_val is not None:
                add_breakdown("ML Classifier", int(ml["prob"] * 20), 20)
                if ml["prob"] > 0.7:
                    add_reason(f"<strong>ML classifier: PHISH ({ml['prob']:.0%})</strong>", 0, "triggered", "✕")
                elif ml["prob"] > 0.5:
                    add_reason(f"<strong>ML classifier: suspicious ({ml['prob']:.0%})</strong>", 0, "triggered", "!")
                else:
                    add_reason(f"<strong>ML classifier: benign ({ml['prob']:.0%})</strong>", 0, "safe", "✓")
                blended = int(round(heuristic_before * 0.7 + ml_score_val * 0.3))
                score = max(0, min(100, blended))
        except Exception as e:
            add_reason(f"<strong>ML error</strong> — {str(e)[:60]}", 0, "neutral", "—")
            add_breakdown("ML Classifier", 0, 20)

    # ── Clamp ─────────────────────────────────────────────────────────────────
    score = max(0, min(100, score))
    for b in breakdown:
        if b["pts"] > b["max"]:
            b["pts"] = b["max"]

    # ── Risk level ────────────────────────────────────────────────────────────
    if score >= 70:
        level, desc, color = "HIGH RISK", "Strong phishing indicators. Do not enter credentials. Block and report.", "#FF3B30"
    elif score >= 35:
        level, desc, color = "MEDIUM RISK", "Suspicious patterns. Verify sender and domain.", "#FFAB00"
    else:
        level, desc, color = "LOW RISK", "No significant threats detected.", "#00E676"

    result = {
        "score":    score,
        "level":    level,
        "desc":     desc,
        "color":    color,
        "reasons":  reasons,
        "breakdown":breakdown,
        "hostname": hostname,
        "raw":      raw,
        "whois":    {"age_days": age_days, "creation_date": creation_str, "error": whois_err, "available": HAS_WHOIS},
        "dns_resolves": dns,
        "ml":       ml,
        "java":     java_data,
        "ensemble": {"heuristic": heuristic_before, "ml_score": ml_score_val, "final": score},
    }
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Flask Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Serve the main PhishShield UI."""
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({
        "status":         "ok",
        "framework":      "Flask",
        "version":        "2.1",
        "whois_available": HAS_WHOIS,
        "ml_available":   HAS_ML,
        "db_available":   HAS_DB if _db else False,
        "java_available": (JAVA_DIR / (JAVA_CLASS + ".class")).exists(),
        "time":           datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    try:
        result = analyze_url(url)
    except Exception as e:
        logger.error(f"analyze error: {e}")
        return jsonify({"error": str(e)}), 500

    # Persist to MySQL asynchronously (best-effort)
    if _db and HAS_DB:
        try:
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            scan_id = _db.save_scan(result, client_ip)
            result["scan_id"] = scan_id
        except Exception as e:
            logger.warning(f"DB save failed: {e}")

    return jsonify(result)


@app.route("/api/history")
def history():
    limit  = min(int(request.args.get("limit",  20)), 100)
    offset = int(request.args.get("offset", 0))
    if _db and HAS_DB:
        rows = _db.get_history(limit, offset)
    else:
        rows = []
    return jsonify({"history": rows, "db_available": HAS_DB})


@app.route("/api/stats")
def stats():
    if _db and HAS_DB:
        data = _db.get_stats()
    else:
        data = {}
    return jsonify({"stats": data, "db_available": HAS_DB})


@app.route("/api/scan/<int:scan_id>")
def scan_detail(scan_id: int):
    if not (_db and HAS_DB):
        return jsonify({"error": "DB not available"}), 503
    detail = _db.get_scan_detail(scan_id)
    if detail is None:
        abort(404)
    return jsonify(detail)


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logger.info("Starting PhishShield Flask server on http://localhost:5000")
    logger.info(f"  WHOIS : {HAS_WHOIS} | ML: {HAS_ML} | DB: {HAS_DB}")
    app.run(host="0.0.0.0", port=5000, debug=True)
