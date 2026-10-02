"""
PhishShield Backend — FastAPI
Real WHOIS + DNS + heuristics. Mirrors frontend scoring but adds server-side signals.
Run: uvicorn app:app --reload --port 8000
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
from datetime import datetime, timezone
import re
import socket

try:
    import whois  # python-whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    from backend import ml_model as _ml
    ml_model = _ml
    HAS_ML = ml_model.available()
except Exception:
    try:
        import ml_model as _ml2
        ml_model = _ml2
        HAS_ML = ml_model.available()
    except Exception:
        HAS_ML = False
        ml_model = None

app = FastAPI(title="PhishShield API", version="2.1", description="Real-time phishing URL analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# serve frontend static if present (Docker)
try:
    from fastapi.staticfiles import StaticFiles
    from pathlib import Path
    _static_root = Path(__file__).parent.parent
    if (_static_root / "index.html").exists():
        app.mount("/static", StaticFiles(directory=str(_static_root)), name="static")
except Exception:
    pass

# ---- Config ----
SUSPICIOUS_TLDS = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".work",".date",".party",".click",".country",".stream",".download",".review",".zip",".mov"}
SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","adf.ly","shorturl.at","tiny.cc","rebrand.ly","cutt.ly"}
LOGIN_KEYWORDS = ["login","signin","sign-in","verify","verification","account","secure","banking","update","confirm","webscr","session","authenticate","password","credential"]
POPULAR_DOMAINS = ["google","facebook","apple","paypal","amazon","microsoft","netflix","instagram","twitter","linkedin","github","yahoo","whatsapp","tiktok","adobe"]

def levenshtein(a,b):
    m,n=len(a),len(b)
    dp=[[0]*(n+1) for _ in range(m+1)]
    for i in range(m+1): dp[i][0]=i
    for j in range(n+1): dp[0][j]=j
    for i in range(1,m+1):
        for j in range(1,n+1):
            dp[i][j]=min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+(0 if a[i-1]==b[j-1] else 1))
    return dp[m][n]

class AnalyzeRequest(BaseModel):
    url: str

def normalize_url(raw: str) -> str:
    raw=raw.strip()
    if not raw:
        raise ValueError("Empty URL")
    if not re.match(r"^https?://", raw, re.I):
        raw="http://"+raw
    return raw

def whois_age_days(hostname: str):
    """Returns (age_days, creation_date_str, error)"""
    if not HAS_WHOIS:
        return None, None, "python-whois not installed"
    try:
        # strip port
        domain = hostname.split(":")[0]
        # whois on IP fails fast
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            return None, None, "IP host"
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if not cd:
            return None, None, "No creation_date"
        # whois may return naive datetime
        if cd.tzinfo is None:
            cd = cd.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - cd).days
        return age, cd.isoformat(), None
    except Exception as e:
        return None, None, str(e)[:120]

def dns_exists(hostname: str) -> bool | None:
    try:
        socket.gethostbyname(hostname.split(":")[0])
        return True
    except:
        return False

def analyze_url(raw_input: str):
    raw = normalize_url(raw_input)
    try:
        parsed = urlparse(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid URL: no hostname")

    hostname = parsed.hostname.lower()
    full = raw.lower()
    path_q = (parsed.path + ("?"+parsed.query if parsed.query else "")).lower()
    reasons=[]
    breakdown=[]
    score=0

    def add_breakdown(name, pts, max_pts):
        breakdown.append({"name": name, "pts": pts, "max": max_pts})
    def add_reason(text, points, type_, icon):
        nonlocal score
        reasons.append({"text": text, "points": points, "type": type_, "icon": icon})
        if type_=="triggered":
            score+=points

    # 1 Transport
    if parsed.scheme=="http":
        add_reason("<strong>Unencrypted HTTP</strong> — no TLS",10,"triggered","!")
        add_breakdown("Transport Security",10,10)
    else:
        add_reason("<strong>HTTPS enabled</strong>",0,"safe","✓")
        add_breakdown("Transport Security",0,10)

    # 2 IP host
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    if is_ip:
        add_reason("<strong>IP address as hostname</strong>",25,"triggered","✕")
        add_breakdown("Host Identity",25,25)
    else:
        add_reason("<strong>Domain-based host</strong>",0,"safe","✓")
        add_breakdown("Host Identity",0,25)

    # 3 @ trick
    if "@" in raw:
        add_reason("<strong>“@” in URL</strong> — masks true destination",18,"triggered","✕")
        add_breakdown("URL Obfuscation",18,35)
    else:
        add_breakdown("URL Obfuscation",0,35)

    # 4 Punycode
    obf = next(b for b in breakdown if b["name"]=="URL Obfuscation")
    if "xn--" in hostname:
        add_reason("<strong>Punycode / IDN homograph</strong>",25,"triggered","✕")
        obf["pts"]+=25
    else:
        add_reason("<strong>No punycode</strong>",0,"safe","✓")

    # 5 Length
    if len(raw)>150:
        add_reason(f"<strong>Abnormal URL length ({len(raw)} chars)</strong>",15,"triggered","!")
        obf["pts"]+=15
    elif len(raw)>75:
        add_reason(f"<strong>Long URL ({len(raw)} chars)</strong>",7,"triggered","!")
        obf["pts"]+=7
    else:
        add_reason(f"<strong>Normal URL length</strong> ({len(raw)} chars)",0,"safe","✓")

    # encoding
    pct = raw.count("%")
    if pct>=5:
        add_reason(f"<strong>Heavy encoding ({pct} %)</strong>",12,"triggered","!")
        obf["pts"]+=12
    elif pct>=2:
        add_reason(f"<strong>Encoded chars ({pct} %)</strong>",5,"triggered","!")
        obf["pts"]+=5
    else:
        add_reason("<strong>No suspicious encoding</strong>",0,"neutral","—")

    # 6 subdomains
    dots = hostname.count(".")
    if dots>=4:
        add_reason(f"<strong>Excessive subdomains ({dots} dots)</strong>",15,"triggered","!")
        add_breakdown("Subdomain Depth",15,15)
    elif dots==3:
        add_reason(f"<strong>Multiple subdomains ({dots} dots)</strong>",6,"triggered","!")
        add_breakdown("Subdomain Depth",6,15)
    else:
        add_reason("<strong>Normal subdomain depth</strong>",0,"safe","✓")
        add_breakdown("Subdomain Depth",0,15)

    # 7 Hyphens
    if "-" in hostname:
        hyphens=hostname.count("-")
        pts=12 if hyphens>=2 else 8
        add_reason(f"<strong>Hyphens in domain ({hyphens})</strong>",pts,"triggered","!")
        add_breakdown("Domain Pattern",pts,25)
    else:
        add_reason("<strong>No hyphens in domain</strong>",0,"safe","✓")
        add_breakdown("Domain Pattern",0,25)
    # 8 TLD
    tld="."+hostname.split(".")[-1]
    dp = next(b for b in breakdown if b["name"]=="Domain Pattern")
    if tld in SUSPICIOUS_TLDS:
        add_reason(f"<strong>Suspicious TLD ({tld})</strong>",18,"triggered","✕")
        dp["pts"]+=18
    else:
        add_reason(f"<strong>TLD ({tld})</strong> — not high-risk",0,"safe","✓")

    # 9 Shortener
    if any(s in hostname for s in SHORTENERS):
        add_reason("<strong>URL shortener</strong>",20,"triggered","!")
        add_breakdown("Redirection Risk",20,20)
    else:
        add_breakdown("Redirection Risk",0,20)
        add_reason("<strong>No shortener</strong>",0,"safe","✓")

    # 10 Keywords
    found=[k for k in LOGIN_KEYWORDS if k in full]
    if found:
        pts=min(15, 8+len(found)*3)
        add_reason(f"<strong>Login keywords</strong> — {', '.join(found[:4])}",pts,"triggered","!")
        add_breakdown("Keyword Trap",pts,15)
    else:
        add_reason("<strong>No login bait keywords</strong>",0,"safe","✓")
        add_breakdown("Keyword Trap",0,15)

    # 11 Typosquat
    domain_part=hostname.split(".")[0]
    typosquat=None
    for pop in POPULAR_DOMAINS:
        d=levenshtein(domain_part, pop)
        if d<=2 and domain_part!=pop:
            typosquat=pop
            break
        if pop in hostname and not hostname.endswith(pop+".com") and not hostname.endswith(pop+".net"):
            base=".".join(hostname.split(".")[-2:])
            if base!=pop+".com" and base!=pop+".net" and pop in hostname:
                typosquat=pop
                break
    if typosquat:
        add_reason(f"<strong>Possible typosquat of {typosquat}</strong>",22,"triggered","✕")
        add_breakdown("Brand Impersonation",22,25)
    else:
        hyphen_brand=next((p for p in POPULAR_DOMAINS if f"{p}-" in hostname or f"-{p}" in hostname), None)
        if hyphen_brand:
            add_reason(f"<strong>Brand + hyphen ({hyphen_brand})</strong>",14,"triggered","!")
            add_breakdown("Brand Impersonation",14,25)
        else:
            add_reason("<strong>No typosquat</strong>",0,"safe","✓")
            add_breakdown("Brand Impersonation",0,25)

    # 13 Port
    port=parsed.port
    if port and port not in (80,443):
        add_reason(f"<strong>Non-standard port :{port}</strong>",10,"triggered","!")
        add_breakdown("Network Anomaly",10,10)
    else:
        add_breakdown("Network Anomaly",0,10)
        add_reason("<strong>Standard port</strong>",0,"neutral","—")

    # 14 REAL WHOIS age
    age_days, creation_str, whois_err = whois_age_days(hostname)
    if age_days is not None:
        if age_days < 30:
            add_reason(f"<strong>Very recently registered ({age_days} days ago)</strong> — high phishing correlation",20,"triggered","✕")
            add_breakdown("Domain Age (WHOIS)",20,20)
        elif age_days < 90:
            add_reason(f"<strong>Recently registered ({age_days} days)</strong>",12,"triggered","!")
            add_breakdown("Domain Age (WHOIS)",12,20)
        elif age_days < 365:
            add_reason(f"<strong>Young domain ({age_days} days)</strong>",5,"triggered","!")
            add_breakdown("Domain Age (WHOIS)",5,20)
        else:
            add_reason(f"<strong>Established domain ({age_days} days, since {creation_str[:10]})</strong>",0,"safe","✓")
            add_breakdown("Domain Age (WHOIS)",0,20)
    else:
        # fallback heuristic
        has_nums=bool(re.search(r"\d", hostname))
        heuristic = len(hostname)>20 or (has_nums and "-" in hostname)
        if heuristic:
            add_reason(f"<strong>Recently registered pattern (WHOIS: {whois_err})</strong>",10,"triggered","!")
            add_breakdown("Domain Age (WHOIS)",10,20)
        else:
            add_reason(f"<strong>Domain age unknown (WHOIS: {whois_err})</strong> — heuristic: normal",0,"neutral","—")
            add_breakdown("Domain Age (WHOIS)",0,20)

    # 15 Structure
    path_depth=len([p for p in parsed.path.split("/") if p])
    has_q=bool(parsed.query)
    if path_depth>=4 or (has_q and len(raw)>80):
        add_reason("<strong>Abnormal URL structure</strong> — deep path / complex query",8,"triggered","!")
        add_breakdown("Structure Anomaly",8,10)
    else:
        add_reason("<strong>Normal URL structure</strong>",0,"safe","✓")
        add_breakdown("Structure Anomaly",0,10)
    if not any(b["name"]=="Structure Anomaly" for b in breakdown):
        add_breakdown("Structure Anomaly",0,10)

    # DNS check (extra signal, low weight)
    dns = dns_exists(hostname)
    if dns is False and not is_ip:
        add_reason("<strong>Domain does not resolve (NXDOMAIN)</strong>",8,"triggered","!")
        # add to network anomaly
        net=next(b for b in breakdown if b["name"]=="Network Anomaly")
        net["pts"]=min(net["max"], net["pts"]+8)

    # ML ensemble
    ml = None
    ml_score = None
    heuristic_before = score
    if HAS_ML and ml_model is not None:
        try:
            ml = ml_model.predict(raw)
            ml_score = ml["score"] if ml else None
            if ml_score is not None:
                # breakdown entry for ML
                add_breakdown("ML Classifier", int(ml_score/100*20), 20)
                # add reason (does not directly add to score, ensemble blends)
                if ml["prob"] > 0.7:
                    add_reason(f"<strong>ML classifier: PHISH ({ml['prob']:.0%})</strong> — model strongly flags as phishing", 0, "triggered", "✕")
                elif ml["prob"] > 0.5:
                    add_reason(f"<strong>ML classifier: suspicious ({ml['prob']:.0%})</strong>", 0, "triggered", "!")
                else:
                    add_reason(f"<strong>ML classifier: benign ({ml['prob']:.0%})</strong>", 0, "safe", "✓")
                # ensemble: 70% heuristic + 30% ML
                blended = int(round(heuristic_before*0.7 + ml_score*0.3))
                score = max(0,min(100, blended))
                # update ML breakdown pts to reflect prob
                ml_b = next(b for b in breakdown if b["name"]=="ML Classifier")
                ml_b["pts"] = int(ml["prob"]*20)
        except Exception as e:
            add_reason(f"<strong>ML error</strong> — {str(e)[:60]}",0,"neutral","—")
            add_breakdown("ML Classifier",0,20)

    # clamp
    score=max(0,min(100,score))
    for b in breakdown:
        if b["pts"]>b["max"]:
            b["pts"]=b["max"]

    if score>=70:
        level, desc, color="HIGH RISK","Strong phishing indicators. Do not enter credentials. Block and report.","#FF3B30"
    elif score>=35:
        level, desc, color="MEDIUM RISK","Suspicious patterns. Verify sender and domain.","#FFAB00"
    else:
        level, desc, color="LOW RISK","No significant threats detected.","#00E676"

    return {
        "score": score,
        "level": level,
        "desc": desc,
        "color": color,
        "reasons": reasons,
        "breakdown": breakdown,
        "hostname": hostname,
        "raw": raw,
        "whois": {"age_days": age_days, "creation_date": creation_str, "error": whois_err, "available": HAS_WHOIS},
        "dns_resolves": dns,
        "ml": ml,
        "ensemble": {"heuristic": heuristic_before, "ml_score": ml_score, "final": score, "weight": "70% heuristic + 30% ML"},
    }

@app.get("/")
def root():
    return {"name":"PhishShield API","version":"2.1","docs":"/docs","health":"/api/health"}

@app.get("/api/health")
def health():
    return {"status":"ok","whois_available": HAS_WHOIS, "ml_available": HAS_ML, "time": datetime.now(timezone.utc).isoformat()}

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="url is required")
    result = analyze_url(req.url)
    return result
