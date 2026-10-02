import re, pickle
from pathlib import Path
from urllib.parse import urlparse

MODEL_PATH = Path(__file__).parent / "model.pkl"
_model = None
_features = None

def _load():
    global _model, _features
    if _model is not None: return
    if not MODEL_PATH.exists():
        _model = None
        return
    with open(MODEL_PATH, "rb") as f:
        data = pickle.load(f)
        _model = data["model"]
        _features = data["features"]

def featurize(url: str):
    raw=url.strip()
    if not re.match(r"^https?://", raw, re.I): raw="http://"+raw
    try: p=urlparse(raw)
    except: p=urlparse("http://"+raw)
    host=(p.hostname or "").lower()
    full=raw.lower()
    has_ip=1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0
    has_at=1 if "@" in raw else 0
    has_puny=1 if "xn--" in host else 0
    url_len=len(raw)/200.0
    pct=raw.count("%")/10.0
    dots=host.count(".")/5.0
    hyph=host.count("-")/3.0
    tld="."+host.split(".")[-1] if "." in host else ""
    sus_tld=1 if tld in {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".work",".date",".party",".click"} else 0
    is_short=1 if any(s in host for s in ["bit.ly","tinyurl.com","t.co","goo.gl"]) else 0
    kw_cnt=sum(1 for k in ["login","verify","account","secure","banking","update","confirm","webscr"] if k in full)/4.0
    def lev(a,b):
        m,n=len(a),len(b)
        dp=[[0]*(n+1) for _ in range(m+1)]
        for i in range(m+1): dp[i][0]=i
        for j in range(n+1): dp[0][j]=j
        for i in range(1,m+1):
            for j in range(1,n+1):
                dp[i][j]=min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+(0 if a[i-1]==b[j-1] else 1))
        return dp[m][n]
    domain_part=host.split(".")[0] if host else ""
    typosquat=0
    for pop in ["google","facebook","apple","paypal","amazon","microsoft","netflix","instagram","twitter","linkedin"]:
        if domain_part!=pop and lev(domain_part, pop)<=2:
            typosquat=1; break
        if pop in host and not host.endswith(pop+".com"):
            typosquat=1; break
    hyphen_brand=1 if any(f"{pop}-" in host or f"-{pop}" in host for pop in ["google","facebook","apple","paypal","amazon","microsoft","netflix"]) else 0
    nonstd_port=1 if p.port and p.port not in (80,443) else 0
    young=1 if (len(host)>20 or (bool(re.search(r"\d",host)) and "-" in host)) else 0
    path_depth=len([x for x in p.path.split("/") if x])/6.0
    has_query=1 if p.query else 0
    return [has_ip, has_at, has_puny, min(url_len,1.5), min(pct,1), min(dots,1), min(hyph,1), sus_tld, is_short, min(kw_cnt,1), typosquat, hyphen_brand, nonstd_port, young, min(path_depth,1), has_query]

def predict(url: str):
    _load()
    if _model is None:
        return None
    vec=featurize(url)
    prob=float(_model.predict_proba([vec])[0,1])
    label="phish" if prob>0.5 else "benign"
    return {"prob": prob, "score": int(prob*100), "label": label, "available": True}

def available() -> bool:
    _load()
    return _model is not None
