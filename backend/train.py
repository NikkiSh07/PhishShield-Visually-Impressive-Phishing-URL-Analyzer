"""
Train PhishShield ML classifier on synthetic URL dataset.
Features mirror heuristic engine so model learns to generalize.
Outputs: backend/model.pkl + metrics printed
"""
import re, random
from urllib.parse import urlparse
import pickle
from pathlib import Path

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
except ImportError:
    raise SystemExit("pip install scikit-learn")

SUSPICIOUS_TLDS = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".work",".date",".party",".click"}
SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl"}
POPULAR = ["google","facebook","apple","paypal","amazon","microsoft","netflix","instagram","twitter","linkedin"]
LOGIN_KW = ["login","verify","account","secure","banking","update","confirm","webscr"]

def featurize(url: str):
    raw=url.strip()
    if not re.match(r"^https?://", raw, re.I): raw="http://"+raw
    try: p=urlparse(raw)
    except: p=urlparse("http://"+raw)
    host=(p.hostname or "").lower()
    full=raw.lower()
    # 1 has_ip
    has_ip=1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0
    has_at=1 if "@" in raw else 0
    has_puny=1 if "xn--" in host else 0
    url_len=len(raw)/200.0  # normalized 0-1+
    pct=raw.count("%")/10.0
    dots=host.count(".")/5.0
    hyphens=host.count("-")/3.0
    tld="."+host.split(".")[-1] if "." in host else ""
    sus_tld=1 if tld in SUSPICIOUS_TLDS else 0
    is_short=1 if any(s in host for s in SHORTENERS) else 0
    kw_cnt=sum(1 for k in LOGIN_KW if k in full)/4.0
    # typosquat: lev dist <=2
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
    for pop in POPULAR:
        if domain_part!=pop and lev(domain_part, pop)<=2:
            typosquat=1; break
        if pop in host and not host.endswith(pop+".com"):
            typosquat=1; break
    hyphen_brand=1 if any(f"{pop}-" in host or f"-{pop}" in host for pop in POPULAR) else 0
    nonstd_port=1 if p.port and p.port not in (80,443) else 0
    young_heuristic=1 if (len(host)>20 or (bool(re.search(r"\d",host)) and "-" in host)) else 0
    path_depth=len([x for x in p.path.split("/") if x])/6.0
    has_query=1 if p.query else 0
    return [has_ip, has_at, has_puny, min(url_len,1.5), min(pct,1), min(dots,1), min(hyphens,1), sus_tld, is_short, min(kw_cnt,1), typosquat, hyphen_brand, nonstd_port, young_heuristic, min(path_depth,1), has_query]

FEATURE_NAMES=["has_ip","has_at","has_puny","url_len","pct","dots","hyphens","sus_tld","shortener","kw_cnt","typosquat","hyphen_brand","nonstd_port","young","path_depth","has_query"]

def gen_benign(n):
    benign_domains=["google.com","github.com","stackoverflow.com","wikipedia.org","amazon.com","microsoft.com","apple.com","netflix.com","linkedin.com","yahoo.com","nytimes.com","bbc.co.uk","mozilla.org","python.org","reddit.com"]
    urls=[]
    for _ in range(n):
        d=random.choice(benign_domains)
        scheme=random.choice(["https://","https://"])
        path=random.choice(["","/","/search?q=test","/about","/products","/login" if random.random()<0.15 else "/article/123"])
        # 10% http benign still benign
        if random.random()<0.05: scheme="http://"
        urls.append(scheme+d+path)
    return urls

def gen_phish(n):
    urls=[]
    for _ in range(n):
        pop=random.choice(POPULAR)
        tld=random.choice(list(SUSPICIOUS_TLDS)+[".com",".tk",".xyz"])
        # typosquat variants
        typo=pop
        if random.random()<0.7:
            # insert hyphen or char swap
            if random.random()<0.5:
                typo=pop+"-secure-login"
            else:
                # one char change
                idx=random.randrange(len(pop))
                typo=pop[:idx]+random.choice("abcdefghijklmnopqrstuvwxyz")+pop[idx+1:]
        host=f"{typo}{tld}"
        if random.random()<0.3: host=f"{random.choice(['secure','login','verify'])}.{host}"
        if random.random()<0.4: host=host.replace(".", "-")+ "." + tld.strip(".")  # extra hyphen
        scheme="http://"
        if random.random()<0.2: scheme="https://"
        path="/"+random.choice(LOGIN_KW)+random.choice(["","?session="+str(random.randint(1000,9999)),"/account/verify"])
        if random.random()<0.25: path+="".join(["%20"]*random.randint(2,4))
        if random.random()<0.15: path="//"+host+"@evil.com"  # @ trick not fully but simulate
        url=scheme+host+path
        # IP variant
        if random.random()<0.08:
            url=f"http://192.168.{random.randint(0,255)}.{random.randint(0,255)}/login"
        # shortener
        if random.random()<0.08:
            url=f"https://bit.ly/{random.randint(100000,999999)}"
        # punycode
        if random.random()<0.05:
            url="https://xn--pple-43d.com/login"
        urls.append(url)
    return urls

random.seed(42)
benign=gen_benign(1200)
phish=gen_phish(1200)
X=[featurize(u) for u in benign+phish]
y=[0]*len(benign)+[1]*len(phish)

X_train, X_test, y_train, y_test=train_test_split(X,y,test_size=0.2, random_state=42, stratify=y)
clf=RandomForestClassifier(n_estimators=120, max_depth=12, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)
pred=clf.predict(X_test)
proba=clf.predict_proba(X_test)[:,1]
acc=accuracy_score(y_test, pred)
print(f"Accuracy: {acc:.3f}")
print(classification_report(y_test, pred, target_names=["benign","phish"]))
print("Feature importances:")
for name, imp in sorted(zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: -x[1]):
    print(f"  {name:15} {imp:.3f}")

out=Path(__file__).parent/"model.pkl"
with open(out,"wb") as f:
    pickle.dump({"model": clf, "features": FEATURE_NAMES}, f)
print(f"Saved to {out} ({out.stat().st_size} bytes)")

# quick sanity
for u in ["https://google.com","http://paypal-secure-login.tk/verify/account?session=abc","https://bit.ly/3xAmz12"]:
    prob=clf.predict_proba([featurize(u)])[0,1]
    print(f"{u:55} -> {prob:.2f} ({'PHISH' if prob>0.5 else 'benign'})")
