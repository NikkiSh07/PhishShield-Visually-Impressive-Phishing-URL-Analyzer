import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from backend.app import app, analyze_url
from backend import ml_model

client = TestClient(app)

def ok(cond, msg):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    return cond

fails = 0
def check(cond, msg):
    global fails
    if not ok(cond, msg):
        fails += 1

print("=== PhishShield Test Suite ===")
print(f"ML available: {ml_model.available()}")
print()

# 1. Health
print("-- API Health --")
r = client.get("/api/health")
check(r.status_code == 200, f"GET /api/health 200 (got {r.status_code})")
j = r.json()
check(j["status"] == "ok", f"health status ok")
check("ml_available" in j, f"health has ml_available={j.get('ml_available')}")
check("whois_available" in j, f"health has whois_available")
print()

# 2. Benign URLs should be LOW
print("-- Benign URLs -> LOW RISK --")
benign = [
    ("https://google.com", 0, 30),
    ("https://github.com/login", None, None), # has login kw but trusted domain -> should still be LOW/MED
    ("https://example.com", 0, 30),
    ("https://stackoverflow.com/search?q=test", 0, 35),
]
for url, lo, hi in benign:
    res = analyze_url(url)
    if lo is not None:
        check(lo <= res["score"] <= hi, f"{url} score {res['score']} in [{lo},{hi}] level={res['level']}")
    else:
        check(res["level"] in ("LOW RISK","MEDIUM RISK"), f"{url} level {res['level']} score {res['score']}")
    check(res["level"] != "HIGH RISK" or "google" not in url, f"{url} not falsely HIGH")

# via API
for url,_,_ in benign:
    r = client.post("/api/analyze", json={"url": url})
    check(r.status_code == 200, f"POST /api/analyze benign {url} 200")
    check(r.json()["score"] == analyze_url(url)["score"], f"API parity for {url}")

print()

# 3. Phishing URLs should be HIGH
print("-- Phishing URLs -> HIGH RISK --")
phish = [
    "http://paypal-secure-login.tk/verify/account?session=abc",
    "http://192.168.1.23/login",
    "https://xn--pple-43d.com/login",
    "http://amazon.com-signin.suspicious-site.ga/auth",
    "https://bit.ly/3xAmz12", # shortener solo -> MED or LOW, not HIGH but should have signal
]
for url in phish:
    res = analyze_url(url)
    print(f"  {url} -> {res['score']} {res['level']} ml={res['ml']}")
    if "paypal-secure-login.tk" in url:
        check(res["score"] >= 70 and res["level"] == "HIGH RISK", f"paypal typosquat HIGH ({res['score']})")
        check(any("typosquat" in x["text"].lower() for x in res["reasons"] if x["type"]=="triggered"), "paypal typosquat reason present")
        check(any("suspicious tld" in x["text"].lower() for x in res["reasons"] if x["type"]=="triggered"), "paypal suspicious TLD")
    if "192.168" in url:
        check(any("ip address" in x["text"].lower() for x in res["reasons"] if x["type"]=="triggered"), "IP host detected")
    if "xn--" in url:
        check(any("punycode" in x["text"].lower() for x in res["reasons"] if x["type"]=="triggered"), "punycode detected")
    if "bit.ly" in url:
        check(any("shortener" in x["text"].lower() for x in res["reasons"] if x["type"]=="triggered"), "shortener detected")
        check(res["score"] >= 15, "shortener raises score")

print()

# 4. Edge cases
print("-- Edge Cases --")
# empty
r = client.post("/api/analyze", json={"url": ""})
check(r.status_code in (400,422), f"empty url rejected ({r.status_code})")
# invalid
try:
    res = analyze_url("not a url !!!!")
    # urlparse will treat as hostname? check it doesn't crash
    check(isinstance(res["score"], int), "invalid url handled without crash")
except Exception as e:
    check(False, f"invalid url crashed: {e}")

# @ trick
res = analyze_url("http://user@example.com@evil.com/login")
check(any("@" in x["text"] or "at" in x["text"].lower() for x in res["reasons"]), "@ trick handled")
# long url
long_url = "https://example.com/" + "a"*160 + "?q=" + "b"*50
res = analyze_url(long_url)
check(res["score"] >= 7, f"long url penalty ({res['score']})")
# hyphen
res = analyze_url("https://my-paypal-secure.com/login")
check(any("hyphen" in x["text"].lower() for x in res["reasons"] if x["type"]=="triggered"), "hyphen detected")
# ML
print()
print("-- ML Model --")
check(ml_model.available(), "model.pkl loadable")
p = ml_model.predict("https://google.com")
check(p["label"]=="benign" and p["prob"]<0.3, f"ML google benign prob={p['prob']:.2f}")
p = ml_model.predict("http://paypal-secure-login.tk/verify")
check(p["label"]=="phish" and p["prob"]>0.7, f"ML paypal phish prob={p['prob']:.2f}")
# ensemble blending: ml should influence final
r = analyze_url("http://paypal-secure-login.tk/verify")
check(r["ensemble"]["ml_score"] is not None, f"ensemble has ml_score {r['ensemble']['ml_score']}")
check(r["ensemble"]["final"] == r["score"], "ensemble final == score")

print()
# 5. Breakdown sanity
print("-- Breakdown --")
for url in ["https://google.com", "http://paypal-secure-login.tk/verify"]:
    res = analyze_url(url)
    for b in res["breakdown"]:
        check(b["pts"] <= b["max"], f"{url} breakdown {b['name']} {b['pts']}/{b['max']}")
        check(b["pts"] >=0, f"{url} breakdown {b['name']} non-negative")

print()
print("="*40)
if fails==0:
    print(f"ALL TESTS PASSED (0 failures)")
else:
    print(f"{fails} TEST(S) FAILED")
    sys.exit(1)
