# PhishShield — Visually Impressive Phishing URL Analyzer

> Paste `https://example.com/login` → get `Risk Score: 87/100 HIGH RISK` with explainable reasons. 100% local fallback, optional Python backend for real WHOIS + ML.

![stack](https://img.shields.io/badge/frontend-HTML%2FCSS%2FJS-0A0E14) ![api](https://img.shields.io/badge/backend-FastAPI-009688) ![ml](https://img.shields.io/badge/ML-RandomForest-orange)

## Features — 15+ heuristics + ML ensemble
- Transport (HTTP vs HTTPS), IP host, `@` trick, punycode `xn--`, length, encoding
- Subdomain depth, hyphens, suspicious TLDs (`.tk/.ml/.xyz`), shorteners (`bit.ly`)
- Login keywords, typosquat (Levenshtein ≤2 vs 15 popular brands), brand+hyphen
- Non-standard port, WHOIS age (real `python-whois` or heuristic), path depth, NXDOMAIN
- **ML ensemble**: 120-tree RandomForest on 16 URL features — final = `70% heuristics + 30% ML` (`backend/train.py:1`, `backend/ml_model.py:1`)

## Quick Start (frontend only — no install)
```powershell
# just open
start index.html
```

## With Backend (real WHOIS + ML)
```powershell
cd backend
pip install -r requirements.txt
python train.py          # generates model.pkl (once)
uvicorn app:app --reload --port 8000
# http://localhost:8000/docs  http://localhost:8000/api/health
```
Frontend auto-detects `http://localhost:8000` — if reachable uses backend, else 100% local (`script.js:16`).

API:
```
POST /api/analyze {"url":"https://example.com/login"}
→ {score, level, color, reasons, breakdown, hostname, whois, dns_resolves, ml, ensemble}
GET /api/health → {status, whois_available, ml_available}
```

## Chrome Extension
```
chrome://extensions → Developer mode → Load unpacked → select `extension/` folder
# or install zip
```
Popup (`extension/popup.html:1`) reads active tab, runs same heuristics locally, tries backend if running. Build zip: `PhishShield-extension-v2.1.zip` (already built).

## Docker
```powershell
docker-compose up --build
# http://localhost:8000  (API)
# http://localhost:8000/docs
```
`Dockerfile:1` — python:3.11-slim + `backend/requirements.txt`.

## Project Layout
```
index.html      # impressive UI + gauge + extension preview
style.css       # cyber dark theme
script.js       # client heuristics + backend auto-detect
backend/
  app.py        # FastAPI + WHOIS + DNS + ML ensemble
  ml_model.py   # loads model.pkl
  train.py      # synthetic 2400 URLs → RandomForest
  model.pkl     # 362 KB
  requirements.txt
extension/
  manifest.json # MV3
  popup.html/js # compact analyzer
  icon*.png
Dockerfile, docker-compose.yml
```

## Demo URLs
- `https://google.com` → LOW (0)
- `http://paypal-secure-login.tk/verify/account?session=abc` → HIGH (95-96)
- `http://192.168.1.23/login` → MEDIUM (52, IP host)
- `https://bit.ly/3xAmz12` → LOW-MED (shortener solo)
- `https://xn--pple-43d.com/login` → MED-HIGH (punycode)
