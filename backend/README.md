# PhishShield Backend

FastAPI backend with real WHOIS + DNS checks. Mirrors the frontend 15-heuristic engine but replaces the domain-age heuristic with a live WHOIS lookup.

## Run

```powershell
cd backend
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
# docs: http://localhost:8000/docs
# health: http://localhost:8000/api/health
```

## API

POST /api/analyze
```json
{"url": "https://example.com/login"}
```
Response: `{score, level, desc, color, reasons, breakdown, hostname, whois, dns_resolves}`

GET /api/health → `{status, whois_available}`

Frontend auto-detects backend at `http://localhost:8000` and uses it if reachable, otherwise falls back to 100% client-side analysis.
