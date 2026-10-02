FROM python:3.11-slim

WORKDIR /app

# system deps for whois
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY index.html style.css script.js ./
COPY extension ./extension

# mount frontend as static via FastAPI (if fastapi.staticfiles available)
ENV PYTHONPATH=/app
EXPOSE 8000

CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
