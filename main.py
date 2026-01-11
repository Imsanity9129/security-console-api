from fastapi import FastAPI
from datetime import datetime, timezone

app = FastAPI(
    title="Security Console API",
    version="0.1.0",
)

@app.get("/health")
def health():
    return {
        "status": "ok",
        "time_utc": datetime.now(timezone.utc).isoformat(),
    }
