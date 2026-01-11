# Security Console API

A private FastAPI backend running on a hardened Ubuntu host. The API binds to loopback (`127.0.0.1`) and is accessible exclusively via SSH local port forwarding—no application ports are exposed.

## Architecture (SSH-only ingress)

FastAPI runs on the server at `127.0.0.1:8000` (loopback only). From a laptop, access is provided through an encrypted SSH tunnel:

`ssh -L 8000:localhost:8000 madman@10.0.0.42`
Then access the API locally on the laptop:
`curl http://127.0.0.1:8000/health`
Current Endpoints
GET /health — service status + UTC timestamp

Local Development (server)
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
Roadmap
	•	Add telemetry endpoints (/sysinfo, /ufw, /sessions)
	•	Run FastAPI as a hardened systemd service
	•	Add database storage (SQLite → Postgres) for events/alerts
	•	Add IDS logic (auth log / journal parsing) to generate alerts
	•	Build a React dashboard that consumes the API via SSH tunnel
