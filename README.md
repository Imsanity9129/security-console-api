# Security Console API

A private FastAPI backend running on a hardened Ubuntu host. The API binds to loopback (127.0.0.1) and is accessible exclusively via SSH local port forwarding. No application ports are exposed.


# Architecture (SSH-only ingress)

FastAPI runs on the server at 127.0.0.1:8000 (loopback only).

From a laptop, access is provided through an encrypted SSH tunnel using local port forwarding. Once the tunnel is established, the API is accessed locally on the laptop via localhost.

This design ensures FastAPI is never exposed directly to the network. SSH is the only ingress point, and closing the SSH session immediately removes access.


# Current Endpoints
	•	GET /health
Returns service status and the current UTC timestamp


# Local Development (server)

Development is done inside a Python virtual environment.

Steps:
	•	Create and activate a virtual environment
	•	Install dependencies from requirements.txt
	•	Run FastAPI using uvicorn bound to 127.0.0.1

The application is intentionally bound to loopback to prevent direct network access.


# Security Model
	•	No public HTTP or API ports are exposed
	•	FastAPI binds to loopback only
	•	SSH is the single externally reachable service
	•	Application access is granted explicitly via SSH port forwarding
	•	Closing the SSH tunnel immediately revokes access

This minimizes attack surface and enforces a least-exposure design.


# Roadmap
	•	Run FastAPI as a hardened systemd service
	•	Add database storage (SQLite to Postgres) for events and alerts
	•	Implement IDS-style logic (auth logs and journal parsing)
	•	Build a React dashboard that consumes the API via SSH tunnel
