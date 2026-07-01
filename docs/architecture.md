# Architecture Notes

The platform has five main services:

1. `frontend`: React dashboard for viewing attacks.
2. `backend`: Express API for auth, ingestion, and stats.
3. `postgres`: persistent attack event storage.
4. `http-honeypot`: fake web login/admin surface.
5. `ssh-honeypot`: fake SSH server that rejects credentials.

The honeypots never expose a real shell, admin panel, filesystem, or database.
They only collect metadata and send it to the backend.

For learning, the project uses a shared `HONEYPOT_API_TOKEN` header between honeypots and backend. In a production system, this would be replaced or strengthened with service identity, network policies, mTLS, and stricter firewall rules.
