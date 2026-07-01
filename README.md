# Honeypot Security Platform

A beginner-friendly cloud-native honeypot lab that shows how fake vulnerable services collect attack telemetry and display it in a security dashboard.

This project is built for learning Docker, backend APIs, PostgreSQL, React dashboards, basic networking, SSH/HTTP behavior, and Kubernetes deployment concepts.

This version intentionally keeps the architecture understandable:

- Node.js + Express backend
- PostgreSQL database
- React dashboard
- HTTP honeypot
- SSH honeypot
- Docker Compose
- Starter Kubernetes manifests

## Preview

The dashboard shows total attacks, attacks today, active honeypots, service distribution, top passwords, and a live attack feed.

## Architecture

```text
HTTP/SSH clients
      |
      v
HTTP Honeypot / SSH Honeypot
      |
      | POST /attack
      v
Express Backend
      |
      v
PostgreSQL
      |
      v
React Dashboard
```

## Project Structure

```text
.
├── backend/              # Express API, auth, stats, database access
├── frontend/             # React dashboard
├── honeypots/
│   ├── http/             # Fake HTTP admin page
│   └── ssh/              # Fake SSH server
├── k8s/                  # Starter Kubernetes manifests
├── docs/                 # Architecture notes
├── docker-compose.yml    # Local multi-container setup
└── .env.example          # Environment variable template
```

## Services

| Service | Local URL / Port | Purpose |
| --- | --- | --- |
| Frontend | http://localhost:3000 | Dashboard |
| Backend | http://localhost:8000 | API |
| PostgreSQL | localhost:5432 | Attack storage |
| HTTP Honeypot | http://localhost:8080 | Fake admin site |
| SSH Honeypot | localhost:2222 | Fake SSH server |

## Environment Variables

Copy `.env.example` to `.env` if you want to customize values.

Important variables:

- `DATABASE_URL`: PostgreSQL connection string used by the backend.
- `JWT_SECRET_KEY`: signs dashboard login tokens.
- `DASHBOARD_ADMIN_USERNAME`: dashboard username.
- `DASHBOARD_ADMIN_PASSWORD`: dashboard password.
- `HONEYPOT_API_TOKEN`: shared internal token used by honeypots when reporting events.
- `BACKEND_ATTACK_ENDPOINT`: backend URL used by honeypots.

## Run Locally With Docker

Start Docker Desktop first, then run:

```bash
docker compose up --build
```

Then open:

```text
http://localhost:3000
```

Default login:

```text
username: admin
password: admin123
```

Generate a fake HTTP event:

```bash
curl http://localhost:8080/admin
```

Generate a fake SSH event:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no root@localhost -p 2222
```

If prompted to trust the host, type `yes`. Enter any fake password. The login will be rejected and logged in the dashboard.

Stop the project:

```bash
docker compose down
```

## API Endpoints

Public:

- `GET /health`
- `POST /auth/login`

Honeypot internal:

- `POST /attack`

Dashboard authenticated:

- `GET /attacks`
- `GET /stats`
- `GET /top-ip`
- `GET /top-passwords`
- `GET /countries`
- `GET /timeline`
- `GET /services`

## Kubernetes Learning Path

The `k8s/` folder contains starter manifests for:

- Namespace
- ConfigMap
- Secret
- PostgreSQL
- Backend
- Frontend
- HTTP honeypot
- SSH honeypot

Once Docker Compose works, apply them with:

```bash
kubectl apply -f k8s/
```

Scale the SSH honeypot:

```bash
kubectl -n security-platform scale deployment ssh-honeypot --replicas=3
```

## What This Project Demonstrates

- TCP/HTTP/SSH basics
- Fake service design
- API ingestion
- PostgreSQL schema and indexes
- JWT dashboard authentication
- Dockerized microservices
- Kubernetes Deployments and Services
- Basic security event analytics

## Security Note

This is a learning project. Do not expose it directly to the public internet without proper cloud isolation, firewall rules, resource limits, monitoring, and legal permission.

## Future Improvements

- Real GeoIP database support
- Prometheus and Grafana
- Alerting through Discord or Slack
- Suspicious IP detection
- More honeypot protocols such as FTP, Telnet, Redis, and MySQL
