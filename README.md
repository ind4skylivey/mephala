<p align="center">
  <img src="https://img.shields.io/badge/🍯-HoneyTrap-ff6b6b?style=for-the-badge&labelColor=1a1a2e" alt="HoneyTrap"/>
</p>

<h1 align="center">
  <code>HoneyTrap</code>
</h1>

<p align="center">
  <strong>Intelligent Honeypot System with ML-Powered Threat Classification</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-00d4ff?style=flat-square&logo=python&logoColor=white&labelColor=0d1117" alt="Python"/>
  <img src="https://img.shields.io/badge/fastapi-0.108+-00d4ff?style=flat-square&logo=fastapi&logoColor=white&labelColor=0d1117" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/vue.js-3.4+-00d4ff?style=flat-square&logo=vue.js&logoColor=white&labelColor=0d1117" alt="Vue.js"/>
  <img src="https://img.shields.io/badge/docker-ready-00d4ff?style=flat-square&logo=docker&logoColor=white&labelColor=0d1117" alt="Docker"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-155_passing-00ff88?style=flat-square&labelColor=0d1117" alt="Tests"/>
  <img src="https://img.shields.io/badge/coverage-85%25-00ff88?style=flat-square&labelColor=0d1117" alt="Coverage"/>
  <img src="https://img.shields.io/badge/license-MIT-ff6b6b?style=flat-square&labelColor=0d1117" alt="License"/>
</p>

<br/>

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

## ⚡ Overview

**HoneyTrap** is a high-interaction honeypot system designed to simulate vulnerable network services, capture real-world attack patterns, and classify threats using machine learning.

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│   ╭─────────╮    ╭─────────╮    ╭─────────╮    ╭─────────╮      │
│   │   SSH   │    │  HTTP   │    │   FTP   │    │   ML    │      │
│   │  :2222  │    │  :8080  │    │  :2121  │    │ Engine  │      │
│   ╰────┬────╯    ╰────┬────╯    ╰────┬────╯    ╰────┬────╯      │
│        │              │              │              │            │
│        └──────────────┴──────────────┴──────────────┘            │
│                           │                                      │
│                    ╭──────┴──────╮                               │
│                    │  PostgreSQL │                               │
│                    │    Redis    │                               │
│                    ╰──────┬──────╯                               │
│                           │                                      │
│                    ╭──────┴──────╮                               │
│                    │  Dashboard  │                               │
│                    │   :3000     │                               │
│                    ╰─────────────╯                               │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

## 🎯 Features

<table>
<tr>
<td width="50%">

### 🔐 SSH Honeypot
- Credential harvesting
- Fake shell with 25+ commands
- Virtual filesystem (`/etc/passwd`, `/etc/shadow`)
- Session recording & command logging
- Malicious payload detection

</td>
<td width="50%">

### 🌐 HTTP Honeypot
- WordPress & phpMyAdmin simulation
- Admin panel honeytokens
- SQLi / XSS / RCE detection
- File upload capture
- Request payload logging

</td>
</tr>
<tr>
<td width="50%">

### 📁 FTP Honeypot
- Anonymous & authenticated access
- Passive/Active mode support
- File upload/download capture
- Directory traversal logging
- Malware quarantine

</td>
<td width="50%">

### 🧠 ML Classification
- Random Forest attack classifier
- Isolation Forest anomaly detection
- Real-time threat scoring
- Auto-labeling pipeline
- Model versioning & metrics

</td>
</tr>
</table>

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

## 🚀 Quick Start

### Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/ind4skylivey/honeytrap.git
cd honeytrap

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Launch all services
cd docker && docker-compose up -d

# View logs
docker-compose logs -f honeytrap
```

### Manual Installation

```bash
# Clone and setup
git clone https://github.com/ind4skylivey/honeytrap.git
cd honeytrap

# Run setup script
chmod +x scripts/setup.sh
./scripts/setup.sh

# Start PostgreSQL and Redis (required)
# Then run migrations
alembic upgrade head

# Start honeypot services
python core/honeypot.py

# Start API (separate terminal)
uvicorn api.server:app --reload --port 8000

# Start dashboard (separate terminal)
cd dashboard && npm install && npm run dev
```

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

## 📊 Dashboard

<table>
<tr>
<td align="center">
<strong>Real-time Attack Feed</strong><br/>
<sub>Live WebSocket updates with severity indicators</sub>
</td>
<td align="center">
<strong>Geographic Map</strong><br/>
<sub>Attack origins with Leaflet visualization</sub>
</td>
</tr>
<tr>
<td align="center">
<strong>Timeline Charts</strong><br/>
<sub>Attack frequency over time with Chart.js</sub>
</td>
<td align="center">
<strong>Attack Analytics</strong><br/>
<sub>Type distribution, top attackers, statistics</sub>
</td>
</tr>
</table>

**Access Points:**
| Service | URL | Description |
|---------|-----|-------------|
| Dashboard | `http://localhost:3000` | Vue.js frontend |
| API Docs | `http://localhost:8000/docs` | Swagger UI |
| WebSocket | `ws://localhost:8000/ws/live` | Real-time feed |

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

## 🏗️ Architecture

```
honeytrap/
├── core/                   # System nucleus
│   ├── base_service.py     # Abstract honeypot base class
│   ├── config.py           # Pydantic configuration
│   ├── database.py         # SQLAlchemy async ORM
│   ├── honeypot.py         # Main orchestrator
│   └── logger.py           # Structured logging
│
├── services/               # Honeypot implementations
│   ├── ssh_honeypot.py     # SSH with asyncssh
│   ├── http_honeypot.py    # HTTP with aiohttp
│   ├── ftp_honeypot.py     # FTP with asyncio
│   └── utils/              # Fake FS, templates, sessions
│
├── ml/                     # Machine learning pipeline
│   ├── preprocessor.py     # Feature extraction
│   ├── models.py           # RF classifier, Isolation Forest
│   ├── trainer.py          # Training pipeline
│   └── predictor.py        # Real-time classification
│
├── api/                    # FastAPI REST API
│   ├── server.py           # Application factory
│   ├── auth.py             # JWT authentication
│   └── routes/             # Endpoint definitions
│
├── dashboard/              # Vue.js 3 frontend
│   └── src/
│       ├── components/     # Reusable UI components
│       ├── views/          # Page components
│       └── stores/         # Pinia state management
│
└── docker/                 # Containerization
    ├── Dockerfile          # Multi-stage build
    ├── docker-compose.yml  # Service orchestration
    └── nginx.conf          # Reverse proxy
```

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

## 🔧 Configuration

### Environment Variables

```bash
# Core
HONEYTRAP_ENV=production
DEBUG=false

# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/honeytrap

# Redis
REDIS_URL=redis://localhost:6379/0

# API
API_SECRET_KEY=your-secure-secret-key
API_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Services
SSH_PORT=2222
HTTP_PORT=8080
FTP_PORT=2121

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

### Service Configuration

```yaml
# config/honeypot.yml
ssh:
  enabled: true
  port: 2222
  banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
  fake_users: [root, admin, ubuntu]

http:
  enabled: true
  port: 8080
  server_header: "Apache/2.4.52 (Ubuntu)"

ftp:
  enabled: true
  port: 2121
  anonymous_enabled: true
```

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=core --cov=services --cov=ml --cov=api

# Specific module
pytest tests/unit/test_base_service.py -v
```

**Test Coverage:**
- ✅ 155 tests passing
- ✅ Unit tests for all core modules
- ✅ Integration tests for services
- ✅ Async test support with pytest-asyncio

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

## 🤖 ML Pipeline

### Train Models

```bash
# Generate synthetic data and train
python scripts/train_models.py --synthetic 5000 --version v1

# Train with custom data
python scripts/train_models.py --data attacks.csv --tune

# Models saved to ml/models/
```

### Attack Classification

The ML engine classifies attacks into:

| Type | Description | Severity |
|------|-------------|----------|
| `reconnaissance` | Port scanning, enumeration | 🟢 Low |
| `brute_force` | Credential stuffing | 🟡 Medium |
| `sql_injection` | Database attacks | 🔴 High |
| `xss` | Cross-site scripting | 🟡 Medium |
| `rce` | Remote code execution | 🔴 Critical |
| `path_traversal` | Directory traversal | 🟠 High |
| `credential_theft` | Password harvesting | 🟠 High |

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

## 📡 API Reference

### Authentication

```bash
# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Response
{"access_token": "eyJ...", "token_type": "bearer"}
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/attacks` | List attacks (paginated) |
| `GET` | `/api/v1/attacks/{id}` | Attack details |
| `POST` | `/api/v1/attacks/search` | Advanced search |
| `GET` | `/api/v1/stats/overview` | Dashboard stats |
| `GET` | `/api/v1/stats/timeline` | Attack timeline |
| `GET` | `/api/v1/stats/geographic` | Geo distribution |
| `WS` | `/ws/live` | Real-time feed |

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

## ⚠️ Legal Disclaimer

> **This software is intended for authorized security research and educational purposes only.**
>
> - Deploy only on networks you own or have explicit permission to test
> - Ensure compliance with local laws and regulations
> - Do not use captured data for malicious purposes
> - The authors are not responsible for misuse of this software

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

## 📜 License

```
MIT License

Copyright (c) 2024 ind4skylivey

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

<p align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%"/>
</p>

<p align="center">
  <sub>Built with ☕ by <a href="https://github.com/ind4skylivey">ind4skylivey</a></sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Made%20with-Python-ff6b6b?style=for-the-badge&logo=python&logoColor=white&labelColor=0d1117"/>
  <img src="https://img.shields.io/badge/Powered%20by-AsyncIO-00d4ff?style=for-the-badge&logo=python&logoColor=white&labelColor=0d1117"/>
</p>
