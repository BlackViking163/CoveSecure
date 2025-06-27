# CoveSecure - GRC Risk Register Web App

**CoveSecure** is an advanced Governance, Risk, and Compliance (GRC) Risk Register web application, built with Flask. Designed for enterprise-grade use, it offers strong security, role-based access, insightful analytics, and seamless deployment with Docker and CI/CD pipelines.

---

## Features

### Core Functionality
- Risk Management: Add, edit, filter, and delete risks
- Role-Based User Management: Admin vs User capabilities
- Real-Time Analytics: Dynamic risk-level and status charts
- Audit Logging: Track user actions and data changes
- Export Tools: Export data to Excel or PDF

### Security Highlights
- Secure authentication (hashed passwords, sessions)
- Input validation to prevent XSS and SQL injection
- Security headers & HTTPS-ready
- Admin-only routes and actions
- Full audit trail and log rotation support

### Dev & Deployment
- Docker and Docker Compose ready
- CI/CD with GitHub Actions
- Modular architecture
- Configurable via environment variables
- Preconfigured for GCP, AWS, Azure, and Kubernetes

### UI/UX
- Clean, responsive interface
- Role-based views
- Charts using Chart.js
- Accessible forms and tables

---

## Requirements

### Runtime
- Python 3.11+
- SQLite (default) or any Flask-compatible DB
- Modern browser (Chrome/Firefox/Edge)

### Dependencies
See [`requirements.txt`](./requirements.txt) and [`requirements-dev.txt`](./requirements-dev.txt) for full list.

---

## Installation

### Local
```bash
git clone https://github.com/BlackViking163/CoveSecure.git
cd CoveSecure
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python init_db.py
python app.py
```

### Docker
```bash
docker-compose up --build
```

### Development
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
pytest
```

---

## Default Admin Login
- **Username**: admin
- **Password**: admin123

> Change immediately in production.

---

## Testing & Linting
```bash
pytest --cov=app --cov-report=html
flake8 .
black --check .
isort --check-only .
bandit -r .
safety check
```

---

## Deployment

### Production Server
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Google Cloud Run
```bash
gcloud builds submit --tag gcr.io/PROJECT-ID/covesecure
gcloud run deploy --image gcr.io/PROJECT-ID/covesecure --platform managed
```

### Kubernetes (sample manifest)
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: covesecure
spec:
  replicas: 3
  selector:
    matchLabels:
      app: covesecure
  template:
    metadata:
      labels:
        app: covesecure
    spec:
      containers:
      - name: covesecure
        image: covesecure:latest
        ports:
        - containerPort: 5000
```

---

## Dashboards & Charts
- Risk Level Breakdown
- Status Distribution
- Control Measures Overview

All visualized using Chart.js with real-time backend data.

---

## Directory Structure
```
.
├── app.py                  # Main Flask app
├── init_db.py             # DB initializer
├── requirements.txt       # Dependencies
├── templates/             # HTML templates
├── static/                # CSS, JS files
├── tests/                 # Unit & integration tests
├── docs/                  # Documentation
├── .github/workflows/     # CI/CD GitHub Actions
```

---

## Contributing
- Fork ➝ Create branch ➝ Code ➝ Test ➝ PR
- Keep 90%+ test coverage
- Adhere to PEP8, security and style checks

---

## License
MIT License. See [`LICENSE`](./LICENSE).

---
