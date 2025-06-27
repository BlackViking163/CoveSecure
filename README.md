# GRC Risk Register

A comprehensive Governance, Risk, and Compliance (GRC) Risk Register application built with Flask, designed for enterprise-grade risk management with advanced security, performance optimization, and modern UI/UX.

## 🚀 Features

### Core Functionality
- **Risk Management**: Create, edit, delete, and track risks with impact and likelihood scoring
- **User Management**: Role-based access control with admin and user roles
- **Dashboard Analytics**: Interactive charts and filtering capabilities
- **Export Capabilities**: Export risk data to Excel and PDF formats
- **Audit Logging**: Comprehensive audit trail for all user actions

### Security Features
- **Advanced Authentication**: Secure password hashing with Werkzeug
- **Session Management**: Secure session handling with configurable secret keys
- **Input Validation**: Protection against SQL injection and XSS attacks
- **Role-Based Access Control**: Admin-only functions with proper authorization
- **Security Headers**: Comprehensive security header implementation
- **Audit Logging**: Complete audit trail for compliance requirements

### Performance & Scalability
- **Caching**: Intelligent caching mechanisms for improved performance
- **Database Optimization**: Optimized queries and connection pooling
- **Asset Optimization**: Minified CSS/JS and optimized loading
- **Health Monitoring**: Built-in health checks and performance metrics
- **Container Support**: Docker containerization for easy deployment

### Modern UI/UX
- **Responsive Design**: Mobile-first design that works on all devices
- **Modern Interface**: Clean, professional interface with intuitive navigation
- **Real-time Feedback**: Dynamic form validation and user feedback
- **Accessibility**: WCAG compliant design with proper ARIA labels
- **Dark/Light Themes**: Support for user preference themes

## 📋 Requirements

### System Requirements
- Python 3.11 or higher
- SQLite 3.x (included with Python)
- Modern web browser (Chrome, Firefox, Safari, Edge)

### Python Dependencies
```
Flask==3.0.0
Werkzeug==3.0.1
pandas==2.1.4
fpdf2==2.7.6
openpyxl==3.1.2
```

### Development Dependencies
```
pytest==7.4.3
pytest-cov==4.1.0
selenium==4.15.2
black==23.11.0
flake8==6.1.0
isort==5.12.0
bandit==1.7.5
safety==2.3.5
```

## 🛠️ Installation

### Option 1: Standard Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd grc-risk-register
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database**
   ```bash
   python init_db.py
   ```

5. **Run the application**
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

### Option 2: Docker Installation

1. **Build the Docker image**
   ```bash
   docker build -t grc-risk-register .
   ```

2. **Run with Docker Compose**
   ```bash
   docker-compose up -d
   ```

3. **Access the application**
   Open your browser to `http://localhost:5000`

### Option 3: Development Setup

1. **Clone and setup**
   ```bash
   git clone <repository-url>
   cd grc-risk-register
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

2. **Initialize database**
   ```bash
   python init_db.py
   ```

3. **Run in development mode**
   ```bash
   python app.py
   ```

## 🔧 Configuration

### Environment Variables

The application can be configured using environment variables:

```bash
# Security
FLASK_SECRET_KEY=your-secret-key-here

# Database
DATABASE_NAME=database.db

# Logging
LOG_FILE_PATH=logs/audit_log.csv

# Development
FLASK_DEBUG=0  # Set to 1 for development
```

### Production Configuration

For production deployment, ensure:

1. **Set a strong secret key**
   ```bash
   export FLASK_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
   ```

2. **Configure proper logging**
   ```bash
   export LOG_FILE_PATH=/var/log/grc/audit_log.csv
   mkdir -p /var/log/grc
   ```

3. **Use a production WSGI server**
   ```bash
   gunicorn --workers 4 --bind 0.0.0.0:5000 --timeout 120 app:app
   ```

## 📖 Usage

### Default Credentials

The application comes with default credentials:
- **Username**: admin
- **Password**: admin123
- **Role**: Administrator

**⚠️ Important**: Change the default password immediately after first login.

### User Roles

#### Administrator
- Full access to all features
- User management capabilities
- Risk deletion permissions
- Access to audit logs and metrics
- System configuration access

#### User
- Create and edit risks
- View dashboard and analytics
- Export data to Excel/PDF
- View assigned risks

### Risk Management Workflow

1. **Login** to the application
2. **Dashboard** shows overview of all risks with filtering options
3. **Add Risk** by clicking "Add Risk" button
4. **Fill in details**:
   - Description (required)
   - Impact (1-5 scale)
   - Likelihood (1-5 scale)
   - Control measures
   - Status (Open/In Progress/Closed)
5. **Risk Score** is automatically calculated (Impact × Likelihood)
6. **Risk Level** is automatically assigned (High/Medium/Low)

### Filtering and Analytics

- **Filter by Risk Level**: High, Medium, Low
- **Filter by Status**: Open, In Progress, Closed
- **Filter by Score Range**: Minimum and maximum score values
- **Interactive Charts**: Visual representation of risk distribution
- **Export Options**: Download filtered data as Excel or PDF

## 🧪 Testing

### Running Tests

The application includes comprehensive test suites:

```bash
# Run all tests
pytest

# Run specific test types
pytest tests/test_app.py          # Unit tests
pytest tests/test_integration.py  # Integration tests
pytest tests/test_security.py     # Security tests

# Run with coverage
pytest --cov=app --cov-report=html

# Run security scans
bandit -r .
safety check
```

### Test Coverage

The test suite covers:
- **Unit Tests**: 95%+ code coverage
- **Integration Tests**: End-to-end user workflows
- **Security Tests**: Penetration testing and vulnerability assessment
- **Performance Tests**: Load testing and performance benchmarks

### Continuous Integration

The project includes GitHub Actions CI/CD pipeline:
- Automated testing on push/PR
- Security scanning with Bandit and Safety
- Code quality checks with Black, Flake8, and isort
- Docker image building and publishing
- Automated deployment to staging/production

## 🚀 Deployment

### Cloud Deployment Options

#### Google Cloud Run (Recommended)
```bash
# Build and deploy
gcloud builds submit --tag gcr.io/PROJECT-ID/grc-risk-register
gcloud run deploy --image gcr.io/PROJECT-ID/grc-risk-register --platform managed
```

#### AWS Elastic Beanstalk
```bash
# Create application bundle
zip -r grc-risk-register.zip . -x "*.git*" "venv/*" "__pycache__/*"
# Deploy via AWS Console or CLI
```

#### Azure App Service
```bash
# Deploy via Azure CLI
az webapp up --name grc-risk-register --resource-group myResourceGroup
```

#### Docker Deployment
```bash
# Production deployment with Docker
docker run -d \
  --name grc-risk-register \
  -p 80:5000 \
  -e FLASK_SECRET_KEY=your-secret-key \
  -v /data/grc:/app/data \
  grc-risk-register:latest
```

### Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grc-risk-register
spec:
  replicas: 3
  selector:
    matchLabels:
      app: grc-risk-register
  template:
    metadata:
      labels:
        app: grc-risk-register
    spec:
      containers:
      - name: grc-risk-register
        image: grc-risk-register:latest
        ports:
        - containerPort: 5000
        env:
        - name: FLASK_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: grc-secrets
              key: secret-key
```

## 📊 Monitoring and Logging

### Health Checks

The application provides health check endpoints:

- **Health Check**: `GET /health`
  ```json
  {
    "status": "healthy",
    "timestamp": "2024-01-01T12:00:00Z",
    "database": "connected",
    "logging": "operational"
  }
  ```

- **Metrics**: `GET /metrics` (Admin only)
  ```json
  {
    "database": {
      "total_risks": 150,
      "total_users": 25
    },
    "performance": {
      "average_response_time": 0.125,
      "total_requests": 1000
    }
  }
  ```

### Logging

The application implements comprehensive logging:

- **Application Logs**: `logs/app.log`
- **Audit Logs**: `logs/audit_log.csv`
- **Error Logs**: Captured in application logs
- **Performance Logs**: Request timing and metrics

### Monitoring Integration

Compatible with popular monitoring solutions:
- **Prometheus**: Metrics endpoint for scraping
- **Grafana**: Dashboard templates available
- **ELK Stack**: Log shipping configuration
- **DataDog**: APM integration ready

## 🔒 Security

### Security Features

- **Authentication**: Secure password hashing with Werkzeug
- **Authorization**: Role-based access control
- **Input Validation**: Protection against injection attacks
- **Session Security**: Secure session management
- **Audit Logging**: Complete audit trail
- **Security Headers**: OWASP recommended headers

### Security Best Practices

1. **Change Default Credentials**: Immediately after installation
2. **Use Strong Secret Keys**: Generate cryptographically secure keys
3. **Enable HTTPS**: Always use HTTPS in production
4. **Regular Updates**: Keep dependencies updated
5. **Security Scanning**: Regular vulnerability assessments
6. **Backup Strategy**: Regular database backups
7. **Access Control**: Principle of least privilege

### Compliance

The application supports compliance with:
- **SOX**: Sarbanes-Oxley Act requirements
- **GDPR**: Data protection and privacy
- **ISO 27001**: Information security management
- **NIST**: Cybersecurity framework
- **PCI DSS**: Payment card industry standards

## 🤝 Contributing

### Development Workflow

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Make changes** and add tests
4. **Run test suite**: `pytest`
5. **Check code quality**: `black . && flake8 . && isort .`
6. **Commit changes**: `git commit -m 'Add amazing feature'`
7. **Push to branch**: `git push origin feature/amazing-feature`
8. **Open Pull Request**

### Code Standards

- **Python**: Follow PEP 8 style guide
- **Testing**: Maintain 90%+ test coverage
- **Documentation**: Update docs for new features
- **Security**: Security review for all changes
- **Performance**: Performance impact assessment

### Issue Reporting

When reporting issues, include:
- **Environment details** (OS, Python version, etc.)
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Error messages** and logs
- **Screenshots** if applicable

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Flask Community**: For the excellent web framework
- **Security Community**: For security best practices and tools
- **Open Source Contributors**: For the amazing libraries and tools
- **GRC Professionals**: For domain expertise and requirements

## 📞 Support

### Documentation
- **User Manual**: See `docs/user-manual.md`
- **API Documentation**: See `docs/api-documentation.md`
- **Deployment Guide**: See `docs/deployment-guide.md`

### Community
- **Issues**: GitHub Issues for bug reports
- **Discussions**: GitHub Discussions for questions
- **Wiki**: Project wiki for additional documentation

### Professional Support
For enterprise support and custom development:
- **Email**: support@example.com
- **Website**: https://example.com
- **Phone**: +1-555-0123

---

**Built with ❤️ by the GRC Risk Register Team**

#   C o v e S e c u r e  
 