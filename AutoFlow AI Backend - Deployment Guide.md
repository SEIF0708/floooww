# AutoFlow AI Backend - Deployment Guide

This comprehensive guide covers deploying the AutoFlow AI backend system in various environments, from local development to production servers.

## Table of Contents

1. [Local Development Setup](#local-development-setup)
2. [Production Deployment](#production-deployment)
3. [Database Configuration](#database-configuration)
4. [Security Configuration](#security-configuration)
5. [Performance Optimization](#performance-optimization)
6. [Monitoring and Logging](#monitoring-and-logging)
7. [Backup and Recovery](#backup-and-recovery)
8. [Troubleshooting](#troubleshooting)

## Local Development Setup

### Prerequisites

Ensure you have the following installed on your development machine:

- **Python 3.11+**: The application requires Python 3.11 or higher
- **pip**: Python package installer
- **Virtual Environment**: For dependency isolation
- **Git**: For version control (optional)

### Quick Start

The backend is already configured and ready to run. Follow these steps:

1. **Navigate to the project directory**:
   ```bash
   cd autoflow_backend
   ```

2. **Activate the virtual environment**:
   ```bash
   source venv/bin/activate
   ```

3. **Verify dependencies** (already installed):
   ```bash
   pip list
   ```

4. **Start the development server**:
   ```bash
   python src/main.py
   ```

5. **Verify the installation**:
   - Open http://localhost:5000 in your browser
   - Check the health endpoint: http://localhost:5000/api/health
   - Test the login page: http://localhost:5000/login.html

### Development Configuration

The current development configuration includes:

```python
# Development settings in src/main.py
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/app.db'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# CORS enabled for all origins (development only)
CORS(app, origins="*")

# Debug mode enabled
app.run(host='0.0.0.0', port=5000, debug=True)
```

## Production Deployment

### Environment Preparation

For production deployment, you'll need to modify several configuration aspects:

#### 1. Update Secret Keys

**Critical**: Change the default secret keys before production deployment.

```python
import secrets

# Generate secure secret keys
SECRET_KEY = secrets.token_urlsafe(32)
JWT_SECRET_KEY = secrets.token_urlsafe(32)
```

#### 2. Environment Variables

Create a `.env` file for production configuration:

```bash
# .env file
FLASK_ENV=production
SECRET_KEY=your-super-secure-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here
DATABASE_URL=postgresql://username:password@localhost/autoflow_db
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

#### 3. Production Configuration File

Create `src/config.py`:

```python
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'dev-jwt-secret'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database/app.db'

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://username:password@localhost/autoflow_db'

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
```

#### 4. Update Main Application

Modify `src/main.py` for production:

```python
import os
from flask import Flask, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from src.models.user import db
from src.routes.user import user_bp
from src.routes.auth import auth_bp
from src.config import config

def create_app(config_name=None):
    app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))
    
    # Load configuration
    config_name = config_name or os.environ.get('FLASK_ENV', 'default')
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    jwt = JWTManager(app)
    bcrypt = Bcrypt(app)
    
    # Configure CORS for production
    cors_origins = os.environ.get('CORS_ORIGINS', '*').split(',')
    CORS(app, origins=cors_origins)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(user_bp, url_prefix='/api/user')
    
    # Create tables
    with app.app_context():
        db.create_all()
    
    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
```

### Web Server Configuration

#### Using Gunicorn (Recommended)

1. **Install Gunicorn**:
   ```bash
   pip install gunicorn
   ```

2. **Create Gunicorn configuration** (`gunicorn.conf.py`):
   ```python
   bind = "0.0.0.0:5000"
   workers = 4
   worker_class = "sync"
   worker_connections = 1000
   timeout = 30
   keepalive = 2
   max_requests = 1000
   max_requests_jitter = 100
   preload_app = True
   ```

3. **Start with Gunicorn**:
   ```bash
   gunicorn --config gunicorn.conf.py src.main:app
   ```

#### Using uWSGI

1. **Install uWSGI**:
   ```bash
   pip install uwsgi
   ```

2. **Create uWSGI configuration** (`uwsgi.ini`):
   ```ini
   [uwsgi]
   module = src.main:app
   master = true
   processes = 4
   socket = /tmp/autoflow.sock
   chmod-socket = 666
   vacuum = true
   die-on-term = true
   ```

3. **Start with uWSGI**:
   ```bash
   uwsgi --ini uwsgi.ini
   ```

### Reverse Proxy Configuration

#### Nginx Configuration

Create `/etc/nginx/sites-available/autoflow`:

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;
    
    # SSL Configuration
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    
    # Static files
    location /static/ {
        alias /path/to/autoflow_backend/src/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # API and application
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://127.0.0.1:5000;
        # ... other proxy settings
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/autoflow /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## Database Configuration

### SQLite (Development)

The current setup uses SQLite, which is perfect for development and small-scale deployments:

```python
SQLALCHEMY_DATABASE_URI = 'sqlite:///database/app.db'
```

### PostgreSQL (Production Recommended)

For production, PostgreSQL is recommended:

1. **Install PostgreSQL**:
   ```bash
   sudo apt update
   sudo apt install postgresql postgresql-contrib
   ```

2. **Create database and user**:
   ```sql
   sudo -u postgres psql
   CREATE DATABASE autoflow_db;
   CREATE USER autoflow_user WITH PASSWORD 'secure_password';
   GRANT ALL PRIVILEGES ON DATABASE autoflow_db TO autoflow_user;
   \q
   ```

3. **Install Python PostgreSQL adapter**:
   ```bash
   pip install psycopg2-binary
   ```

4. **Update database URI**:
   ```python
   SQLALCHEMY_DATABASE_URI = 'postgresql://autoflow_user:secure_password@localhost/autoflow_db'
   ```

### MySQL (Alternative)

For MySQL deployment:

1. **Install MySQL**:
   ```bash
   sudo apt install mysql-server
   ```

2. **Create database**:
   ```sql
   mysql -u root -p
   CREATE DATABASE autoflow_db;
   CREATE USER 'autoflow_user'@'localhost' IDENTIFIED BY 'secure_password';
   GRANT ALL PRIVILEGES ON autoflow_db.* TO 'autoflow_user'@'localhost';
   FLUSH PRIVILEGES;
   EXIT;
   ```

3. **Install Python MySQL adapter**:
   ```bash
   pip install PyMySQL
   ```

4. **Update database URI**:
   ```python
   SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://autoflow_user:secure_password@localhost/autoflow_db'
   ```

### Database Migration

For production deployment with existing data:

1. **Backup existing data**:
   ```bash
   # For SQLite
   cp src/database/app.db src/database/app.db.backup
   
   # For PostgreSQL
   pg_dump autoflow_db > autoflow_backup.sql
   ```

2. **Create migration script** (`migrate.py`):
   ```python
   from src.main import create_app
   from src.models.user import db
   
   app = create_app('production')
   with app.app_context():
       db.create_all()
       print("Database tables created successfully")
   ```

3. **Run migration**:
   ```bash
   python migrate.py
   ```

## Security Configuration

### SSL/TLS Certificate

#### Using Let's Encrypt (Free)

1. **Install Certbot**:
   ```bash
   sudo apt install certbot python3-certbot-nginx
   ```

2. **Obtain certificate**:
   ```bash
   sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
   ```

3. **Auto-renewal**:
   ```bash
   sudo crontab -e
   # Add this line:
   0 12 * * * /usr/bin/certbot renew --quiet
   ```

### Firewall Configuration

Configure UFW (Ubuntu Firewall):

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

### Application Security

#### Rate Limiting

Install Flask-Limiter:

```bash
pip install Flask-Limiter
```

Add to your application:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Apply to specific routes
@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # ... login logic
```

#### Input Sanitization

The application already includes comprehensive input validation. Ensure all user inputs are validated:

```python
from src.utils.validators import Validator

# Example usage
is_valid, errors = Validator.validate_email(email)
if not is_valid:
    return jsonify({'error': 'Invalid email'}), 400
```

## Performance Optimization

### Database Optimization

1. **Add database indexes**:
   ```python
   # In user model
   email = db.Column(db.String(120), unique=True, nullable=False, index=True)
   created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
   ```

2. **Connection pooling**:
   ```python
   app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
       'pool_size': 10,
       'pool_recycle': 120,
       'pool_pre_ping': True
   }
   ```

### Caching

Implement Redis caching:

1. **Install Redis**:
   ```bash
   sudo apt install redis-server
   pip install redis Flask-Caching
   ```

2. **Configure caching**:
   ```python
   from flask_caching import Cache
   
   cache = Cache(app, config={
       'CACHE_TYPE': 'redis',
       'CACHE_REDIS_URL': 'redis://localhost:6379/0'
   })
   
   @cache.cached(timeout=300)
   def get_user_stats(user_id):
       # ... expensive operation
   ```

### Static File Optimization

1. **Enable Gzip compression** in Nginx:
   ```nginx
   gzip on;
   gzip_vary on;
   gzip_min_length 1024;
   gzip_types text/plain text/css application/json application/javascript;
   ```

2. **Set proper cache headers**:
   ```nginx
   location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
       expires 1y;
       add_header Cache-Control "public, immutable";
   }
   ```

## Monitoring and Logging

### Application Logging

Configure structured logging:

```python
import logging
from logging.handlers import RotatingFileHandler

if not app.debug:
    file_handler = RotatingFileHandler('logs/autoflow.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('AutoFlow AI Backend startup')
```

### System Monitoring

#### Using systemd for process management

Create `/etc/systemd/system/autoflow.service`:

```ini
[Unit]
Description=AutoFlow AI Backend
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/autoflow_backend
Environment=PATH=/path/to/autoflow_backend/venv/bin
ExecStart=/path/to/autoflow_backend/venv/bin/gunicorn --config gunicorn.conf.py src.main:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable autoflow
sudo systemctl start autoflow
```

#### Health Monitoring

Create a health check script (`health_check.py`):

```python
import requests
import sys

try:
    response = requests.get('http://localhost:5000/api/health', timeout=10)
    if response.status_code == 200:
        print("Service is healthy")
        sys.exit(0)
    else:
        print(f"Service returned status {response.status_code}")
        sys.exit(1)
except Exception as e:
    print(f"Health check failed: {e}")
    sys.exit(1)
```

Add to crontab for monitoring:
```bash
*/5 * * * * /path/to/autoflow_backend/venv/bin/python /path/to/health_check.py
```

## Backup and Recovery

### Database Backup

#### Automated PostgreSQL Backup

Create backup script (`backup.sh`):

```bash
#!/bin/bash
BACKUP_DIR="/backups/autoflow"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/autoflow_backup_$DATE.sql"

mkdir -p $BACKUP_DIR

pg_dump autoflow_db > $BACKUP_FILE

# Compress the backup
gzip $BACKUP_FILE

# Keep only last 7 days of backups
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_FILE.gz"
```

Add to crontab:
```bash
0 2 * * * /path/to/backup.sh
```

#### Application Files Backup

```bash
#!/bin/bash
BACKUP_DIR="/backups/autoflow"
DATE=$(date +%Y%m%d_%H%M%S)
APP_DIR="/path/to/autoflow_backend"

tar -czf "$BACKUP_DIR/app_backup_$DATE.tar.gz" \
    --exclude="$APP_DIR/venv" \
    --exclude="$APP_DIR/__pycache__" \
    --exclude="$APP_DIR/*.log" \
    "$APP_DIR"
```

### Recovery Procedures

#### Database Recovery

```bash
# Stop the application
sudo systemctl stop autoflow

# Restore from backup
gunzip -c /backups/autoflow/autoflow_backup_YYYYMMDD_HHMMSS.sql.gz | psql autoflow_db

# Start the application
sudo systemctl start autoflow
```

#### Application Recovery

```bash
# Extract backup
tar -xzf /backups/autoflow/app_backup_YYYYMMDD_HHMMSS.tar.gz -C /tmp

# Copy files (be careful with configuration)
cp -r /tmp/autoflow_backend/* /path/to/autoflow_backend/

# Restart services
sudo systemctl restart autoflow
sudo systemctl restart nginx
```

## Troubleshooting

### Common Issues

#### 1. Database Connection Errors

**Symptoms**: `sqlalchemy.exc.OperationalError`

**Solutions**:
- Check database service status: `sudo systemctl status postgresql`
- Verify connection string in configuration
- Check database user permissions
- Ensure database exists

#### 2. Permission Errors

**Symptoms**: `PermissionError` when starting application

**Solutions**:
```bash
# Fix file permissions
sudo chown -R www-data:www-data /path/to/autoflow_backend
sudo chmod -R 755 /path/to/autoflow_backend

# Fix log directory permissions
sudo mkdir -p /var/log/autoflow
sudo chown www-data:www-data /var/log/autoflow
```

#### 3. Port Already in Use

**Symptoms**: `Address already in use`

**Solutions**:
```bash
# Find process using port 5000
sudo lsof -i :5000

# Kill the process
sudo kill -9 <PID>

# Or use a different port
export PORT=5001
```

#### 4. JWT Token Issues

**Symptoms**: `Invalid token` errors

**Solutions**:
- Verify JWT secret key consistency
- Check token expiration settings
- Ensure proper Authorization header format: `Bearer <token>`

#### 5. CORS Errors

**Symptoms**: Browser console shows CORS errors

**Solutions**:
```python
# Update CORS configuration
CORS(app, origins=['https://yourdomain.com'], supports_credentials=True)
```

### Debugging

#### Enable Debug Mode

For development debugging:

```python
app.config['DEBUG'] = True
app.config['SQLALCHEMY_ECHO'] = True  # Log SQL queries
```

#### Log Analysis

```bash
# View recent logs
tail -f /path/to/autoflow_backend/flask.log

# Search for errors
grep -i error /path/to/autoflow_backend/flask.log

# View system logs
sudo journalctl -u autoflow -f
```

### Performance Issues

#### Database Performance

```sql
-- Check slow queries (PostgreSQL)
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;
```

#### Application Performance

```python
# Add timing middleware
import time
from flask import request

@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    duration = time.time() - request.start_time
    app.logger.info(f'{request.method} {request.path} - {response.status_code} - {duration:.3f}s')
    return response
```

## Maintenance

### Regular Maintenance Tasks

1. **Weekly**:
   - Review application logs
   - Check disk space usage
   - Verify backup integrity

2. **Monthly**:
   - Update system packages
   - Review security logs
   - Performance analysis

3. **Quarterly**:
   - Security audit
   - Dependency updates
   - Capacity planning

### Update Procedures

#### Application Updates

```bash
# Backup current version
cp -r /path/to/autoflow_backend /path/to/autoflow_backend.backup

# Update code
git pull origin main  # or copy new files

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt

# Run migrations if needed
python migrate.py

# Restart services
sudo systemctl restart autoflow
```

#### System Updates

```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Update Python packages
pip list --outdated
pip install --upgrade package_name

# Restart services after updates
sudo systemctl restart autoflow nginx
```

This deployment guide provides comprehensive instructions for deploying the AutoFlow AI backend in various environments. Follow the appropriate sections based on your deployment needs and environment requirements.

---

**Created by**: Manus AI  
**Version**: 1.0.0  
**Last Updated**: June 25, 2025

