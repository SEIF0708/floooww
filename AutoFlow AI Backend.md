# AutoFlow AI Backend

A complete Flask-based backend system for the AutoFlow AI platform, providing user authentication, registration, and management functionality with JWT-based security.

## Overview

This backend system is designed to support the AutoFlow AI frontend landing page with comprehensive user management capabilities. It includes secure user registration, authentication, profile management, and password reset functionality, all built with modern security practices and scalable architecture.

## Features

### Authentication & Security
- **JWT-based Authentication**: Secure token-based authentication with access and refresh tokens
- **Password Security**: bcrypt hashing with salt rounds for secure password storage
- **Input Validation**: Comprehensive server-side validation for all user inputs
- **CORS Support**: Cross-origin resource sharing enabled for frontend integration
- **Rate Limiting Ready**: Architecture prepared for rate limiting implementation
- **SQL Injection Protection**: SQLAlchemy ORM prevents SQL injection attacks

### User Management
- **User Registration**: Complete registration flow with email validation
- **User Login**: Secure login with email and password
- **Profile Management**: Update user information and change passwords
- **Email Verification**: Token-based email verification system
- **Password Reset**: Secure password reset with time-limited tokens
- **Account Management**: User account deletion with confirmation

### API Endpoints
- **Health Check**: System status monitoring
- **Authentication Routes**: Login, register, logout, refresh tokens
- **User Routes**: Profile management, password changes, account operations
- **Error Handling**: Standardized error responses with proper HTTP status codes

## Technology Stack

- **Framework**: Flask 3.1.1
- **Database**: SQLite (development) / PostgreSQL (production ready)
- **Authentication**: Flask-JWT-Extended
- **Password Hashing**: Flask-Bcrypt
- **CORS**: Flask-CORS
- **Validation**: Flask-WTF, email-validator
- **ORM**: SQLAlchemy

## Project Structure

```
autoflow_backend/
├── src/
│   ├── models/
│   │   ├── __init__.py
│   │   └── user.py              # User and UserSession models
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── auth.py              # Authentication endpoints
│   │   └── user.py              # User management endpoints
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── auth.py              # Authentication utilities
│   │   └── validators.py        # Input validation utilities
│   ├── static/                  # Frontend files (HTML, CSS, JS)
│   │   ├── index.html
│   │   ├── login.html
│   │   └── signup.html
│   ├── database/
│   │   └── app.db              # SQLite database file
│   └── main.py                 # Main Flask application
├── venv/                       # Virtual environment
├── requirements.txt            # Python dependencies
├── flask.log                   # Application logs
└── README.md                   # This file
```

## Installation & Setup

### Prerequisites
- Python 3.11 or higher
- pip (Python package installer)
- Virtual environment support

### Quick Start

1. **Clone or extract the project**:
   ```bash
   cd autoflow_backend
   ```

2. **Activate the virtual environment**:
   ```bash
   source venv/bin/activate
   ```

3. **Install dependencies** (already installed):
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   python src/main.py
   ```

5. **Access the application**:
   - Frontend: http://localhost:5000
   - API Health Check: http://localhost:5000/api/health
   - Login Page: http://localhost:5000/login.html
   - Signup Page: http://localhost:5000/signup.html

## API Documentation

### Base URL
```
http://localhost:5000/api
```

### Authentication Endpoints

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
  "fullName": "John Doe",
  "email": "john@example.com",
  "password": "SecurePassword123!"
}
```

**Response (201 Created)**:
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "full_name": "John Doe",
    "email": "john@example.com",
    "is_active": true,
    "email_verified": false,
    "created_at": "2025-06-25T15:46:17.179803",
    "updated_at": "2025-06-25T15:46:17.179808",
    "last_login": null
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Login User
```http
POST /auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePassword123!"
}
```

**Response (200 OK)**:
```json
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "full_name": "John Doe",
    "email": "john@example.com",
    "is_active": true,
    "email_verified": false,
    "created_at": "2025-06-25T15:46:17.179803",
    "updated_at": "2025-06-25T15:46:21.888007",
    "last_login": "2025-06-25T15:46:21.885890"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Refresh Token
```http
POST /auth/refresh
Authorization: Bearer <refresh_token>
```

#### Logout
```http
POST /auth/logout
Authorization: Bearer <access_token>
```

#### Forgot Password
```http
POST /auth/forgot-password
Content-Type: application/json

{
  "email": "john@example.com"
}
```

#### Reset Password
```http
POST /auth/reset-password
Content-Type: application/json

{
  "email": "john@example.com",
  "token": "reset_token_here",
  "password": "NewSecurePassword123!"
}
```

#### Verify Email
```http
POST /auth/verify-email
Content-Type: application/json

{
  "email": "john@example.com",
  "token": "verification_token_here"
}
```

### User Management Endpoints

#### Get User Profile
```http
GET /user/profile
Authorization: Bearer <access_token>
```

#### Update User Profile
```http
PUT /user/profile
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "fullName": "John Smith",
  "email": "johnsmith@example.com"
}
```

#### Change Password
```http
POST /user/change-password
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewPassword123!"
}
```

#### Resend Email Verification
```http
POST /user/resend-verification
Authorization: Bearer <access_token>
```

#### Delete Account
```http
DELETE /user/account
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "password": "UserPassword123!",
  "confirmation": "DELETE"
}
```

#### Get User Statistics
```http
GET /user/stats
Authorization: Bearer <access_token>
```

### Health Check

#### System Health
```http
GET /health
```

**Response (200 OK)**:
```json
{
  "status": "healthy",
  "message": "AutoFlow AI Backend is running"
}
```

## Database Schema

### Users Table
| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique user identifier |
| full_name | VARCHAR(100) | NOT NULL | User's full name |
| email | VARCHAR(120) | UNIQUE, NOT NULL, INDEX | User's email address |
| password_hash | VARCHAR(128) | NOT NULL | Hashed password |
| is_active | BOOLEAN | DEFAULT TRUE | Account status |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | Account creation time |
| updated_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | Last update time |
| last_login | DATETIME | NULLABLE | Last login timestamp |
| email_verified | BOOLEAN | DEFAULT FALSE | Email verification status |
| verification_token | VARCHAR(100) | NULLABLE | Email verification token |
| reset_token | VARCHAR(100) | NULLABLE | Password reset token |
| reset_token_expires | DATETIME | NULLABLE | Reset token expiration |

### User Sessions Table
| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Session identifier |
| user_id | INTEGER | FOREIGN KEY, NOT NULL | Reference to users.id |
| session_token | VARCHAR(255) | UNIQUE, NOT NULL | Session token |
| expires_at | DATETIME | NOT NULL | Session expiration |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | Session creation time |

## Security Features

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character
- Protection against common weak passwords

### Token Security
- JWT tokens with configurable expiration
- Access tokens: 1 hour expiry
- Refresh tokens: 30 days expiry
- Secure token generation using cryptographic functions

### Input Validation
- Email format validation with deliverability checks
- Full name validation with character restrictions
- Password strength validation
- SQL injection prevention through ORM
- XSS protection through input sanitization

### Error Handling
- Standardized error response format
- Appropriate HTTP status codes
- Detailed logging for debugging
- Generic error messages for security

## Configuration

### Environment Variables
The application uses the following configuration:

```python
# Security
SECRET_KEY = 'your-secret-key-change-in-production'
JWT_SECRET_KEY = 'jwt-secret-string-change-in-production'

# Token Expiration
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

# Database
SQLALCHEMY_DATABASE_URI = 'sqlite:///path/to/database/app.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# CORS
CORS_ORIGINS = '*'  # Configure for production
```

### Production Configuration
For production deployment, ensure:

1. **Change Secret Keys**: Use strong, unique secret keys
2. **Database**: Switch to PostgreSQL or MySQL
3. **HTTPS**: Enable SSL/TLS encryption
4. **CORS**: Restrict origins to your domain
5. **Logging**: Configure proper logging levels
6. **Environment Variables**: Use environment variables for sensitive data

## Testing

The backend has been tested with the following scenarios:

### Successful Tests
- ✅ Health check endpoint responds correctly
- ✅ User registration with valid data
- ✅ User login with correct credentials
- ✅ Frontend pages load correctly (index, login, signup)
- ✅ Database tables created successfully
- ✅ CORS headers configured properly

### API Test Examples

**Register a new user**:
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "fullName": "Test User",
    "email": "test@test.com",
    "password": "TestPassword123!"
  }'
```

**Login with credentials**:
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@test.com",
    "password": "TestPassword123!"
  }'
```

## Error Codes

| HTTP Status | Error Type | Description |
|-------------|------------|-------------|
| 400 | Bad Request | Invalid input data or missing required fields |
| 401 | Unauthorized | Invalid credentials or expired token |
| 403 | Forbidden | Access denied (e.g., unverified email) |
| 404 | Not Found | User or resource not found |
| 409 | Conflict | Email already registered |
| 500 | Internal Server Error | Server-side error |

## Logging

The application logs important events including:
- User registration and login attempts
- Security events (failed logins, token issues)
- Password reset requests
- Email verification attempts
- System errors and exceptions

Logs are written to `flask.log` in the project directory.

## Development

### Adding New Features

1. **Models**: Add new database models in `src/models/`
2. **Routes**: Create new API endpoints in `src/routes/`
3. **Utilities**: Add helper functions in `src/utils/`
4. **Testing**: Test new endpoints with curl or Postman

### Code Style
- Follow PEP 8 Python style guidelines
- Use descriptive variable and function names
- Add docstrings to all functions and classes
- Handle exceptions appropriately
- Validate all user inputs

## Deployment

### Local Development
The application is ready to run locally with the provided setup.

### Production Deployment
For production deployment:

1. **Update Configuration**: Change secret keys and database settings
2. **Database Migration**: Set up production database
3. **Web Server**: Use Gunicorn or uWSGI instead of Flask dev server
4. **Reverse Proxy**: Configure Nginx or Apache
5. **SSL Certificate**: Enable HTTPS
6. **Monitoring**: Set up logging and monitoring
7. **Backup**: Implement database backup strategy

### Docker Deployment (Optional)
Create a `Dockerfile` for containerized deployment:

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ ./src/
EXPOSE 5000

CMD ["python", "src/main.py"]
```

## Support

For issues or questions:
1. Check the logs in `flask.log`
2. Verify all dependencies are installed
3. Ensure the database is accessible
4. Check network connectivity and ports

## License

This project is created for AutoFlow AI platform. All rights reserved.

---

**Created by**: Manus AI  
**Version**: 1.0.0  
**Last Updated**: June 25, 2025

