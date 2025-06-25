# AutoFlow AI Backend - API Documentation

Complete API reference for the AutoFlow AI backend system, including authentication, user management, and all available endpoints.

## Base Information

- **Base URL**: `http://localhost:5000/api` (development)
- **Production URL**: `https://yourdomain.com/api`
- **API Version**: 1.0.0
- **Authentication**: JWT Bearer Token
- **Content Type**: `application/json`

## Authentication

All protected endpoints require a valid JWT token in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

### Token Types

- **Access Token**: Short-lived (1 hour) for API access
- **Refresh Token**: Long-lived (30 days) for obtaining new access tokens

## Response Format

### Success Response
```json
{
  "message": "Operation successful",
  "data": {
    // Response data
  }
}
```

### Error Response
```json
{
  "error": "Error description",
  "details": {
    // Additional error details (optional)
  }
}
```

## HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | OK - Request successful |
| 201 | Created - Resource created successfully |
| 400 | Bad Request - Invalid input data |
| 401 | Unauthorized - Authentication required or failed |
| 403 | Forbidden - Access denied |
| 404 | Not Found - Resource not found |
| 409 | Conflict - Resource already exists |
| 500 | Internal Server Error - Server error |

## Endpoints

### Health Check

#### GET /health

Check if the API is running and healthy.

**Request:**
```http
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "message": "AutoFlow AI Backend is running"
}
```

---

## Authentication Endpoints

### Register User

#### POST /auth/register

Register a new user account.

**Request:**
```http
POST /api/auth/register
Content-Type: application/json

{
  "fullName": "John Doe",
  "email": "john@example.com",
  "password": "SecurePassword123!"
}
```

**Request Body Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| fullName | string | Yes | User's full name (2-100 characters) |
| email | string | Yes | Valid email address |
| password | string | Yes | Password meeting security requirements |

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

**Success Response (201):**
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

**Error Responses:**

```json
// 400 - Invalid input
{
  "error": "Password must be at least 8 characters long"
}

// 409 - Email already exists
{
  "error": "Email address is already registered"
}
```

### Login User

#### POST /auth/login

Authenticate user and receive JWT tokens.

**Request:**
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePassword123!"
}
```

**Request Body Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| email | string | Yes | User's email address |
| password | string | Yes | User's password |

**Success Response (200):**
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

**Error Responses:**

```json
// 401 - Invalid credentials
{
  "error": "Invalid email or password"
}

// 401 - Account deactivated
{
  "error": "Account is deactivated. Please contact support."
}
```

### Refresh Token

#### POST /auth/refresh

Get a new access token using a refresh token.

**Request:**
```http
POST /api/auth/refresh
Authorization: Bearer <refresh_token>
```

**Success Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Error Responses:**

```json
// 401 - Invalid or expired refresh token
{
  "message": "Token has expired"
}

// 404 - User not found
{
  "error": "User not found or inactive"
}
```

### Logout

#### POST /auth/logout

Logout user (client should remove tokens).

**Request:**
```http
POST /api/auth/logout
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "message": "Logout successful"
}
```

### Forgot Password

#### POST /auth/forgot-password

Request a password reset token.

**Request:**
```http
POST /api/auth/forgot-password
Content-Type: application/json

{
  "email": "john@example.com"
}
```

**Request Body Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| email | string | Yes | User's email address |

**Success Response (200):**
```json
{
  "message": "If an account with that email exists, a password reset link has been sent."
}
```

**Note**: This endpoint always returns success to prevent email enumeration attacks.

### Reset Password

#### POST /auth/reset-password

Reset password using a reset token.

**Request:**
```http
POST /api/auth/reset-password
Content-Type: application/json

{
  "email": "john@example.com",
  "token": "reset_token_here",
  "password": "NewSecurePassword123!"
}
```

**Request Body Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| email | string | Yes | User's email address |
| token | string | Yes | Password reset token |
| password | string | Yes | New password meeting requirements |

**Success Response (200):**
```json
{
  "message": "Password reset successful"
}
```

**Error Responses:**

```json
// 400 - Invalid or expired token
{
  "error": "Invalid or expired reset token"
}

// 400 - Invalid password
{
  "error": "Password must contain at least one uppercase letter"
}
```

### Verify Email

#### POST /auth/verify-email

Verify email address using verification token.

**Request:**
```http
POST /api/auth/verify-email
Content-Type: application/json

{
  "email": "john@example.com",
  "token": "verification_token_here"
}
```

**Request Body Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| email | string | Yes | User's email address |
| token | string | Yes | Email verification token |

**Success Response (200):**
```json
{
  "message": "Email verified successfully"
}
```

**Error Responses:**

```json
// 400 - Invalid token
{
  "error": "Invalid verification token"
}

// 200 - Already verified
{
  "message": "Email is already verified"
}
```

---

## User Management Endpoints

### Get User Profile

#### GET /user/profile

Get current user's profile information.

**Request:**
```http
GET /api/user/profile
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "user": {
    "id": 1,
    "full_name": "John Doe",
    "email": "john@example.com",
    "is_active": true,
    "email_verified": false,
    "created_at": "2025-06-25T15:46:17.179803",
    "updated_at": "2025-06-25T15:46:17.179808",
    "last_login": "2025-06-25T15:46:21.885890"
  }
}
```

**Error Responses:**

```json
// 401 - Invalid token
{
  "error": "Authorization token is required"
}

// 404 - User not found
{
  "error": "User not found"
}
```

### Update User Profile

#### PUT /user/profile

Update current user's profile information.

**Request:**
```http
PUT /api/user/profile
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "fullName": "John Smith",
  "email": "johnsmith@example.com"
}
```

**Request Body Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| fullName | string | No | Updated full name |
| email | string | No | Updated email address |

**Success Response (200):**
```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": 1,
    "full_name": "John Smith",
    "email": "johnsmith@example.com",
    "is_active": true,
    "email_verified": false,
    "created_at": "2025-06-25T15:46:17.179803",
    "updated_at": "2025-06-25T16:30:45.123456",
    "last_login": "2025-06-25T15:46:21.885890"
  },
  "updated_fields": ["full_name", "email"]
}
```

**Error Responses:**

```json
// 409 - Email already taken
{
  "error": "Email address is already taken"
}

// 400 - Invalid input
{
  "error": "Full name must be at least 2 characters long"
}
```

### Change Password

#### POST /user/change-password

Change user's password.

**Request:**
```http
POST /api/user/change-password
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewPassword123!"
}
```

**Request Body Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| currentPassword | string | Yes | Current password |
| newPassword | string | Yes | New password meeting requirements |

**Success Response (200):**
```json
{
  "message": "Password changed successfully"
}
```

**Error Responses:**

```json
// 400 - Incorrect current password
{
  "error": "Current password is incorrect"
}

// 400 - Same password
{
  "error": "New password must be different from current password"
}

// 400 - Invalid new password
{
  "error": "Password must contain at least one number"
}
```

### Resend Email Verification

#### POST /user/resend-verification

Resend email verification token.

**Request:**
```http
POST /api/user/resend-verification
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "message": "Verification email sent successfully"
}
```

**Error Responses:**

```json
// 200 - Already verified
{
  "message": "Email is already verified"
}
```

### Delete Account

#### DELETE /user/account

Delete user account permanently.

**Request:**
```http
DELETE /api/user/account
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "password": "UserPassword123!",
  "confirmation": "DELETE"
}
```

**Request Body Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| password | string | Yes | User's current password |
| confirmation | string | Yes | Must be exactly "DELETE" |

**Success Response (200):**
```json
{
  "message": "Account deleted successfully"
}
```

**Error Responses:**

```json
// 400 - Incorrect password
{
  "error": "Incorrect password"
}

// 400 - Invalid confirmation
{
  "error": "Please type DELETE to confirm account deletion"
}
```

### Get User Statistics

#### GET /user/stats

Get user account statistics.

**Request:**
```http
GET /api/user/stats
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "stats": {
    "account_age_days": 15,
    "email_verified": false,
    "last_login": "2025-06-25T15:46:21.885890",
    "created_at": "2025-06-25T15:46:17.179803",
    "total_sessions": 3
  }
}
```

---

## Error Handling

### Common Error Responses

#### 400 Bad Request
```json
{
  "error": "No data provided"
}
```

#### 401 Unauthorized
```json
{
  "message": "Authorization token is required"
}
```

#### 403 Forbidden
```json
{
  "error": "Email verification required"
}
```

#### 404 Not Found
```json
{
  "error": "User not found"
}
```

#### 500 Internal Server Error
```json
{
  "error": "Registration failed. Please try again."
}
```

### Field Validation Errors

When validation fails, the API returns specific error messages:

```json
{
  "error": "Password must be at least 8 characters long"
}
```

Common validation errors:
- "Full name must be at least 2 characters long"
- "Invalid email address"
- "Password must contain at least one uppercase letter"
- "Password must contain at least one lowercase letter"
- "Password must contain at least one number"
- "Password must contain at least one special character"

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **General API**: 200 requests per day, 50 per hour
- **Login endpoint**: 5 requests per minute
- **Registration**: 3 requests per minute
- **Password reset**: 2 requests per minute

When rate limit is exceeded:

```json
{
  "error": "Rate limit exceeded. Please try again later."
}
```

## CORS Configuration

The API supports Cross-Origin Resource Sharing (CORS) with the following configuration:

- **Development**: All origins allowed (`*`)
- **Production**: Specific domains only

Supported headers:
- `Content-Type`
- `Authorization`
- `X-Requested-With`

Supported methods:
- `GET`
- `POST`
- `PUT`
- `DELETE`
- `OPTIONS`

## Code Examples

### JavaScript/Fetch API

#### Register User
```javascript
const registerUser = async (userData) => {
  try {
    const response = await fetch('/api/auth/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userData)
    });
    
    const data = await response.json();
    
    if (response.ok) {
      // Store tokens
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('refresh_token', data.refresh_token);
      return data;
    } else {
      throw new Error(data.error);
    }
  } catch (error) {
    console.error('Registration failed:', error);
    throw error;
  }
};

// Usage
registerUser({
  fullName: 'John Doe',
  email: 'john@example.com',
  password: 'SecurePassword123!'
});
```

#### Login User
```javascript
const loginUser = async (credentials) => {
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentials)
    });
    
    const data = await response.json();
    
    if (response.ok) {
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('refresh_token', data.refresh_token);
      return data;
    } else {
      throw new Error(data.error);
    }
  } catch (error) {
    console.error('Login failed:', error);
    throw error;
  }
};
```

#### Authenticated Request
```javascript
const makeAuthenticatedRequest = async (url, options = {}) => {
  const token = localStorage.getItem('access_token');
  
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      ...options.headers
    }
  });
  
  if (response.status === 401) {
    // Token expired, try to refresh
    await refreshToken();
    // Retry the request
    return makeAuthenticatedRequest(url, options);
  }
  
  return response;
};

const refreshToken = async () => {
  const refreshToken = localStorage.getItem('refresh_token');
  
  const response = await fetch('/api/auth/refresh', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${refreshToken}`
    }
  });
  
  if (response.ok) {
    const data = await response.json();
    localStorage.setItem('access_token', data.access_token);
  } else {
    // Refresh failed, redirect to login
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    window.location.href = '/login.html';
  }
};
```

### Python/Requests

#### Register User
```python
import requests

def register_user(full_name, email, password):
    url = 'http://localhost:5000/api/auth/register'
    data = {
        'fullName': full_name,
        'email': email,
        'password': password
    }
    
    response = requests.post(url, json=data)
    
    if response.status_code == 201:
        return response.json()
    else:
        raise Exception(f"Registration failed: {response.json()['error']}")

# Usage
user_data = register_user('John Doe', 'john@example.com', 'SecurePassword123!')
access_token = user_data['access_token']
```

#### Authenticated Request
```python
def make_authenticated_request(url, token, method='GET', data=None):
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    if method == 'GET':
        response = requests.get(url, headers=headers)
    elif method == 'POST':
        response = requests.post(url, headers=headers, json=data)
    elif method == 'PUT':
        response = requests.put(url, headers=headers, json=data)
    elif method == 'DELETE':
        response = requests.delete(url, headers=headers, json=data)
    
    return response

# Usage
profile_response = make_authenticated_request(
    'http://localhost:5000/api/user/profile',
    access_token
)
```

### cURL Examples

#### Register User
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "fullName": "John Doe",
    "email": "john@example.com",
    "password": "SecurePassword123!"
  }'
```

#### Login User
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePassword123!"
  }'
```

#### Get Profile
```bash
curl -X GET http://localhost:5000/api/user/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### Update Profile
```bash
curl -X PUT http://localhost:5000/api/user/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "fullName": "John Smith",
    "email": "johnsmith@example.com"
  }'
```

## Testing

### Postman Collection

You can import this Postman collection to test all endpoints:

```json
{
  "info": {
    "name": "AutoFlow AI Backend API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [
    {
      "key": "base_url",
      "value": "http://localhost:5000/api"
    },
    {
      "key": "access_token",
      "value": ""
    }
  ],
  "item": [
    {
      "name": "Health Check",
      "request": {
        "method": "GET",
        "url": "{{base_url}}/health"
      }
    },
    {
      "name": "Register",
      "request": {
        "method": "POST",
        "url": "{{base_url}}/auth/register",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"fullName\": \"Test User\",\n  \"email\": \"test@example.com\",\n  \"password\": \"TestPassword123!\"\n}"
        }
      }
    },
    {
      "name": "Login",
      "request": {
        "method": "POST",
        "url": "{{base_url}}/auth/login",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"email\": \"test@example.com\",\n  \"password\": \"TestPassword123!\"\n}"
        }
      }
    },
    {
      "name": "Get Profile",
      "request": {
        "method": "GET",
        "url": "{{base_url}}/user/profile",
        "header": [
          {
            "key": "Authorization",
            "value": "Bearer {{access_token}}"
          }
        ]
      }
    }
  ]
}
```

## Changelog

### Version 1.0.0 (2025-06-25)
- Initial API release
- User registration and authentication
- Profile management
- Password reset functionality
- Email verification
- JWT token-based security
- Comprehensive input validation
- Error handling and logging

---

**Created by**: Manus AI  
**Version**: 1.0.0  
**Last Updated**: June 25, 2025

