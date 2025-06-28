# CoveSecure - API Documentation

## Overview

The CoveSecure provides a RESTful API for programmatic access to risk management functionality. This API enables integration with other systems, automated reporting, and custom applications.

## Base URL

```
https://your-domain.com/api/v1
```

## Authentication

The API uses session-based authentication. Users must first authenticate through the web interface or obtain an API token.

### Session Authentication

1. **Login via Web Interface**: Standard web login creates a session
2. **API Access**: Use the same session for API calls
3. **Session Management**: Sessions expire based on configured timeout

### API Token Authentication (Future)

```http
Authorization: Bearer <your-api-token>
```

## Response Format

All API responses use JSON format with consistent structure:

### Success Response

```json
{
  "success": true,
  "data": {
    // Response data
  },
  "message": "Operation completed successfully",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Response

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": "Additional error details"
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `422 Unprocessable Entity`: Validation errors
- `500 Internal Server Error`: Server error

## Endpoints

### Health Check

#### GET /health

Check system health and status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "database": "connected",
  "logging": "operational",
  "request_count": 1000,
  "avg_response_time": 0.125
}
```

**Status Codes:**
- `200`: System healthy
- `503`: System unhealthy

### Metrics

#### GET /metrics

Get system metrics and statistics (Admin only).

**Response:**
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "database": {
    "total_risks": 150,
    "total_users": 25,
    "risk_distribution": {
      "High": 15,
      "Medium": 75,
      "Low": 60
    }
  },
  "performance": {
    "total_requests": 10000,
    "average_response_time": 0.125,
    "slow_requests_count": 5
  }
}
```

**Status Codes:**
- `200`: Metrics retrieved successfully
- `403`: Unauthorized (non-admin user)

### Risks

#### GET /api/v1/risks

Retrieve list of risks with optional filtering.

**Parameters:**
- `level` (optional): Filter by risk level (High, Medium, Low)
- `status` (optional): Filter by status (Open, In Progress, Closed)
- `min_score` (optional): Minimum risk score
- `max_score` (optional): Maximum risk score
- `limit` (optional): Number of results to return (default: 100)
- `offset` (optional): Number of results to skip (default: 0)

**Example Request:**
```http
GET /api/v1/risks?level=High&status=Open&limit=50
```

**Response:**
```json
{
  "success": true,
  "data": {
    "risks": [
      {
        "id": 1,
        "description": "Critical security vulnerability",
        "impact": 5,
        "likelihood": 5,
        "score": 25,
        "level": "High",
        "control": "Immediate patching required",
        "status": "Open",
        "created_at": "2024-01-01T10:00:00Z",
        "updated_at": "2024-01-01T10:00:00Z"
      }
    ],
    "total_count": 1,
    "filtered_count": 1,
    "pagination": {
      "limit": 50,
      "offset": 0,
      "has_more": false
    }
  }
}
```

#### GET /api/v1/risks/{id}

Retrieve a specific risk by ID.

**Parameters:**
- `id` (required): Risk ID

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "description": "Critical security vulnerability",
    "impact": 5,
    "likelihood": 5,
    "score": 25,
    "level": "High",
    "control": "Immediate patching required",
    "status": "Open",
    "created_at": "2024-01-01T10:00:00Z",
    "updated_at": "2024-01-01T10:00:00Z",
    "created_by": "admin",
    "updated_by": "admin"
  }
}
```

**Status Codes:**
- `200`: Risk found
- `404`: Risk not found

#### POST /api/v1/risks

Create a new risk.

**Request Body:**
```json
{
  "description": "New security risk",
  "impact": 4,
  "likelihood": 3,
  "control": "Security controls in place",
  "status": "Open"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 123,
    "description": "New security risk",
    "impact": 4,
    "likelihood": 3,
    "score": 12,
    "level": "Medium",
    "control": "Security controls in place",
    "status": "Open",
    "created_at": "2024-01-01T12:00:00Z",
    "updated_at": "2024-01-01T12:00:00Z"
  },
  "message": "Risk created successfully"
}
```

**Validation Rules:**
- `description`: Required, max 1000 characters
- `impact`: Required, integer 1-5
- `likelihood`: Required, integer 1-5
- `control`: Optional, max 500 characters
- `status`: Required, one of: Open, In Progress, Closed

**Status Codes:**
- `201`: Risk created successfully
- `400`: Invalid request data
- `422`: Validation errors

#### PUT /api/v1/risks/{id}

Update an existing risk.

**Parameters:**
- `id` (required): Risk ID

**Request Body:**
```json
{
  "description": "Updated risk description",
  "impact": 3,
  "likelihood": 4,
  "control": "Enhanced security controls",
  "status": "In Progress"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 123,
    "description": "Updated risk description",
    "impact": 3,
    "likelihood": 4,
    "score": 12,
    "level": "Medium",
    "control": "Enhanced security controls",
    "status": "In Progress",
    "created_at": "2024-01-01T10:00:00Z",
    "updated_at": "2024-01-01T12:00:00Z"
  },
  "message": "Risk updated successfully"
}
```

**Status Codes:**
- `200`: Risk updated successfully
- `404`: Risk not found
- `422`: Validation errors

#### DELETE /api/v1/risks/{id}

Delete a risk (Admin only).

**Parameters:**
- `id` (required): Risk ID

**Response:**
```json
{
  "success": true,
  "message": "Risk deleted successfully"
}
```

**Status Codes:**
- `200`: Risk deleted successfully
- `403`: Unauthorized (non-admin user)
- `404`: Risk not found

### Users

#### GET /api/v1/users

Retrieve list of users (Admin only).

**Response:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": 1,
        "username": "admin",
        "role": "admin",
        "created_at": "2024-01-01T00:00:00Z",
        "last_login": "2024-01-01T12:00:00Z"
      },
      {
        "id": 2,
        "username": "user1",
        "role": "user",
        "created_at": "2024-01-01T08:00:00Z",
        "last_login": "2024-01-01T11:30:00Z"
      }
    ],
    "total_count": 2
  }
}
```

#### POST /api/v1/users

Create a new user (Admin only).

**Request Body:**
```json
{
  "username": "newuser",
  "password": "securepassword123",
  "role": "user"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 3,
    "username": "newuser",
    "role": "user",
    "created_at": "2024-01-01T12:00:00Z"
  },
  "message": "User created successfully"
}
```

**Validation Rules:**
- `username`: Required, unique, 3-50 characters, alphanumeric and underscore only
- `password`: Required, minimum 8 characters
- `role`: Required, one of: admin, user

### Export

#### GET /api/v1/export/excel

Export risks to Excel format.

**Parameters:**
- Same filtering parameters as GET /api/v1/risks

**Response:**
- Content-Type: `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`
- Content-Disposition: `attachment; filename="risks.xlsx"`

#### GET /api/v1/export/pdf

Export risks to PDF format.

**Parameters:**
- Same filtering parameters as GET /api/v1/risks

**Response:**
- Content-Type: `application/pdf`
- Content-Disposition: `attachment; filename="risks.pdf"`

### Audit Logs

#### GET /api/v1/logs

Retrieve audit logs (Admin only).

**Parameters:**
- `start_date` (optional): Start date for log entries (ISO 8601 format)
- `end_date` (optional): End date for log entries (ISO 8601 format)
- `user` (optional): Filter by username
- `action` (optional): Filter by action type
- `limit` (optional): Number of results (default: 100)
- `offset` (optional): Number of results to skip (default: 0)

**Response:**
```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "timestamp": "2024-01-01T12:00:00Z",
        "user": "admin",
        "action": "Created risk: New security vulnerability",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0..."
      }
    ],
    "total_count": 1,
    "pagination": {
      "limit": 100,
      "offset": 0,
      "has_more": false
    }
  }
}
```

## Error Handling

### Validation Errors

When validation fails, the API returns detailed error information:

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "details": {
      "impact": ["Impact must be between 1 and 5"],
      "description": ["Description is required"]
    }
  }
}
```

### Common Error Codes

- `AUTHENTICATION_REQUIRED`: User must be authenticated
- `INSUFFICIENT_PERMISSIONS`: User lacks required permissions
- `VALIDATION_ERROR`: Request data validation failed
- `RESOURCE_NOT_FOUND`: Requested resource does not exist
- `DUPLICATE_RESOURCE`: Resource already exists
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `INTERNAL_ERROR`: Server-side error

## Rate Limiting

API requests are rate-limited to prevent abuse:

- **Authenticated Users**: 1000 requests per hour
- **Admin Users**: 5000 requests per hour
- **Export Endpoints**: 10 requests per hour

Rate limit headers are included in responses:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## Pagination

List endpoints support pagination:

**Request Parameters:**
- `limit`: Number of items per page (max 1000, default 100)
- `offset`: Number of items to skip (default 0)

**Response Format:**
```json
{
  "data": {
    "items": [...],
    "pagination": {
      "limit": 100,
      "offset": 0,
      "total_count": 500,
      "has_more": true
    }
  }
}
```

## Filtering and Sorting

### Filtering

Most list endpoints support filtering:

**Common Filters:**
- `created_after`: ISO 8601 date
- `created_before`: ISO 8601 date
- `updated_after`: ISO 8601 date
- `updated_before`: ISO 8601 date

**Risk-Specific Filters:**
- `level`: High, Medium, Low
- `status`: Open, In Progress, Closed
- `min_score`: Minimum risk score
- `max_score`: Maximum risk score

### Sorting

Use the `sort` parameter with field names:

```http
GET /api/v1/risks?sort=score,desc&sort=created_at,asc
```

**Supported Sort Fields:**
- `id`: Risk ID
- `score`: Risk score
- `level`: Risk level
- `status`: Risk status
- `created_at`: Creation date
- `updated_at`: Last update date

## Webhooks (Future Feature)

Webhooks will allow real-time notifications of events:

### Supported Events
- `risk.created`: New risk created
- `risk.updated`: Risk updated
- `risk.deleted`: Risk deleted
- `user.created`: New user created
- `user.updated`: User updated

### Webhook Payload
```json
{
  "event": "risk.created",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "risk": {
      "id": 123,
      "description": "New risk",
      // ... full risk object
    }
  }
}
```

## SDK and Libraries

### Python SDK Example

```python
import requests

class GRCClient:
    def __init__(self, base_url, session_cookie):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.cookies.set('session', session_cookie)
    
    def get_risks(self, **filters):
        response = self.session.get(
            f"{self.base_url}/api/v1/risks",
            params=filters
        )
        return response.json()
    
    def create_risk(self, risk_data):
        response = self.session.post(
            f"{self.base_url}/api/v1/risks",
            json=risk_data
        )
        return response.json()

# Usage
client = GRCClient("https://your-domain.com", "your-session-cookie")
risks = client.get_risks(level="High", status="Open")
```

### JavaScript SDK Example

```javascript
class GRCClient {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }
    
    async getRisks(filters = {}) {
        const params = new URLSearchParams(filters);
        const response = await fetch(`${this.baseUrl}/api/v1/risks?${params}`, {
            credentials: 'include'
        });
        return response.json();
    }
    
    async createRisk(riskData) {
        const response = await fetch(`${this.baseUrl}/api/v1/risks`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify(riskData)
        });
        return response.json();
    }
}

// Usage
const client = new GRCClient('https://your-domain.com');
const risks = await client.getRisks({ level: 'High', status: 'Open' });
```

## Testing

### API Testing Tools

**Recommended Tools:**
- **Postman**: GUI-based API testing
- **curl**: Command-line testing
- **HTTPie**: User-friendly command-line tool
- **Insomnia**: Alternative GUI tool

### Example curl Commands

```bash
# Get all risks
curl -X GET "https://your-domain.com/api/v1/risks" \
  -H "Cookie: session=your-session-cookie"

# Create a new risk
curl -X POST "https://your-domain.com/api/v1/risks" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=your-session-cookie" \
  -d '{
    "description": "API Test Risk",
    "impact": 3,
    "likelihood": 4,
    "control": "Test control",
    "status": "Open"
  }'

# Update a risk
curl -X PUT "https://your-domain.com/api/v1/risks/123" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=your-session-cookie" \
  -d '{
    "status": "In Progress"
  }'
```

## Best Practices

### API Usage Best Practices

1. **Authentication**
   - Always use HTTPS in production
   - Implement proper session management
   - Use API tokens for automated systems

2. **Error Handling**
   - Always check response status codes
   - Handle rate limiting gracefully
   - Implement retry logic with exponential backoff

3. **Performance**
   - Use pagination for large datasets
   - Implement client-side caching where appropriate
   - Use filtering to reduce data transfer

4. **Security**
   - Validate all input data
   - Use parameterized queries
   - Implement proper access controls

### Integration Patterns

1. **Batch Processing**
   - Use pagination for large datasets
   - Implement batch operations where possible
   - Handle partial failures gracefully

2. **Real-time Updates**
   - Poll for changes using timestamps
   - Implement webhook handlers (when available)
   - Use WebSocket connections for live updates

3. **Data Synchronization**
   - Implement conflict resolution strategies
   - Use timestamps for change detection
   - Maintain audit trails for changes

## Changelog

### Version 1.0 (Current)
- Initial API release
- Basic CRUD operations for risks and users
- Export functionality
- Health check and metrics endpoints

### Planned Features
- API token authentication
- Webhook support
- Bulk operations
- Advanced filtering and search
- Real-time notifications
- GraphQL endpoint

---

For additional API support or questions, please contact the development team or refer to the main documentation.

**API Version**: 1.0
