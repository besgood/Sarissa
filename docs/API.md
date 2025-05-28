# Sarissa API Documentation

## Overview

The Sarissa API provides a RESTful interface for interacting with the Sarissa Security Platform. All API endpoints are available at `http://your-server:8081/api/v1/`.

## Authentication

### Authentication Methods

1. **JWT Token Authentication**
   ```http
   POST /api/v1/auth/login
   Content-Type: application/json

   {
     "username": "string",
     "password": "string"
   }
   ```

   Response:
   ```json
   {
     "token": "string",
     "expires_in": 3600
   }
   ```

2. **API Key Authentication**
   ```http
   X-API-Key: your-api-key
   ```

## Rate Limiting

- 100 requests per minute per IP
- 1000 requests per hour per API key
- Rate limit headers included in responses:
  - `X-RateLimit-Limit`
  - `X-RateLimit-Remaining`
  - `X-RateLimit-Reset`

## Endpoints

### Vulnerability Management

#### List Vulnerabilities
```http
GET /api/v1/vulnerabilities
Authorization: Bearer <token>

Query Parameters:
- page: integer (default: 1)
- limit: integer (default: 20)
- severity: string (low|medium|high|critical)
- status: string (open|closed|in-progress)
```

Response:
```json
{
  "data": [
    {
      "id": "string",
      "title": "string",
      "severity": "string",
      "status": "string",
      "created_at": "string",
      "updated_at": "string"
    }
  ],
  "pagination": {
    "total": "integer",
    "page": "integer",
    "limit": "integer"
  }
}
```

#### Get Vulnerability Details
```http
GET /api/v1/vulnerabilities/{id}
Authorization: Bearer <token>
```

### Scan Management

#### Start Scan
```http
POST /api/v1/scans
Authorization: Bearer <token>
Content-Type: application/json

{
  "target": "string",
  "scan_type": "string",
  "options": {
    "depth": "integer",
    "timeout": "integer"
  }
}
```

#### Get Scan Status
```http
GET /api/v1/scans/{id}
Authorization: Bearer <token>
```

### User Management

#### Create User
```http
POST /api/v1/users
Authorization: Bearer <token>
Content-Type: application/json

{
  "username": "string",
  "email": "string",
  "password": "string",
  "role": "string"
}
```

#### Update User
```http
PUT /api/v1/users/{id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "email": "string",
  "role": "string"
}
```

## Error Handling

All errors follow this format:
```json
{
  "error": {
    "code": "string",
    "message": "string",
    "details": {}
  }
}
```

Common error codes:
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 429: Too Many Requests
- 500: Internal Server Error

## WebSocket API

### Real-time Updates

Connect to WebSocket endpoint:
```javascript
const ws = new WebSocket('ws://your-server:8081/ws');
```

Events:
- `scan_progress`: Scan progress updates
- `vulnerability_found`: New vulnerability detected
- `system_alert`: System alerts and notifications

## SDK Support

### Python SDK
```python
from sarissa import SarissaClient

client = SarissaClient(api_key='your-api-key')
vulnerabilities = client.vulnerabilities.list()
```

### JavaScript SDK
```javascript
import { SarissaClient } from '@sarissa/sdk';

const client = new SarissaClient({ apiKey: 'your-api-key' });
const vulnerabilities = await client.vulnerabilities.list();
```

## Best Practices

1. **Error Handling**
   - Always check response status codes
   - Implement exponential backoff for retries
   - Handle rate limiting gracefully

2. **Security**
   - Never store API keys in client-side code
   - Use HTTPS for all API calls
   - Rotate API keys regularly

3. **Performance**
   - Use pagination for large data sets
   - Implement caching where appropriate
   - Use WebSocket for real-time updates 