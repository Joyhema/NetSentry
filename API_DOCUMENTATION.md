
# NetSentry API Documentation

## 1. Project Overview

NetSentry is a web-based network security monitoring dashboard that displays laptop system metrics and security events.

**Live Dashboard:** https://netsentry-itpe.onrender.com

## 2. API Endpoints

### A. Submit Agent Events

- **Method:** POST
- **Endpoint:** `/api/agent/events`
- **Purpose:** Receives system metrics and security events from the laptop agent.
- **Authentication:** Requires the `X-API-Key` request header.
- **Content-Type:** `application/json`

Example request:

```json
{
  "event_type": "security_alert",
  "hostname": "test-laptop",
  "message": "Multiple failed login attempts detected - controlled test",
  "severity": "info"
}
```

Example response:

```json
{
  "message": "Event saved",
  "severity": "high",
  "success": true,
  "suspicious": true
}
```

The response above represents the tested suspicious-event detection behavior.

### B. Get Server Statistics

- **Method:** GET
- **Endpoint:** `/api/stats`
- **Purpose:** Retrieves server monitoring statistics.
- **Authentication:** Check the deployed application configuration for the current requirement.

### C. Get Laptop Metrics

- **Method:** GET
- **Endpoint:** `/api/laptop-metrics`
- **Purpose:** Retrieves the latest stored laptop CPU, memory, and disk metrics.

## 3. Security Features

- API-key authentication for agent event submissions.
- Input validation for submitted events.
- Keyword-based suspicious-event detection.
- HIGH severity classification for matching test events.
- SQLite database storage.

## 4. Testing

A controlled test event was submitted successfully through the agent events API. The API returned a successful response, and the dashboard displayed a HIGH severity alert.

**Note:** Keyword-based detection provides indicators for review; it does not prove that an actual attack occurred.

## 5. Future Improvements

- Add automated API tests.
- Improve detection rules and reduce false positives.
- Add role-based access control.
- Add rate limiting and structured audit logging.
