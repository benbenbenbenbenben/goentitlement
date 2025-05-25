# SaaS API Example with JWT Authentication and goentitlement Integration

This example demonstrates how to build a SaaS API with JWT authentication and comprehensive authorization using the goentitlement library. It showcases different access patterns including role-based access control (RBAC), feature flags, subscription tiers, and permission-based authorization.

## Features

- **JWT Authentication**: Secure token-based authentication
- **Role-Based Access Control**: Admin and user roles with different permissions
- **Feature Flags**: Granular feature access control
- **Subscription Tiers**: Basic, Premium, Enterprise subscription levels
- **Permission-Based Authorization**: Fine-grained resource access control
- **Comprehensive Middleware**: Reusable authentication and authorization middleware
- **Test Token Generation**: Built-in endpoints for generating test JWT tokens

## Project Structure

```
examples/saas-api/
├── cmd/server/           # Main application entry point
│   └── main.go          # Server initialization and configuration
├── internal/            # Internal packages
│   ├── auth/           # JWT authentication utilities
│   │   └── jwt.go      # JWT validation, generation, and claims handling
│   ├── handlers/       # HTTP request handlers
│   │   └── api.go      # API endpoint implementations
│   └── middleware/     # HTTP middleware
│       └── auth.go     # Authentication and authorization middleware
├── test/               # Comprehensive test suite
│   ├── helpers.go      # Test utilities and setup functions
│   ├── api_test.go     # Unit tests for JWT and authorization
│   ├── integration_test.go # HTTP endpoint integration tests
│   └── benchmark_test.go   # Performance benchmarks
├── go.mod              # Go module definition
├── README.md           # This file
└── TESTING.md          # Comprehensive testing guide
```

## Quick Start

### 1. Build and Run

```bash
# From the examples/saas-api directory
go build ./cmd/server
./server

# Or run directly
go run ./cmd/server
```

The server will start on `http://localhost:8080`

### 2. Get Test Tokens

Visit `http://localhost:8080/api/tokens` to get JWT tokens for different user types:

- **Admin**: Full access to all features and admin endpoints
- **Premium**: Access to premium features and advanced analytics
- **Basic**: Standard user access with basic features
- **Trial**: Limited access with time-based restrictions

### 3. Test API Endpoints

Use the tokens with the `Authorization: Bearer <token>` header:

```bash
# Get a test token
curl http://localhost:8080/api/tokens

# Use the token to access protected endpoints
curl -H "Authorization: Bearer <your-token>" http://localhost:8080/api/protected
```

## API Endpoints

### Public Endpoints (No Authentication Required)

- `GET /health` - Health check
- `GET /api/public` - Public API information
- `GET /api/tokens` - Get test JWT tokens for different user types

### Protected Endpoints (Authentication Required)

- `GET /api/protected` - Basic protected endpoint
- `GET /api/profile` - User profile with entitlements and roles

### Feature-Gated Endpoints (Require Specific Features)

- `GET /api/features/analytics` - Advanced analytics (requires `advanced_analytics` feature)
- `GET /api/features/api-access` - API access information (requires `api_access` feature)

### Subscription-Tier Restricted Endpoints

- `GET /api/subscription/premium` - Premium features (requires Premium+ subscription)
- `GET /api/subscription/enterprise` - Enterprise features (requires Enterprise subscription)

### Role-Based Access Endpoints

- `GET /api/admin/dashboard` - Admin dashboard (requires `admin` role)

## Authentication Flow

1. **Token Generation**: Use `/api/tokens` to get test tokens or implement your own token generation
2. **Token Validation**: Include token in `Authorization: Bearer <token>` header
3. **Principal Extraction**: Middleware extracts user principal from JWT claims
4. **Authorization Check**: goentitlement manager checks permissions, features, and subscriptions

## User Types and Permissions

### Admin User (`admin-123`)
- **Role**: admin
- **Subscription**: enterprise
- **Features**: advanced_analytics, api_access, bulk_operations
- **Access**: All endpoints including admin dashboard

### Premium User (`user-456`)
- **Role**: user
- **Subscription**: premium
- **Features**: advanced_analytics, priority_support
- **Access**: Premium features and analytics

### Basic User (`user-789`)
- **Role**: user
- **Subscription**: basic
- **Features**: basic_features
- **Access**: Standard protected endpoints

### Trial User (`user-trial`)
- **Role**: user
- **Subscription**: trial (expires in 14 days)
- **Features**: basic_features
- **Access**: Limited access with expiration

## Middleware Components

### AuthMiddleware

The `AuthMiddleware` provides several middleware functions:

- `RequireAuth()` - Validates JWT and extracts principal
- `RequireFeature(feature)` - Checks if user has specific feature enabled
- `RequireSubscription(tier)` - Validates subscription tier
- `RequireRole(role)` - Checks user role
- `RequirePermission(action, resourceType, resourceID)` - Fine-grained permission check
- `OptionalAuth()` - Extracts principal if token provided, but doesn't require it

### Usage Example

```go
// Require authentication
protected.Use(authMiddleware.RequireAuth)

// Require specific feature
router.Handle("/analytics", 
    authMiddleware.RequireFeature("advanced_analytics")(handler))

// Require subscription tier
router.Handle("/premium", 
    authMiddleware.RequireSubscription("premium")(handler))

// Require admin role
router.Handle("/admin", 
    authMiddleware.RequireRole("admin")(handler))
```

## JWT Claims Structure

```json
{
  "user_id": "user-123",
  "email": "user@example.com",
  "role": "user",
  "subscription": "premium",
  "features": ["advanced_analytics", "priority_support"],
  "attributes": {
    "department": "engineering",
    "location": "us-west"
  },
  "iat": 1640995200,
  "exp": 1641081600,
  "iss": "saas-api-example"
}
```

## Error Responses

All endpoints return structured error responses:

```json
{
  "error": "Unauthorized",
  "code": "MISSING_TOKEN",
  "message": "Authorization header is required"
}
```

Common error codes:
- `MISSING_TOKEN` - No Authorization header provided
- `INVALID_TOKEN` - JWT token is invalid or expired
- `FEATURE_NOT_ENABLED` - Required feature not enabled for user
- `INSUFFICIENT_SUBSCRIPTION` - Higher subscription tier required
- `INSUFFICIENT_ROLE` - Required role not assigned to user
- `PERMISSION_DENIED` - Specific permission not granted

## Testing with curl

```bash
# Get test tokens
curl http://localhost:8080/api/tokens

# Test public endpoint
curl http://localhost:8080/api/public

# Test protected endpoint with admin token
curl -H "Authorization: Bearer <admin-token>" \
     http://localhost:8080/api/protected

# Test feature-gated endpoint
curl -H "Authorization: Bearer <admin-token>" \
     http://localhost:8080/api/features/analytics

# Test subscription-restricted endpoint
curl -H "Authorization: Bearer <premium-token>" \
     http://localhost:8080/api/subscription/premium

# Test admin endpoint
curl -H "Authorization: Bearer <admin-token>" \
     http://localhost:8080/api/admin/dashboard
```

## Testing

The project includes a comprehensive test suite covering:

- **Unit Tests**: JWT validation, authentication, and authorization logic
- **Integration Tests**: Complete HTTP request flows and endpoint testing
- **Benchmark Tests**: Performance testing and profiling

### Running Tests

```bash
# Run all tests
cd examples/saas-api
go test ./test/ -v

# Run tests with coverage
go test ./test/ -v -cover

# Run benchmarks
go test ./test/ -bench=. -v

# Run specific test
go test ./test/ -run TestJWTValidation -v
```

For detailed testing information, see [TESTING.md](TESTING.md).

## Configuration

Key configuration constants in `main.go`:

```go
const (
    serverPort = ":8080"
    jwtSigningKey = "your-super-secret-jwt-signing-key-change-this-in-production"
    jwtIssuer = "saas-api-example"
)
```

**Important**: Change the `jwtSigningKey` in production!

## Next Steps

1. **Database Integration**: Replace in-memory store with persistent storage
2. **Production Security**: Implement proper key management and token rotation
3. **Logging & Monitoring**: Add structured logging and metrics collection
4. **Rate Limiting**: Implement API rate limiting
5. **API Documentation**: Generate OpenAPI/Swagger documentation
6. **Caching**: Add Redis caching for entitlement checks

## Dependencies

- `github.com/benbenbenbenbenben/goentitlement` - Main entitlement library
- `github.com/golang-jwt/jwt/v5` - JWT token handling
- `github.com/gorilla/mux` - HTTP routing

This example provides a solid foundation for building production-ready SaaS APIs with comprehensive authorization capabilities.