# SaaS API Testing Guide

This document provides comprehensive information about the testing strategy and implementation for the SaaS API example.

## Test Overview

The test suite provides comprehensive coverage of the SaaS API application, including:

- **Unit Tests**: Testing individual components and functions
- **Integration Tests**: Testing complete HTTP request flows
- **Benchmark Tests**: Performance testing and profiling

## Test Structure

### Test Files

- `test/helpers.go` - Common test utilities and setup functions
- `test/api_test.go` - Unit tests for JWT, authentication, and authorization logic
- `test/integration_test.go` - Integration tests for HTTP endpoints
- `test/benchmark_test.go` - Performance benchmarks

### Test Categories

#### 1. JWT and Authentication Tests

**JWT Validation Tests** (`TestJWTValidation`)
- Valid token processing
- Expired token handling
- Invalid token format detection
- Malformed token rejection
- Wrong signing key detection

**Principal Extraction Tests** (`TestPrincipalExtraction`)
- Converting JWT claims to Principal objects
- Handling different user types (admin, premium, basic, trial)
- Attribute and group mapping

**Middleware Authentication Tests** (`TestMiddlewareAuthentication`)
- Missing authorization header handling
- Invalid authorization header formats
- Bearer token validation
- Authentication success scenarios

#### 2. Authorization Tests

**Feature Authorization Tests** (`TestFeatureAuthorization`)
- Feature flag-based access control
- Role-based feature access
- Subscription-based feature access

**Subscription Authorization Tests** (`TestSubscriptionAuthorization`)
- Subscription tier validation
- Hierarchical subscription access
- Subscription upgrade scenarios

**Role Authorization Tests** (`TestRoleAuthorization`)
- Admin role verification
- Role-based endpoint access
- Permission escalation prevention

#### 3. Integration Tests

**Public Endpoint Tests** (`TestPublicEndpoints`)
- Health check endpoint
- Public API information
- Test token generation

**User Scenario Tests**
- Known users with proper access (`TestKnownUserWithAccessScenarios`)
- Known users without sufficient access (`TestKnownUserWithoutAccessScenarios`)
- Unknown users not in entitlement system (`TestUnknownUserScenarios`)

**Edge Case Tests** (`TestEdgeCases`)
- Empty and malformed headers
- Whitespace handling
- Token format validation
- Expired token scenarios

**Response Structure Tests**
- JSON response format validation (`TestProtectedEndpointResponseStructure`)
- Required field presence (`TestUserProfileEndpointResponseStructure`)
- Content-Type header verification (`TestContentTypeHeaders`)

#### 4. Performance Tests

**Component Benchmarks**
- JWT validation performance (`BenchmarkJWTValidation`)
- JWT generation performance (`BenchmarkJWTGeneration`)
- Claims-to-Principal conversion (`BenchmarkClaimsToPrincipalConversion`)
- Entitlement check operations (`BenchmarkEntitlementChecks`)

**API Endpoint Benchmarks**
- Public endpoint performance (`BenchmarkAPIEndpoints`)
- Protected endpoint performance
- Feature-gated endpoint performance
- Admin endpoint performance

**Load Testing Benchmarks**
- Concurrent request handling (`BenchmarkConcurrentRequests`)
- Mixed workload simulation (`BenchmarkLoadTesting`)
- Authorization pattern performance (`BenchmarkAuthorizationPatterns`)
- Memory usage profiling (`BenchmarkMemoryUsage`)

## Running Tests

### Basic Test Execution

```bash
# Run all tests
cd examples/saas-api
go test ./test/ -v

# Run specific test
go test ./test/ -run TestJWTValidation -v

# Run tests with coverage
go test ./test/ -v -cover
```

### Benchmark Execution

```bash
# Run all benchmarks
go test ./test/ -bench=. -v

# Run specific benchmark
go test ./test/ -bench=BenchmarkJWTValidation -v

# Run benchmarks with memory profiling
go test ./test/ -bench=. -benchmem -v

# Run benchmarks multiple times for accuracy
go test ./test/ -bench=. -count=5 -v
```

### Performance Analysis

```bash
# Generate CPU profile
go test ./test/ -bench=BenchmarkAPIEndpoints -cpuprofile=cpu.prof

# Generate memory profile
go test ./test/ -bench=BenchmarkMemoryUsage -memprofile=mem.prof

# Analyze profiles with pprof
go tool pprof cpu.prof
go tool pprof mem.prof
```

## Test Data

### User Profiles

The test suite includes several predefined user profiles:

- **AdminUser**: Full access to all features and subscription tiers
- **PremiumUser**: Access to premium features and subscription
- **BasicUser**: Limited access to basic features only
- **TrialUser**: Trial access with restricted features
- **UnknownUser**: User not in the entitlement system
- **ExpiredUser**: User with expired JWT token

### Test Entitlements

The test data includes:

- **Roles**: `admin`, `user`
- **Features**: `advanced_analytics`, `api_access`, `bulk_operations`
- **Subscriptions**: `basic`, `premium`, `enterprise`, `trial`

### Test Endpoints

The test suite covers all API endpoints:

- `GET /health` - Health check (public)
- `GET /api/public` - Public API information
- `GET /api/tokens` - Test token generation
- `GET /api/protected` - Basic protected endpoint
- `GET /api/profile` - User profile information
- `GET /api/features/{feature}` - Feature-gated endpoints
- `GET /api/subscription/{tier}` - Subscription-gated endpoints
- `GET /api/admin/{resource}` - Admin-only endpoints

## Test Configuration

### Environment Variables

Tests use the following configuration:

```bash
TEST_JWT_SIGNING_KEY="test-secret-key-for-jwt-signing-in-tests-only"
TEST_JWT_ISSUER="test-saas-api"
```

### Test Server Setup

Each test creates an isolated test server with:

- In-memory entitlement store
- Pre-populated test data
- Mock JWT configuration
- Isolated HTTP server instance

## Coverage Reports

Generate detailed coverage reports:

```bash
# Generate coverage profile
go test ./test/ -coverprofile=coverage.out

# View coverage in browser
go tool cover -html=coverage.out

# Generate coverage by function
go tool cover -func=coverage.out
```

## Performance Benchmarks

### Typical Performance Metrics

Based on benchmark results:

- **JWT Validation**: ~2,700 ns/op
- **JWT Generation**: ~2,100 ns/op
- **Entitlement Checks**: ~500-600 ns/op
- **API Endpoints**: ~90,000-110,000 ns/op
- **Concurrent Requests**: Scales well with increased concurrency

### Memory Usage

- **Token Generation**: ~3,500 B/op, 38 allocs/op
- **Request Processing**: ~29,000 B/op, 249 allocs/op

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Test
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v3
        with:
          go-version: '1.21'
      - name: Run tests
        run: |
          cd examples/saas-api
          go test ./test/ -v -cover
      - name: Run benchmarks
        run: |
          cd examples/saas-api
          go test ./test/ -bench=. -benchtime=1s
```

## Troubleshooting

### Common Issues

1. **Test Server Port Conflicts**
   - Tests use random available ports
   - Each test creates isolated server instances

2. **JWT Token Expiration**
   - Test tokens have 1-hour expiration by default
   - Expired token tests use past timestamps

3. **Entitlement Data**
   - Tests use predefined entitlement data
   - Data is reset for each test

### Debug Mode

Enable verbose logging:

```bash
go test ./test/ -v -args -debug
```

## Contributing

When adding new tests:

1. **Follow naming conventions**: `Test{Component}{Scenario}`
2. **Use table-driven tests** for multiple scenarios
3. **Include both positive and negative test cases**
4. **Add benchmarks for performance-critical code**
5. **Update this documentation** for new test categories

### Test Writing Guidelines

- Use descriptive test names
- Include setup and teardown in test functions
- Assert expected behavior clearly
- Use helper functions to reduce duplication
- Test edge cases and error conditions
- Include performance benchmarks for new features

## Security Testing

The test suite includes security-focused tests:

- Authentication bypass attempts
- Authorization escalation scenarios
- Token manipulation detection
- Input validation testing
- CORS policy verification

## Monitoring and Alerting

Consider setting up monitoring for:

- Test execution time trends
- Benchmark performance regression
- Coverage percentage changes
- Test failure rates
- Memory usage patterns

This ensures the test suite remains effective and catches regressions early.