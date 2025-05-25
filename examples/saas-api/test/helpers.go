// Package test provides testing utilities and helpers for the SaaS API example.
//
// This package contains reusable test infrastructure including test server setup,
// JWT token generation for different user types, HTTP request helpers, and
// assertion utilities for testing authorization scenarios.
//
// Key features:
//   - TestServer for integration testing with real HTTP endpoints
//   - JWT token generation for different user personas (admin, premium, basic, trial)
//   - HTTP request helpers with authentication
//   - Response assertion utilities
//   - Test data setup and teardown
//
// Example usage:
//
//	func TestProtectedEndpoint(t *testing.T) {
//		testServer := test.NewTestServer(t)
//		defer testServer.Close()
//
//		token := testServer.GenerateTokenForUser("premium-user")
//		response := testServer.AuthenticatedRequest("GET", "/api/protected", token, nil)
//
//		test.AssertHTTPStatus(t, response, http.StatusOK)
//	}
package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/benbenbenbenbenben/goentitlement"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/auth"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/handlers"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

const (
	// TestJWTSigningKey is a test-only JWT signing key for generating tokens
	TestJWTSigningKey = "test-jwt-signing-key-for-testing-only"
	// TestJWTIssuer identifies the test environment in JWT tokens
	TestJWTIssuer = "saas-api-test"
)

// TestServer represents a complete test server instance with all dependencies.
//
// This structure provides everything needed for integration testing, including
// an HTTP test server, entitlement manager, JWT manager, and all handlers.
// It allows tests to make real HTTP requests and verify the complete
// authentication and authorization flow.
type TestServer struct {
	// Server is the HTTP test server instance
	Server *httptest.Server
	// EntitlementManager provides authorization functionality
	EntitlementManager goentitlement.EntitlementManager
	// JWTManager handles token operations
	JWTManager *auth.JWTManager
	// AuthMiddleware provides authentication middleware
	AuthMiddleware *middleware.AuthMiddleware
	// APIHandlers contains all HTTP request handlers
	APIHandlers *handlers.APIHandlers
}

// TestingInterface provides a common interface for testing.T and testing.B.
//
// This interface allows test helper functions to work with both unit tests
// and benchmarks, providing consistent error reporting across test types.
type TestingInterface interface {
	// Fatalf reports a fatal error and stops test execution
	Fatalf(format string, args ...interface{})
	// Errorf reports an error but continues test execution
	Errorf(format string, args ...interface{})
}

// SetupTestServer creates a new test server instance with all dependencies
func SetupTestServer(t TestingInterface) *TestServer {
	// Initialize the goentitlement manager with in-memory store
	entitlementManager := goentitlement.NewManager()

	// Initialize sample data
	if err := initializeTestData(entitlementManager); err != nil {
		t.Fatalf("Failed to initialize test data: %v", err)
	}

	// Initialize JWT manager
	jwtManager := auth.NewJWTManager([]byte(TestJWTSigningKey), TestJWTIssuer)

	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(jwtManager, entitlementManager)

	// Initialize handlers
	apiHandlers := handlers.NewAPIHandlers(entitlementManager, jwtManager)

	// Setup router
	router := mux.NewRouter()
	router.Use(middleware.CORS)
	router.Use(middleware.Logging)
	apiHandlers.SetupRoutes(router, authMiddleware)

	// Create test server
	server := httptest.NewServer(router)

	return &TestServer{
		Server:             server,
		EntitlementManager: entitlementManager,
		JWTManager:         jwtManager,
		AuthMiddleware:     authMiddleware,
		APIHandlers:        apiHandlers,
	}
}

// TearDownTestServer cleans up the test server
func (ts *TestServer) TearDownTestServer() {
	ts.Server.Close()
}

// UserProfile represents different test user types
type UserProfile struct {
	UserID       string
	Email        string
	Role         string
	Subscription string
	Features     []string
	Attributes   map[string]string
	IsExpired    bool
}

// Test user profiles
var (
	AdminUser = UserProfile{
		UserID:       "admin-123",
		Email:        "admin@example.com",
		Role:         "admin",
		Subscription: "enterprise",
		Features:     []string{"advanced_analytics", "api_access", "bulk_operations"},
		Attributes: map[string]string{
			"department": "engineering",
			"location":   "us-west",
		},
	}

	PremiumUser = UserProfile{
		UserID:       "user-456",
		Email:        "premium@example.com",
		Role:         "user",
		Subscription: "premium",
		Features:     []string{"advanced_analytics", "priority_support"},
		Attributes: map[string]string{
			"plan_start": time.Now().Format("2006-01-02"),
		},
	}

	BasicUser = UserProfile{
		UserID:       "user-789",
		Email:        "basic@example.com",
		Role:         "user",
		Subscription: "basic",
		Features:     []string{"basic_features"},
		Attributes: map[string]string{
			"trial": "false",
		},
	}

	TrialUser = UserProfile{
		UserID:       "user-trial",
		Email:        "trial@example.com",
		Role:         "user",
		Subscription: "trial",
		Features:     []string{"basic_features"},
		Attributes: map[string]string{
			"trial":      "true",
			"trial_ends": time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		},
	}

	UnknownUser = UserProfile{
		UserID:       "user-unknown",
		Email:        "unknown@example.com",
		Role:         "user",
		Subscription: "basic",
		Features:     []string{"basic_features"},
		Attributes:   map[string]string{},
	}

	ExpiredUser = UserProfile{
		UserID:       "user-expired",
		Email:        "expired@example.com",
		Role:         "user",
		Subscription: "basic",
		Features:     []string{"basic_features"},
		Attributes:   map[string]string{},
		IsExpired:    true,
	}
)

// GenerateTestToken creates a JWT token for the given user profile
func (ts *TestServer) GenerateTestToken(profile UserProfile) (string, error) {
	claims := &auth.JWTClaims{
		UserID:       profile.UserID,
		Email:        profile.Email,
		Role:         profile.Role,
		Subscription: profile.Subscription,
		Features:     profile.Features,
		Attributes:   profile.Attributes,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Issuer:   TestJWTIssuer,
		},
	}

	// Set expiration based on profile
	if profile.IsExpired {
		claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
	} else {
		claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	}

	return ts.JWTManager.GenerateToken(claims)
}

// CreateRequestWithAuth creates an HTTP request with authorization header
func CreateRequestWithAuth(method, url, token string, body interface{}) (*http.Request, error) {
	var reqBody *bytes.Buffer
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(jsonBody)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

// CreateRequest creates an HTTP request without authorization
func CreateRequest(method, url string, body interface{}) (*http.Request, error) {
	return CreateRequestWithAuth(method, url, "", body)
}

// AssertStatusCode asserts that the response has the expected status code
func AssertStatusCode(t *testing.T, resp *http.Response, expected int) {
	if resp.StatusCode != expected {
		t.Errorf("Expected status code %d, got %d", expected, resp.StatusCode)
	}
}

// AssertJSONResponse asserts that the response contains expected JSON structure
func AssertJSONResponse(t *testing.T, resp *http.Response, expectedSuccess bool, expectedCode string) map[string]interface{} {
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	// Check if this is a success response (has 'success' field)
	if success, ok := response["success"].(bool); ok {
		if success != expectedSuccess {
			t.Errorf("Expected success=%t, got success=%t", expectedSuccess, success)
		}

		if expectedCode != "" {
			code, ok := response["code"].(string)
			if !ok && !expectedSuccess {
				t.Errorf("Error response missing 'code' field")
			} else if ok && code != expectedCode {
				t.Errorf("Expected code='%s', got code='%s'", expectedCode, code)
			}
		}
	} else {
		// This is an error response from middleware (has 'error' and 'code' fields)
		if expectedSuccess {
			t.Errorf("Expected success response but got error response")
		}

		if expectedCode != "" {
			code, ok := response["code"].(string)
			if !ok {
				t.Errorf("Error response missing 'code' field")
			} else if code != expectedCode {
				t.Errorf("Expected code='%s', got code='%s'", expectedCode, code)
			}
		}
	}

	return response
}

// AssertErrorResponse asserts that the response is an error with expected details
func AssertErrorResponse(t *testing.T, resp *http.Response, expectedStatus int, expectedCode string) {
	AssertStatusCode(t, resp, expectedStatus)
	AssertJSONResponse(t, resp, false, expectedCode)
}

// AssertSuccessResponse asserts that the response is successful
func AssertSuccessResponse(t *testing.T, resp *http.Response, expectedStatus int) map[string]interface{} {
	AssertStatusCode(t, resp, expectedStatus)
	return AssertJSONResponse(t, resp, true, "")
}

// MakeRequest makes an HTTP request to the test server
func (ts *TestServer) MakeRequest(req *http.Request) (*http.Response, error) {
	client := &http.Client{}
	// Update the request URL to use the test server
	req.URL.Scheme = "http"
	req.URL.Host = ts.Server.URL[7:] // Remove "http://" prefix
	return client.Do(req)
}

// initializeTestData sets up sample users, features, and entitlements for testing
func initializeTestData(manager goentitlement.EntitlementManager) error {
	ctx := context.Background()

	// Sample principals (users) - only known users, not unknown
	principals := []goentitlement.Principal{
		{
			ID:   "admin-123",
			Type: goentitlement.PrincipalTypeUser,
			Attributes: map[string]interface{}{
				"email":      "admin@example.com",
				"department": "engineering",
				"location":   "us-west",
			},
			Groups:    []string{"admin", "subscription:enterprise"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:   "user-456",
			Type: goentitlement.PrincipalTypeUser,
			Attributes: map[string]interface{}{
				"email":      "premium@example.com",
				"plan_start": time.Now().Format("2006-01-02"),
			},
			Groups:    []string{"user", "subscription:premium"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:   "user-789",
			Type: goentitlement.PrincipalTypeUser,
			Attributes: map[string]interface{}{
				"email": "basic@example.com",
				"trial": "false",
			},
			Groups:    []string{"user", "subscription:basic"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:   "user-trial",
			Type: goentitlement.PrincipalTypeUser,
			Attributes: map[string]interface{}{
				"email":      "trial@example.com",
				"trial":      "true",
				"trial_ends": time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
			},
			Groups:    []string{"user", "subscription:trial"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	// Sample resources (features, subscriptions)
	resources := []goentitlement.Resource{
		{
			ID:   "advanced_analytics",
			Type: goentitlement.ResourceTypeFeature,
			Attributes: map[string]interface{}{
				"description": "Advanced analytics and reporting",
				"category":    "analytics",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:   "api_access",
			Type: goentitlement.ResourceTypeFeature,
			Attributes: map[string]interface{}{
				"description": "API access and integration",
				"category":    "integration",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:   "bulk_operations",
			Type: goentitlement.ResourceTypeFeature,
			Attributes: map[string]interface{}{
				"description": "Bulk data operations",
				"category":    "operations",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:   "basic",
			Type: goentitlement.ResourceTypeSubscription,
			Attributes: map[string]interface{}{
				"description": "Basic subscription tier",
				"price":       "$9.99/month",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:   "premium",
			Type: goentitlement.ResourceTypeSubscription,
			Attributes: map[string]interface{}{
				"description": "Premium subscription tier",
				"price":       "$29.99/month",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:   "enterprise",
			Type: goentitlement.ResourceTypeSubscription,
			Attributes: map[string]interface{}{
				"description": "Enterprise subscription tier",
				"price":       "$99.99/month",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	// Sample entitlements
	entitlements := []goentitlement.Entitlement{
		// Admin user entitlements
		{
			Type:      goentitlement.EntitlementTypeRole,
			Principal: principals[0], // admin-123
			Action:    "admin",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			Type:      goentitlement.EntitlementTypeSubscription,
			Principal: principals[0], // admin-123
			Resource:  &resources[4], // premium
			Action:    "use",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			Type:      goentitlement.EntitlementTypeSubscription,
			Principal: principals[0], // admin-123
			Resource:  &resources[5], // enterprise
			Action:    "use",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			Type:      goentitlement.EntitlementTypeFeatureFlag,
			Principal: principals[0], // admin-123
			Resource:  &resources[0], // advanced_analytics
			Action:    "use",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			Type:      goentitlement.EntitlementTypeFeatureFlag,
			Principal: principals[0], // admin-123
			Resource:  &resources[1], // api_access
			Action:    "use",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			Type:      goentitlement.EntitlementTypeFeatureFlag,
			Principal: principals[0], // admin-123
			Resource:  &resources[2], // bulk_operations
			Action:    "use",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},

		// Premium user entitlements
		{
			Type:      goentitlement.EntitlementTypeSubscription,
			Principal: principals[1], // user-456
			Resource:  &resources[4], // premium
			Action:    "use",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			Type:      goentitlement.EntitlementTypeFeatureFlag,
			Principal: principals[1], // user-456
			Resource:  &resources[0], // advanced_analytics
			Action:    "use",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},

		// Basic user entitlements
		{
			Type:      goentitlement.EntitlementTypeSubscription,
			Principal: principals[2], // user-789
			Resource:  &resources[3], // basic
			Action:    "use",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},

		// Trial user entitlements
		{
			Type:      goentitlement.EntitlementTypeSubscription,
			Principal: principals[3], // user-trial
			Resource:  &resources[3], // basic (trial has basic features)
			Action:    "use",
			ExpiresAt: func() *time.Time { t := time.Now().AddDate(0, 0, 14); return &t }(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	// Grant all entitlements
	for _, entitlement := range entitlements {
		if err := manager.GrantEntitlement(ctx, entitlement); err != nil {
			return fmt.Errorf("failed to grant entitlement: %w", err)
		}
	}

	return nil
}
