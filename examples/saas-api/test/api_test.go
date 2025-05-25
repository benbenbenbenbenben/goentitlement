package test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/benbenbenbenbenben/goentitlement"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/auth"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/middleware"
	"github.com/golang-jwt/jwt/v5"
)

// TestJWTValidation tests JWT token validation scenarios
func TestJWTValidation(t *testing.T) {
	jwtManager := auth.NewJWTManager([]byte(TestJWTSigningKey), TestJWTIssuer)

	tests := []struct {
		name        string
		setupToken  func() string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid token",
			setupToken: func() string {
				claims := &auth.JWTClaims{
					UserID:       "test-user",
					Email:        "test@example.com",
					Role:         "user",
					Subscription: "basic",
					Features:     []string{"basic_features"},
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						Issuer:    TestJWTIssuer,
					},
				}
				token, _ := jwtManager.GenerateToken(claims)
				return token
			},
			expectError: false,
		},
		{
			name: "expired token",
			setupToken: func() string {
				claims := &auth.JWTClaims{
					UserID:       "test-user",
					Email:        "test@example.com",
					Role:         "user",
					Subscription: "basic",
					Features:     []string{"basic_features"},
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
						IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
						Issuer:    TestJWTIssuer,
					},
				}
				token, _ := jwtManager.GenerateToken(claims)
				return token
			},
			expectError: true,
			errorMsg:    "token is expired",
		},
		{
			name: "invalid token format",
			setupToken: func() string {
				return "invalid.token.format"
			},
			expectError: true,
			errorMsg:    "failed to parse token",
		},
		{
			name: "malformed token",
			setupToken: func() string {
				return "not-a-jwt-token"
			},
			expectError: true,
			errorMsg:    "failed to parse token",
		},
		{
			name: "token with wrong signing key",
			setupToken: func() string {
				wrongJWTManager := auth.NewJWTManager([]byte("wrong-key"), TestJWTIssuer)
				claims := &auth.JWTClaims{
					UserID:       "test-user",
					Email:        "test@example.com",
					Role:         "user",
					Subscription: "basic",
					Features:     []string{"basic_features"},
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						Issuer:    TestJWTIssuer,
					},
				}
				token, _ := wrongJWTManager.GenerateToken(claims)
				return token
			},
			expectError: true,
			errorMsg:    "failed to parse token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.setupToken()
			claims, err := jwtManager.ValidateToken(token)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if claims == nil {
					t.Errorf("Expected claims but got nil")
				}
			}
		})
	}
}

// TestPrincipalExtraction tests conversion from JWT claims to Principal
func TestPrincipalExtraction(t *testing.T) {
	tests := []struct {
		name   string
		claims *auth.JWTClaims
		verify func(t *testing.T, principal goentitlement.Principal)
	}{
		{
			name: "basic user claims",
			claims: &auth.JWTClaims{
				UserID:       "user-123",
				Email:        "user@example.com",
				Role:         "user",
				Subscription: "basic",
				Features:     []string{"basic_features"},
				Attributes: map[string]string{
					"department": "engineering",
				},
			},
			verify: func(t *testing.T, principal goentitlement.Principal) {
				if principal.ID != "user-123" {
					t.Errorf("Expected ID 'user-123', got '%s'", principal.ID)
				}
				if principal.Type != goentitlement.PrincipalTypeUser {
					t.Errorf("Expected type 'user', got '%s'", principal.Type)
				}
				if email, ok := principal.Attributes["email"].(string); !ok || email != "user@example.com" {
					t.Errorf("Expected email 'user@example.com', got '%v'", principal.Attributes["email"])
				}
				if role, ok := principal.Attributes["role"].(string); !ok || role != "user" {
					t.Errorf("Expected role 'user', got '%v'", principal.Attributes["role"])
				}
				if subscription, ok := principal.Attributes["subscription"].(string); !ok || subscription != "basic" {
					t.Errorf("Expected subscription 'basic', got '%v'", principal.Attributes["subscription"])
				}
				expectedGroups := []string{"user", "subscription:basic"}
				if len(principal.Groups) != len(expectedGroups) {
					t.Errorf("Expected %d groups, got %d", len(expectedGroups), len(principal.Groups))
				}
			},
		},
		{
			name: "admin with enterprise subscription",
			claims: &auth.JWTClaims{
				UserID:       "admin-456",
				Email:        "admin@example.com",
				Role:         "admin",
				Subscription: "enterprise",
				Features:     []string{"advanced_analytics", "api_access"},
			},
			verify: func(t *testing.T, principal goentitlement.Principal) {
				expectedGroups := []string{"admin", "subscription:enterprise"}
				if len(principal.Groups) != len(expectedGroups) {
					t.Errorf("Expected groups %v, got %v", expectedGroups, principal.Groups)
				}
				features, ok := principal.Attributes["features"].([]string)
				if !ok {
					t.Errorf("Expected features to be []string, got %T", principal.Attributes["features"])
				} else if len(features) != 2 {
					t.Errorf("Expected 2 features, got %d", len(features))
				}
			},
		},
		{
			name: "user without subscription",
			claims: &auth.JWTClaims{
				UserID: "user-789",
				Email:  "user@example.com",
				Role:   "user",
				// No subscription
				Features: []string{},
			},
			verify: func(t *testing.T, principal goentitlement.Principal) {
				expectedGroups := []string{"user"}
				if len(principal.Groups) != len(expectedGroups) {
					t.Errorf("Expected groups %v, got %v", expectedGroups, principal.Groups)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal := auth.ClaimsToPrincipal(tt.claims)
			tt.verify(t, principal)
		})
	}
}

// TestMiddlewareAuthentication tests the authentication middleware
func TestMiddlewareAuthentication(t *testing.T) {
	testServer := SetupTestServer(t)
	defer testServer.TearDownTestServer()

	tests := []struct {
		name           string
		setupRequest   func() (string, string)
		expectedStatus int
		expectedCode   string
	}{
		{
			name: "missing authorization header",
			setupRequest: func() (string, string) {
				return "GET", ""
			},
			expectedStatus: 401,
			expectedCode:   "MISSING_TOKEN",
		},
		{
			name: "invalid authorization header format",
			setupRequest: func() (string, string) {
				return "GET", "InvalidFormat token"
			},
			expectedStatus: 401,
			expectedCode:   "INVALID_TOKEN_FORMAT",
		},
		{
			name: "missing Bearer prefix",
			setupRequest: func() (string, string) {
				token, _ := testServer.GenerateTestToken(BasicUser)
				return "GET", token // Missing "Bearer " prefix
			},
			expectedStatus: 401,
			expectedCode:   "INVALID_TOKEN_FORMAT",
		},
		{
			name: "invalid token",
			setupRequest: func() (string, string) {
				return "GET", "Bearer invalid-token"
			},
			expectedStatus: 401,
			expectedCode:   "INVALID_TOKEN",
		},
		{
			name: "expired token",
			setupRequest: func() (string, string) {
				token, _ := testServer.GenerateTestToken(ExpiredUser)
				return "GET", "Bearer " + token
			},
			expectedStatus: 401,
			expectedCode:   "INVALID_TOKEN",
		},
		{
			name: "valid token",
			setupRequest: func() (string, string) {
				token, _ := testServer.GenerateTestToken(BasicUser)
				return "GET", "Bearer " + token
			},
			expectedStatus: 200,
			expectedCode:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, authHeader := tt.setupRequest()

			req, err := CreateRequest(method, testServer.Server.URL+"/api/protected", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			if authHeader != "" {
				req.Header.Set("Authorization", authHeader)
			}

			resp, err := testServer.MakeRequest(req)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			AssertStatusCode(t, resp, tt.expectedStatus)
			if tt.expectedCode != "" {
				AssertJSONResponse(t, resp, false, tt.expectedCode)
			}
		})
	}
}

// TestFeatureAuthorization tests feature-based authorization
func TestFeatureAuthorization(t *testing.T) {
	testServer := SetupTestServer(t)
	defer testServer.TearDownTestServer()

	tests := []struct {
		name           string
		userProfile    UserProfile
		endpoint       string
		expectedStatus int
		expectedCode   string
	}{
		{
			name:           "admin accessing analytics feature",
			userProfile:    AdminUser,
			endpoint:       "/api/features/analytics",
			expectedStatus: 200,
		},
		{
			name:           "premium user accessing analytics feature",
			userProfile:    PremiumUser,
			endpoint:       "/api/features/analytics",
			expectedStatus: 200,
		},
		{
			name:           "basic user accessing analytics feature (denied)",
			userProfile:    BasicUser,
			endpoint:       "/api/features/analytics",
			expectedStatus: 403,
			expectedCode:   "FEATURE_NOT_ENABLED",
		},
		{
			name:           "admin accessing api access feature",
			userProfile:    AdminUser,
			endpoint:       "/api/features/api-access",
			expectedStatus: 200,
		},
		{
			name:           "basic user accessing api access feature (denied)",
			userProfile:    BasicUser,
			endpoint:       "/api/features/api-access",
			expectedStatus: 403,
			expectedCode:   "FEATURE_NOT_ENABLED",
		},
		{
			name:           "trial user accessing analytics feature (denied)",
			userProfile:    TrialUser,
			endpoint:       "/api/features/analytics",
			expectedStatus: 403,
			expectedCode:   "FEATURE_NOT_ENABLED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := testServer.GenerateTestToken(tt.userProfile)
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			req, err := CreateRequestWithAuth("GET", testServer.Server.URL+tt.endpoint, token, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := testServer.MakeRequest(req)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			AssertStatusCode(t, resp, tt.expectedStatus)
			if tt.expectedCode != "" {
				AssertJSONResponse(t, resp, false, tt.expectedCode)
			}
		})
	}
}

// TestSubscriptionAuthorization tests subscription-based authorization
func TestSubscriptionAuthorization(t *testing.T) {
	testServer := SetupTestServer(t)
	defer testServer.TearDownTestServer()

	tests := []struct {
		name           string
		userProfile    UserProfile
		endpoint       string
		expectedStatus int
		expectedCode   string
	}{
		{
			name:           "premium user accessing premium features",
			userProfile:    PremiumUser,
			endpoint:       "/api/subscription/premium",
			expectedStatus: 200,
		},
		{
			name:           "admin accessing premium features",
			userProfile:    AdminUser,
			endpoint:       "/api/subscription/premium",
			expectedStatus: 200,
		},
		{
			name:           "basic user accessing premium features (denied)",
			userProfile:    BasicUser,
			endpoint:       "/api/subscription/premium",
			expectedStatus: 403,
			expectedCode:   "INSUFFICIENT_SUBSCRIPTION",
		},
		{
			name:           "admin accessing enterprise features",
			userProfile:    AdminUser,
			endpoint:       "/api/subscription/enterprise",
			expectedStatus: 200,
		},
		{
			name:           "premium user accessing enterprise features (denied)",
			userProfile:    PremiumUser,
			endpoint:       "/api/subscription/enterprise",
			expectedStatus: 403,
			expectedCode:   "INSUFFICIENT_SUBSCRIPTION",
		},
		{
			name:           "trial user accessing premium features (denied)",
			userProfile:    TrialUser,
			endpoint:       "/api/subscription/premium",
			expectedStatus: 403,
			expectedCode:   "INSUFFICIENT_SUBSCRIPTION",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := testServer.GenerateTestToken(tt.userProfile)
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			req, err := CreateRequestWithAuth("GET", testServer.Server.URL+tt.endpoint, token, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := testServer.MakeRequest(req)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			AssertStatusCode(t, resp, tt.expectedStatus)
			if tt.expectedCode != "" {
				AssertJSONResponse(t, resp, false, tt.expectedCode)
			}
		})
	}
}

// TestRoleAuthorization tests role-based authorization
func TestRoleAuthorization(t *testing.T) {
	testServer := SetupTestServer(t)
	defer testServer.TearDownTestServer()

	tests := []struct {
		name           string
		userProfile    UserProfile
		endpoint       string
		expectedStatus int
		expectedCode   string
	}{
		{
			name:           "admin accessing admin dashboard",
			userProfile:    AdminUser,
			endpoint:       "/api/admin/dashboard",
			expectedStatus: 200,
		},
		{
			name:           "regular user accessing admin dashboard (denied)",
			userProfile:    BasicUser,
			endpoint:       "/api/admin/dashboard",
			expectedStatus: 403,
			expectedCode:   "INSUFFICIENT_ROLE",
		},
		{
			name:           "premium user accessing admin dashboard (denied)",
			userProfile:    PremiumUser,
			endpoint:       "/api/admin/dashboard",
			expectedStatus: 403,
			expectedCode:   "INSUFFICIENT_ROLE",
		},
		{
			name:           "trial user accessing admin dashboard (denied)",
			userProfile:    TrialUser,
			endpoint:       "/api/admin/dashboard",
			expectedStatus: 403,
			expectedCode:   "INSUFFICIENT_ROLE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := testServer.GenerateTestToken(tt.userProfile)
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			req, err := CreateRequestWithAuth("GET", testServer.Server.URL+tt.endpoint, token, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := testServer.MakeRequest(req)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			AssertStatusCode(t, resp, tt.expectedStatus)
			if tt.expectedCode != "" {
				AssertJSONResponse(t, resp, false, tt.expectedCode)
			}
		})
	}
}

// TestOptionalAuth tests the optional authentication middleware
func TestOptionalAuth(t *testing.T) {
	testServer := SetupTestServer(t)
	defer testServer.TearDownTestServer()

	// Test with public endpoint that uses OptionalAuth
	tests := []struct {
		name           string
		setupAuth      func() string
		expectedStatus int
	}{
		{
			name: "no auth header - should succeed",
			setupAuth: func() string {
				return ""
			},
			expectedStatus: 200,
		},
		{
			name: "invalid auth header - should succeed (optional)",
			setupAuth: func() string {
				return "Invalid format"
			},
			expectedStatus: 200,
		},
		{
			name: "valid auth header - should succeed with principal",
			setupAuth: func() string {
				token, _ := testServer.GenerateTestToken(BasicUser)
				return "Bearer " + token
			},
			expectedStatus: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := CreateRequest("GET", testServer.Server.URL+"/api/public", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			authHeader := tt.setupAuth()
			if authHeader != "" {
				req.Header.Set("Authorization", authHeader)
			}

			resp, err := testServer.MakeRequest(req)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			AssertStatusCode(t, resp, tt.expectedStatus)
		})
	}
}

// TestJWTClaimsValidation tests validation of required JWT claims
func TestJWTClaimsValidation(t *testing.T) {
	jwtManager := auth.NewJWTManager([]byte(TestJWTSigningKey), TestJWTIssuer)

	tests := []struct {
		name        string
		claims      *auth.JWTClaims
		expectError bool
	}{
		{
			name: "all required claims present",
			claims: &auth.JWTClaims{
				UserID:       "user-123",
				Email:        "user@example.com",
				Role:         "user",
				Subscription: "basic",
				Features:     []string{"basic_features"},
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    TestJWTIssuer,
				},
			},
			expectError: false,
		},
		{
			name: "missing user ID",
			claims: &auth.JWTClaims{
				// UserID missing
				Email:        "user@example.com",
				Role:         "user",
				Subscription: "basic",
				Features:     []string{"basic_features"},
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    TestJWTIssuer,
				},
			},
			expectError: false, // JWT validation doesn't require specific claims, just valid structure
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := jwtManager.GenerateToken(tt.claims)
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			claims, err := jwtManager.ValidateToken(token)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && claims == nil {
				t.Errorf("Expected claims but got nil")
			}
		})
	}
}

// TestContextPrincipalExtraction tests extracting principal from context
func TestContextPrincipalExtraction(t *testing.T) {
	// Create a test principal
	principal := goentitlement.Principal{
		ID:   "test-user",
		Type: goentitlement.PrincipalTypeUser,
		Attributes: map[string]interface{}{
			"email": "test@example.com",
		},
		Groups:    []string{"user"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Test with principal in context
	ctx := context.WithValue(context.Background(), middleware.PrincipalContextKey, principal)
	extractedPrincipal, ok := middleware.GetPrincipalFromContext(ctx)
	if !ok {
		t.Errorf("Expected to extract principal from context")
	}
	if extractedPrincipal.ID != "test-user" {
		t.Errorf("Expected principal ID 'test-user', got '%s'", extractedPrincipal.ID)
	}

	// Test with no principal in context
	emptyCtx := context.Background()
	_, ok = middleware.GetPrincipalFromContext(emptyCtx)
	if ok {
		t.Errorf("Expected no principal in empty context")
	}
}
