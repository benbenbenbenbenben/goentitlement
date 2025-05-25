package test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/benbenbenbenbenben/goentitlement"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

// BenchmarkJWTValidation benchmarks JWT token validation performance
func BenchmarkJWTValidation(b *testing.B) {
	jwtManager := auth.NewJWTManager([]byte(TestJWTSigningKey), TestJWTIssuer)

	// Pre-generate a valid token
	claims := &auth.JWTClaims{
		UserID:       "bench-user",
		Email:        "bench@example.com",
		Role:         "user",
		Subscription: "basic",
		Features:     []string{"basic_features"},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    TestJWTIssuer,
		},
	}
	token, err := jwtManager.GenerateToken(claims)
	if err != nil {
		b.Fatalf("Failed to generate token: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := jwtManager.ValidateToken(token)
			if err != nil {
				b.Errorf("Token validation failed: %v", err)
			}
		}
	})
}

// BenchmarkJWTGeneration benchmarks JWT token generation performance
func BenchmarkJWTGeneration(b *testing.B) {
	jwtManager := auth.NewJWTManager([]byte(TestJWTSigningKey), TestJWTIssuer)

	claims := &auth.JWTClaims{
		UserID:       "bench-user",
		Email:        "bench@example.com",
		Role:         "user",
		Subscription: "basic",
		Features:     []string{"basic_features"},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    TestJWTIssuer,
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := jwtManager.GenerateToken(claims)
			if err != nil {
				b.Errorf("Token generation failed: %v", err)
			}
		}
	})
}

// BenchmarkClaimsToPrincipalConversion benchmarks conversion from JWT claims to Principal
func BenchmarkClaimsToPrincipalConversion(b *testing.B) {
	claims := &auth.JWTClaims{
		UserID:       "bench-user",
		Email:        "bench@example.com",
		Role:         "user",
		Subscription: "premium",
		Features:     []string{"feature1", "feature2", "feature3"},
		Attributes: map[string]string{
			"department": "engineering",
			"location":   "us-west",
			"team":       "backend",
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			principal := auth.ClaimsToPrincipal(claims)
			_ = principal // Use the result to prevent optimization
		}
	})
}

// BenchmarkEntitlementChecks benchmarks various entitlement check operations
func BenchmarkEntitlementChecks(b *testing.B) {
	manager := goentitlement.NewManager()
	ctx := context.Background()

	// Initialize test data
	if err := initializeTestData(manager); err != nil {
		b.Fatalf("Failed to initialize test data: %v", err)
	}

	// Create test principal
	principal := goentitlement.Principal{
		ID:   "admin-123",
		Type: goentitlement.PrincipalTypeUser,
		Attributes: map[string]interface{}{
			"email": "admin@example.com",
		},
		Groups:    []string{"admin", "subscription:enterprise"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	benchmarks := []struct {
		name string
		fn   func() error
	}{
		{
			name: "HasRole",
			fn: func() error {
				_, err := manager.HasRole(ctx, principal, "admin")
				return err
			},
		},
		{
			name: "HasFeature",
			fn: func() error {
				_, err := manager.HasFeature(ctx, principal, "advanced_analytics")
				return err
			},
		},
		{
			name: "HasSubscription",
			fn: func() error {
				_, err := manager.HasSubscription(ctx, principal, "enterprise")
				return err
			},
		},
		{
			name: "CheckPermission",
			fn: func() error {
				resource := goentitlement.Resource{
					ID:   "test-resource",
					Type: goentitlement.ResourceTypeCustom,
				}
				_, err := manager.CheckPermission(ctx, principal, "read", resource)
				return err
			},
		},
		{
			name: "ListEntitlements",
			fn: func() error {
				_, err := manager.ListEntitlements(ctx, principal)
				return err
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := bm.fn(); err != nil {
						b.Errorf("Entitlement check failed: %v", err)
					}
				}
			})
		})
	}
}

// BenchmarkAPIEndpoints benchmarks HTTP endpoint performance
func BenchmarkAPIEndpoints(b *testing.B) {
	testServer := SetupTestServer(b)
	defer testServer.TearDownTestServer()

	// Pre-generate tokens for different user types
	adminToken, _ := testServer.GenerateTestToken(AdminUser)
	premiumToken, _ := testServer.GenerateTestToken(PremiumUser)
	basicToken, _ := testServer.GenerateTestToken(BasicUser)

	endpoints := []struct {
		name     string
		endpoint string
		token    string
	}{
		{"PublicHealth", "/health", ""},
		{"PublicInfo", "/api/public", ""},
		{"ProtectedBasic", "/api/protected", basicToken},
		{"ProtectedPremium", "/api/protected", premiumToken},
		{"ProtectedAdmin", "/api/protected", adminToken},
		{"ProfileBasic", "/api/profile", basicToken},
		{"ProfilePremium", "/api/profile", premiumToken},
		{"ProfileAdmin", "/api/profile", adminToken},
		{"FeatureAnalyticsPremium", "/api/features/analytics", premiumToken},
		{"FeatureAnalyticsAdmin", "/api/features/analytics", adminToken},
		{"SubscriptionPremium", "/api/subscription/premium", premiumToken},
		{"SubscriptionEnterprise", "/api/subscription/enterprise", adminToken},
		{"AdminDashboard", "/api/admin/dashboard", adminToken},
	}

	for _, endpoint := range endpoints {
		b.Run(endpoint.name, func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					var req *http.Request
					var err error

					if endpoint.token != "" {
						req, err = CreateRequestWithAuth("GET", testServer.Server.URL+endpoint.endpoint, endpoint.token, nil)
					} else {
						req, err = CreateRequest("GET", testServer.Server.URL+endpoint.endpoint, nil)
					}

					if err != nil {
						b.Errorf("Failed to create request: %v", err)
						continue
					}

					resp, err := testServer.MakeRequest(req)
					if err != nil {
						b.Errorf("Failed to make request: %v", err)
						continue
					}
					resp.Body.Close()

					if resp.StatusCode >= 400 {
						b.Errorf("Request failed with status %d for endpoint %s", resp.StatusCode, endpoint.endpoint)
					}
				}
			})
		})
	}
}

// BenchmarkConcurrentRequests benchmarks concurrent request handling
func BenchmarkConcurrentRequests(b *testing.B) {
	testServer := SetupTestServer(b)
	defer testServer.TearDownTestServer()

	token, _ := testServer.GenerateTestToken(BasicUser)

	concurrencies := []int{1, 10, 50, 100}

	for _, concurrency := range concurrencies {
		b.Run(fmt.Sprintf("Concurrency%d", concurrency), func(b *testing.B) {
			b.SetParallelism(concurrency)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					req, err := CreateRequestWithAuth("GET", testServer.Server.URL+"/api/protected", token, nil)
					if err != nil {
						b.Errorf("Failed to create request: %v", err)
						continue
					}

					resp, err := testServer.MakeRequest(req)
					if err != nil {
						b.Errorf("Failed to make request: %v", err)
						continue
					}
					resp.Body.Close()

					if resp.StatusCode != 200 {
						b.Errorf("Expected status 200, got %d", resp.StatusCode)
					}
				}
			})
		})
	}
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	testServer := SetupTestServer(b)
	defer testServer.TearDownTestServer()

	b.Run("TokenGeneration", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := testServer.GenerateTestToken(BasicUser)
			if err != nil {
				b.Errorf("Failed to generate token: %v", err)
			}
		}
	})

	b.Run("RequestProcessing", func(b *testing.B) {
		token, _ := testServer.GenerateTestToken(BasicUser)
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			req, err := CreateRequestWithAuth("GET", testServer.Server.URL+"/api/protected", token, nil)
			if err != nil {
				b.Errorf("Failed to create request: %v", err)
				continue
			}

			resp, err := testServer.MakeRequest(req)
			if err != nil {
				b.Errorf("Failed to make request: %v", err)
				continue
			}
			resp.Body.Close()
		}
	})
}

// BenchmarkLoadTesting simulates load testing scenarios
func BenchmarkLoadTesting(b *testing.B) {
	testServer := SetupTestServer(b)
	defer testServer.TearDownTestServer()

	// Pre-generate tokens for different user types
	userTokens := make([]string, 100)
	userProfiles := []UserProfile{AdminUser, PremiumUser, BasicUser, TrialUser}

	for i := 0; i < 100; i++ {
		profile := userProfiles[i%len(userProfiles)]
		profile.UserID = fmt.Sprintf("load-user-%d", i)
		token, _ := testServer.GenerateTestToken(profile)
		userTokens[i] = token
	}

	endpoints := []string{
		"/api/protected",
		"/api/profile",
		"/api/features/analytics",
		"/api/subscription/premium",
		"/api/admin/dashboard",
	}

	b.Run("MixedWorkload", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				// Simulate realistic user behavior
				token := userTokens[b.N%len(userTokens)]
				endpoint := endpoints[b.N%len(endpoints)]

				req, err := CreateRequestWithAuth("GET", testServer.Server.URL+endpoint, token, nil)
				if err != nil {
					continue
				}

				resp, err := testServer.MakeRequest(req)
				if err != nil {
					continue
				}
				resp.Body.Close()
			}
		})
	})
}

// BenchmarkAuthorizationPatterns benchmarks different authorization patterns
func BenchmarkAuthorizationPatterns(b *testing.B) {
	testServer := SetupTestServer(b)
	defer testServer.TearDownTestServer()

	patterns := []struct {
		name     string
		endpoint string
		users    []UserProfile
	}{
		{
			name:     "RoleBasedAccess",
			endpoint: "/api/admin/dashboard",
			users:    []UserProfile{AdminUser, BasicUser}, // Admin succeeds, Basic fails
		},
		{
			name:     "FeatureBasedAccess",
			endpoint: "/api/features/analytics",
			users:    []UserProfile{AdminUser, PremiumUser, BasicUser}, // Admin & Premium succeed, Basic fails
		},
		{
			name:     "SubscriptionBasedAccess",
			endpoint: "/api/subscription/premium",
			users:    []UserProfile{AdminUser, PremiumUser, BasicUser}, // Admin & Premium succeed, Basic fails
		},
	}

	for _, pattern := range patterns {
		b.Run(pattern.name, func(b *testing.B) {
			tokens := make([]string, len(pattern.users))
			for i, user := range pattern.users {
				tokens[i], _ = testServer.GenerateTestToken(user)
			}

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					token := tokens[b.N%len(tokens)]
					req, err := CreateRequestWithAuth("GET", testServer.Server.URL+pattern.endpoint, token, nil)
					if err != nil {
						continue
					}

					resp, err := testServer.MakeRequest(req)
					if err != nil {
						continue
					}
					resp.Body.Close()
				}
			})
		})
	}
}

// BenchmarkCachePerformance benchmarks caching scenarios (if implemented)
func BenchmarkCachePerformance(b *testing.B) {
	testServer := SetupTestServer(b)
	defer testServer.TearDownTestServer()

	token, _ := testServer.GenerateTestToken(AdminUser)

	b.Run("RepeatedEntitlementChecks", func(b *testing.B) {
		// Simulate repeated checks for the same user/resource combinations
		// This would benefit from caching if implemented
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				req, err := CreateRequestWithAuth("GET", testServer.Server.URL+"/api/profile", token, nil)
				if err != nil {
					continue
				}

				resp, err := testServer.MakeRequest(req)
				if err != nil {
					continue
				}
				resp.Body.Close()
			}
		})
	})
}

// BenchmarkErrorHandling benchmarks error handling performance
func BenchmarkErrorHandling(b *testing.B) {
	testServer := SetupTestServer(b)
	defer testServer.TearDownTestServer()

	errorScenarios := []struct {
		name    string
		request func() (*http.Request, error)
	}{
		{
			name: "MissingAuth",
			request: func() (*http.Request, error) {
				return CreateRequest("GET", testServer.Server.URL+"/api/protected", nil)
			},
		},
		{
			name: "InvalidToken",
			request: func() (*http.Request, error) {
				return CreateRequestWithAuth("GET", testServer.Server.URL+"/api/protected", "invalid-token", nil)
			},
		},
		{
			name: "InsufficientPermissions",
			request: func() (*http.Request, error) {
				token, _ := testServer.GenerateTestToken(BasicUser)
				return CreateRequestWithAuth("GET", testServer.Server.URL+"/api/admin/dashboard", token, nil)
			},
		},
	}

	for _, scenario := range errorScenarios {
		b.Run(scenario.name, func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					req, err := scenario.request()
					if err != nil {
						continue
					}

					resp, err := testServer.MakeRequest(req)
					if err != nil {
						continue
					}
					resp.Body.Close()
				}
			})
		})
	}
}

// BenchmarkResourceContention benchmarks resource contention scenarios
func BenchmarkResourceContention(b *testing.B) {
	testServer := SetupTestServer(b)
	defer testServer.TearDownTestServer()

	// Create multiple users accessing the same resources
	var tokens []string
	for i := 0; i < 10; i++ {
		profile := AdminUser
		profile.UserID = fmt.Sprintf("contention-user-%d", i)
		token, _ := testServer.GenerateTestToken(profile)
		tokens = append(tokens, token)
	}

	b.Run("SharedResourceAccess", func(b *testing.B) {
		var wg sync.WaitGroup
		concurrency := 10

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			wg.Add(concurrency)
			for j := 0; j < concurrency; j++ {
				go func(tokenIndex int) {
					defer wg.Done()
					token := tokens[tokenIndex%len(tokens)]
					req, err := CreateRequestWithAuth("GET", testServer.Server.URL+"/api/profile", token, nil)
					if err != nil {
						return
					}

					resp, err := testServer.MakeRequest(req)
					if err != nil {
						return
					}
					resp.Body.Close()
				}(j)
			}
			wg.Wait()
		}
	})
}
