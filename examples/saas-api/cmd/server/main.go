package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/benbenbenbenbenben/goentitlement"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/auth"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/handlers"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/middleware"
	"github.com/gorilla/mux"
)

const (
	// Server configuration
	serverPort = ":8080"

	// JWT configuration
	jwtSigningKey = "your-super-secret-jwt-signing-key-change-this-in-production"
	jwtIssuer     = "saas-api-example"
)

func main() {
	log.Println("Starting SaaS API Example with goentitlement integration...")

	// Initialize the goentitlement manager with in-memory store
	entitlementManager := goentitlement.NewManager()

	// Initialize sample data
	if err := initializeSampleData(entitlementManager); err != nil {
		log.Fatalf("Failed to initialize sample data: %v", err)
	}

	// Initialize JWT manager
	jwtManager := auth.NewJWTManager([]byte(jwtSigningKey), jwtIssuer)

	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(jwtManager, entitlementManager)

	// Initialize handlers
	apiHandlers := handlers.NewAPIHandlers(entitlementManager, jwtManager)

	// Setup router
	router := mux.NewRouter()

	// Apply global middleware
	router.Use(middleware.CORS)
	router.Use(middleware.Logging)

	// Setup API routes
	apiHandlers.SetupRoutes(router, authMiddleware)

	// Create HTTP server
	server := &http.Server{
		Addr:         serverPort,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on port %s", serverPort)
		log.Println("Available endpoints:")
		log.Println("  GET  /health                    - Health check")
		log.Println("  GET  /api/public                - Public information")
		log.Println("  GET  /api/tokens                - Get test JWT tokens")
		log.Println("  GET  /api/protected             - Protected endpoint (requires auth)")
		log.Println("  GET  /api/profile               - User profile (requires auth)")
		log.Println("  GET  /api/features/analytics    - Advanced analytics (requires feature)")
		log.Println("  GET  /api/features/api-access   - API access (requires feature)")
		log.Println("  GET  /api/subscription/premium  - Premium features (requires premium+)")
		log.Println("  GET  /api/subscription/enterprise - Enterprise features (requires enterprise)")
		log.Println("  GET  /api/admin/dashboard       - Admin dashboard (requires admin role)")
		log.Println("")
		log.Printf("Visit http://localhost%s/api/tokens to get test JWT tokens", serverPort)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

// initializeSampleData sets up sample users, features, and entitlements for testing
func initializeSampleData(manager goentitlement.EntitlementManager) error {
	ctx := context.Background()

	// Sample principals (users)
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
			return err
		}
	}

	log.Printf("Initialized sample data:")
	log.Printf("  - %d principals", len(principals))
	log.Printf("  - %d resources", len(resources))
	log.Printf("  - %d entitlements", len(entitlements))

	return nil
}
