package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/benbenbenbenbenben/goentitlement"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/auth"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/middleware"
	"github.com/gorilla/mux"
)

// APIHandlers contains all API handlers and dependencies
type APIHandlers struct {
	entitlementManager goentitlement.EntitlementManager
	jwtManager         *auth.JWTManager
}

// NewAPIHandlers creates a new API handlers instance
func NewAPIHandlers(entitlementManager goentitlement.EntitlementManager, jwtManager *auth.JWTManager) *APIHandlers {
	return &APIHandlers{
		entitlementManager: entitlementManager,
		jwtManager:         jwtManager,
	}
}

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Code    string      `json:"code,omitempty"`
}

// UserInfo represents user information response
type UserInfo struct {
	UserID       string            `json:"user_id"`
	Email        string            `json:"email"`
	Role         string            `json:"role"`
	Subscription string            `json:"subscription"`
	Features     []string          `json:"features"`
	Attributes   map[string]string `json:"attributes"`
}

// FeatureStatus represents feature status information
type FeatureStatus struct {
	Feature string `json:"feature"`
	Enabled bool   `json:"enabled"`
}

// SubscriptionInfo represents subscription information
type SubscriptionInfo struct {
	Tier      string `json:"tier"`
	Active    bool   `json:"active"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// writeJSONResponse writes a JSON response
func writeJSONResponse(w http.ResponseWriter, statusCode int, response Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// Public Endpoints (no auth required)

// HealthHandler handles health check requests
func (h *APIHandlers) HealthHandler(w http.ResponseWriter, r *http.Request) {
	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// PublicInfoHandler provides public information about the API
func (h *APIHandlers) PublicInfoHandler(w http.ResponseWriter, r *http.Request) {
	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"name":        "SaaS API Example",
			"description": "Example API demonstrating goentitlement integration",
			"features": []string{
				"JWT Authentication",
				"Role-based Access Control",
				"Feature Flags",
				"Subscription Tiers",
			},
			"endpoints": map[string]string{
				"health":    "/health",
				"public":    "/api/public",
				"protected": "/api/protected",
				"features":  "/api/features",
				"premium":   "/api/premium",
				"admin":     "/api/admin",
			},
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// GetTestTokensHandler provides test JWT tokens for different user types
func (h *APIHandlers) GetTestTokensHandler(w http.ResponseWriter, r *http.Request) {
	adminToken, _ := h.jwtManager.GenerateTestAdminToken()
	premiumToken, _ := h.jwtManager.GenerateTestPremiumUserToken()
	basicToken, _ := h.jwtManager.GenerateTestBasicUserToken()
	trialToken, _ := h.jwtManager.GenerateTestTrialUserToken()

	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"admin": map[string]string{
				"token":       adminToken,
				"description": "Admin user with enterprise subscription and all features",
			},
			"premium": map[string]string{
				"token":       premiumToken,
				"description": "Premium user with advanced features",
			},
			"basic": map[string]string{
				"token":       basicToken,
				"description": "Basic user with standard features",
			},
			"trial": map[string]string{
				"token":       trialToken,
				"description": "Trial user with limited access",
			},
			"usage": map[string]string{
				"header":  "Authorization: Bearer <token>",
				"example": "curl -H 'Authorization: Bearer " + basicToken[:20] + "...' http://localhost:8080/api/protected",
			},
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// Protected Endpoints (require basic authentication)

// ProtectedHandler requires authentication but no specific permissions
func (h *APIHandlers) ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetPrincipalFromContext(r.Context())
	if !ok {
		writeJSONResponse(w, http.StatusUnauthorized, Response{
			Success: false,
			Error:   "Principal not found",
			Code:    "NO_PRINCIPAL",
		})
		return
	}

	claims, _ := middleware.GetClaimsFromContext(r.Context())

	userInfo := UserInfo{
		UserID:       principal.ID,
		Email:        claims.Email,
		Role:         claims.Role,
		Subscription: claims.Subscription,
		Features:     claims.Features,
		Attributes:   claims.Attributes,
	}

	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"message": "Access granted to protected endpoint",
			"user":    userInfo,
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// GetUserProfileHandler returns the authenticated user's profile
func (h *APIHandlers) GetUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetPrincipalFromContext(r.Context())
	if !ok {
		writeJSONResponse(w, http.StatusUnauthorized, Response{
			Success: false,
			Error:   "Principal not found",
			Code:    "NO_PRINCIPAL",
		})
		return
	}

	// Get user's entitlements
	entitlements, err := h.entitlementManager.ListEntitlements(r.Context(), principal)
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Failed to get entitlements",
			Code:    "ENTITLEMENT_ERROR",
		})
		return
	}

	// Get user's roles
	roles, err := h.entitlementManager.GetRoles(r.Context(), principal.ID)
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Failed to get roles",
			Code:    "ROLE_ERROR",
		})
		return
	}

	// Get subscription tier
	subscriptionTier, err := h.entitlementManager.GetSubscriptionTier(r.Context(), principal.ID)
	if err != nil {
		subscriptionTier = "none"
	}

	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"principal":    principal,
			"entitlements": entitlements,
			"roles":        roles,
			"subscription": subscriptionTier,
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// Feature-gated Endpoints

// AdvancedAnalyticsHandler requires the advanced_analytics feature
func (h *APIHandlers) AdvancedAnalyticsHandler(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.GetPrincipalFromContext(r.Context())

	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"message": "Advanced analytics data",
			"user_id": principal.ID,
			"analytics": map[string]interface{}{
				"page_views":      12345,
				"unique_users":    987,
				"conversion_rate": 3.45,
				"revenue":         "$12,345.67",
			},
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// APIAccessHandler requires the api_access feature
func (h *APIHandlers) APIAccessHandler(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.GetPrincipalFromContext(r.Context())

	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"message": "API access granted",
			"user_id": principal.ID,
			"api_info": map[string]interface{}{
				"rate_limit":        "1000 requests/hour",
				"allowed_endpoints": []string{"/api/data", "/api/export", "/api/import"},
				"api_key":           "api_key_" + principal.ID,
			},
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// Subscription-tier Restricted Endpoints

// PremiumFeaturesHandler requires premium subscription or higher
func (h *APIHandlers) PremiumFeaturesHandler(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.GetPrincipalFromContext(r.Context())

	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"message": "Premium features access",
			"user_id": principal.ID,
			"features": []string{
				"Priority Support",
				"Advanced Reporting",
				"Custom Integrations",
				"Extended Storage",
			},
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// EnterpriseFeaturesHandler requires enterprise subscription
func (h *APIHandlers) EnterpriseFeaturesHandler(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.GetPrincipalFromContext(r.Context())

	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"message": "Enterprise features access",
			"user_id": principal.ID,
			"features": []string{
				"SSO Integration",
				"Advanced Security",
				"Dedicated Support",
				"Custom SLA",
				"White-label Options",
			},
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// Role-based Access Endpoints

// AdminDashboardHandler requires admin role
func (h *APIHandlers) AdminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.GetPrincipalFromContext(r.Context())

	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"message":  "Admin dashboard access",
			"admin_id": principal.ID,
			"dashboard": map[string]interface{}{
				"total_users":     1234,
				"active_sessions": 567,
				"system_health":   "Good",
				"revenue_today":   "$5,678.90",
			},
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// SetupRoutes configures all API routes
func (h *APIHandlers) SetupRoutes(router *mux.Router, authMiddleware *middleware.AuthMiddleware) {
	// Public endpoints (no authentication required)
	router.HandleFunc("/health", h.HealthHandler).Methods("GET")
	router.HandleFunc("/api/public", h.PublicInfoHandler).Methods("GET")
	router.HandleFunc("/api/tokens", h.GetTestTokensHandler).Methods("GET")

	// Protected endpoints (require authentication)
	protected := router.PathPrefix("/api").Subrouter()
	protected.Use(authMiddleware.RequireAuth)

	protected.HandleFunc("/protected", h.ProtectedHandler).Methods("GET")
	protected.HandleFunc("/profile", h.GetUserProfileHandler).Methods("GET")

	// Feature-gated endpoints
	featureRoutes := protected.PathPrefix("/features").Subrouter()
	featureRoutes.Handle("/analytics",
		authMiddleware.RequireFeature("advanced_analytics")(
			http.HandlerFunc(h.AdvancedAnalyticsHandler))).Methods("GET")

	featureRoutes.Handle("/api-access",
		authMiddleware.RequireFeature("api_access")(
			http.HandlerFunc(h.APIAccessHandler))).Methods("GET")

	// Subscription-tier restricted endpoints
	subscriptionRoutes := protected.PathPrefix("/subscription").Subrouter()
	subscriptionRoutes.Handle("/premium",
		authMiddleware.RequireSubscription("premium")(
			http.HandlerFunc(h.PremiumFeaturesHandler))).Methods("GET")

	subscriptionRoutes.Handle("/enterprise",
		authMiddleware.RequireSubscription("enterprise")(
			http.HandlerFunc(h.EnterpriseFeaturesHandler))).Methods("GET")

	// Role-based access endpoints
	adminRoutes := protected.PathPrefix("/admin").Subrouter()
	adminRoutes.Handle("/dashboard",
		authMiddleware.RequireRole("admin")(
			http.HandlerFunc(h.AdminDashboardHandler))).Methods("GET")
}
