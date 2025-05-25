package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/benbenbenbenbenben/goentitlement"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/auth"
)

// ContextKey type for context keys to avoid collisions
type ContextKey string

const (
	// PrincipalContextKey is the key for storing the principal in request context
	PrincipalContextKey ContextKey = "principal"
	// ClaimsContextKey is the key for storing JWT claims in request context
	ClaimsContextKey ContextKey = "claims"
)

// AuthMiddleware handles JWT authentication and authorization
type AuthMiddleware struct {
	jwtManager         *auth.JWTManager
	entitlementManager goentitlement.EntitlementManager
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(jwtManager *auth.JWTManager, entitlementManager goentitlement.EntitlementManager) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager:         jwtManager,
		entitlementManager: entitlementManager,
	}
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeErrorResponse writes a JSON error response
func writeErrorResponse(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error:   http.StatusText(statusCode),
		Code:    code,
		Message: message,
	}

	json.NewEncoder(w).Encode(response)
}

// RequireAuth middleware validates JWT tokens and extracts principal
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeErrorResponse(w, http.StatusUnauthorized, "MISSING_TOKEN", "Authorization header is required")
			return
		}

		// Parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeErrorResponse(w, http.StatusUnauthorized, "INVALID_TOKEN_FORMAT", "Authorization header must be 'Bearer <token>'")
			return
		}

		tokenString := parts[1]

		// Validate JWT token
		claims, err := m.jwtManager.ValidateToken(tokenString)
		if err != nil {
			writeErrorResponse(w, http.StatusUnauthorized, "INVALID_TOKEN", err.Error())
			return
		}

		// Convert claims to principal
		principal := auth.ClaimsToPrincipal(claims)

		// Store principal and claims in request context
		ctx := context.WithValue(r.Context(), PrincipalContextKey, principal)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)

		// Continue to next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireFeature middleware checks if the authenticated user has a specific feature enabled
func (m *AuthMiddleware) RequireFeature(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get principal from context
			principal, ok := r.Context().Value(PrincipalContextKey).(goentitlement.Principal)
			if !ok {
				writeErrorResponse(w, http.StatusUnauthorized, "NO_PRINCIPAL", "Principal not found in context")
				return
			}

			// Check if user has the required feature
			hasFeature, err := m.entitlementManager.HasFeature(r.Context(), principal, feature)
			if err != nil {
				writeErrorResponse(w, http.StatusInternalServerError, "FEATURE_CHECK_ERROR", err.Error())
				return
			}

			if !hasFeature {
				writeErrorResponse(w, http.StatusForbidden, "FEATURE_NOT_ENABLED", "Feature '"+feature+"' is not enabled for this user")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireSubscription middleware checks if the authenticated user has a specific subscription tier
func (m *AuthMiddleware) RequireSubscription(tier string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get principal from context
			principal, ok := r.Context().Value(PrincipalContextKey).(goentitlement.Principal)
			if !ok {
				writeErrorResponse(w, http.StatusUnauthorized, "NO_PRINCIPAL", "Principal not found in context")
				return
			}

			// Check if user has the required subscription
			hasSubscription, err := m.entitlementManager.HasSubscription(r.Context(), principal, tier)
			if err != nil {
				writeErrorResponse(w, http.StatusInternalServerError, "SUBSCRIPTION_CHECK_ERROR", err.Error())
				return
			}

			if !hasSubscription {
				writeErrorResponse(w, http.StatusForbidden, "INSUFFICIENT_SUBSCRIPTION", "Subscription tier '"+tier+"' is required")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole middleware checks if the authenticated user has a specific role
func (m *AuthMiddleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get principal from context
			principal, ok := r.Context().Value(PrincipalContextKey).(goentitlement.Principal)
			if !ok {
				writeErrorResponse(w, http.StatusUnauthorized, "NO_PRINCIPAL", "Principal not found in context")
				return
			}

			// Check if user has the required role
			hasRole, err := m.entitlementManager.HasRole(r.Context(), principal, role)
			if err != nil {
				writeErrorResponse(w, http.StatusInternalServerError, "ROLE_CHECK_ERROR", err.Error())
				return
			}

			if !hasRole {
				writeErrorResponse(w, http.StatusForbidden, "INSUFFICIENT_ROLE", "Role '"+role+"' is required")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission middleware checks if the authenticated user has a specific permission for a resource
func (m *AuthMiddleware) RequirePermission(action string, resourceType goentitlement.ResourceType, resourceID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get principal from context
			principal, ok := r.Context().Value(PrincipalContextKey).(goentitlement.Principal)
			if !ok {
				writeErrorResponse(w, http.StatusUnauthorized, "NO_PRINCIPAL", "Principal not found in context")
				return
			}

			// Create resource object
			resource := goentitlement.Resource{
				ID:   resourceID,
				Type: resourceType,
			}

			// Check permission
			allowed, err := m.entitlementManager.CheckPermission(r.Context(), principal, action, resource)
			if err != nil {
				writeErrorResponse(w, http.StatusInternalServerError, "PERMISSION_CHECK_ERROR", err.Error())
				return
			}

			if !allowed {
				writeErrorResponse(w, http.StatusForbidden, "PERMISSION_DENIED", "Permission denied for action '"+action+"' on resource '"+resourceID+"'")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// OptionalAuth middleware extracts principal if a valid token is provided, but doesn't require it
func (m *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// No token provided, continue without principal
			next.ServeHTTP(w, r)
			return
		}

		// Parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			// Invalid token format, continue without principal
			next.ServeHTTP(w, r)
			return
		}

		tokenString := parts[1]

		// Validate JWT token
		claims, err := m.jwtManager.ValidateToken(tokenString)
		if err != nil {
			// Invalid token, continue without principal
			next.ServeHTTP(w, r)
			return
		}

		// Convert claims to principal
		principal := auth.ClaimsToPrincipal(claims)

		// Store principal and claims in request context
		ctx := context.WithValue(r.Context(), PrincipalContextKey, principal)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)

		// Continue to next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetPrincipalFromContext extracts the principal from the request context
func GetPrincipalFromContext(ctx context.Context) (goentitlement.Principal, bool) {
	principal, ok := ctx.Value(PrincipalContextKey).(goentitlement.Principal)
	return principal, ok
}

// GetClaimsFromContext extracts the JWT claims from the request context
func GetClaimsFromContext(ctx context.Context) (*auth.JWTClaims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*auth.JWTClaims)
	return claims, ok
}

// CORS middleware for handling cross-origin requests
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Logging middleware for request logging
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple request logging - in production you'd want structured logging
		next.ServeHTTP(w, r)
	})
}
