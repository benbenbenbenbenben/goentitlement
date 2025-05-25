// Package middleware provides HTTP middleware for the SaaS API example.
//
// This package demonstrates how to integrate JWT authentication and
// goentitlement authorization into HTTP middleware, providing reusable
// components for protecting API endpoints.
//
// The middleware handles:
//   - JWT token extraction and validation
//   - Principal creation from JWT claims
//   - Context injection for downstream handlers
//   - Standardized error responses for authentication failures
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/benbenbenbenbenben/goentitlement"
	"github.com/benbenbenbenbenben/goentitlement/examples/saas-api/internal/auth"
)

// ContextKey is a custom type for context keys to avoid string collision.
//
// Using a custom type for context keys is a Go best practice that prevents
// accidental key collisions when multiple packages store values in the
// same request context.
type ContextKey string

const (
	// PrincipalContextKey is used to store the authenticated principal in request context
	PrincipalContextKey ContextKey = "principal"
	// ClaimsContextKey is used to store the JWT claims in request context
	ClaimsContextKey ContextKey = "claims"
)

// AuthMiddleware provides JWT authentication and entitlement-based authorization.
//
// This middleware extracts JWT tokens from requests, validates them, converts
// the claims into goentitlement Principal objects, and injects both the
// principal and claims into the request context for use by downstream handlers.
//
// The middleware supports the standard Authorization header format:
//
//	Authorization: Bearer <jwt-token>
type AuthMiddleware struct {
	// jwtManager handles token validation and claims extraction
	jwtManager *auth.JWTManager
	// entitlementManager provides additional authorization capabilities
	entitlementManager goentitlement.EntitlementManager
}

// NewAuthMiddleware creates a new authentication middleware instance.
//
// The middleware requires both a JWT manager for token operations and an
// entitlement manager for authorization decisions.
//
// Example:
//
//	authMiddleware := NewAuthMiddleware(jwtManager, entitlementManager)
//	router.Use(authMiddleware.RequireAuth)
func NewAuthMiddleware(jwtManager *auth.JWTManager, entitlementManager goentitlement.EntitlementManager) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager:         jwtManager,
		entitlementManager: entitlementManager,
	}
}

// ErrorResponse represents a standardized error response format.
//
// This structure provides consistent error formatting for authentication
// and authorization failures across all middleware.
type ErrorResponse struct {
	// Error contains a human-readable error message
	Error string `json:"error"`
	// Code provides a machine-readable error code
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
