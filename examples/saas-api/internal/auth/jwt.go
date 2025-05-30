// Package auth provides JWT-based authentication for the SaaS API example.
//
// This package demonstrates how to integrate JWT tokens with the goentitlement
// library, embedding authorization information directly in the tokens while
// still leveraging the entitlement system for fine-grained access control.
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/benbenbenbenbenben/goentitlement"
	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims represents the custom claims embedded in JWT tokens.
//
// These claims include user identification, role information, subscription
// details, and feature flags. This allows for efficient authorization
// decisions without always requiring database lookups, while still
// maintaining integration with the entitlement system.
//
// Example token payload:
//
//	{
//		"user_id": "user-456",
//		"email": "premium@example.com",
//		"role": "user",
//		"subscription": "premium",
//		"features": ["advanced_analytics"],
//		"attributes": {"department": "engineering"},
//		"iss": "saas-api-example",
//		"exp": 1234567890
//	}
type JWTClaims struct {
	// UserID is the unique identifier for the user
	UserID string `json:"user_id"`
	// Email is the user's email address
	Email string `json:"email"`
	// Role specifies the user's primary role (user, admin, etc.)
	Role string `json:"role"`
	// Subscription indicates the user's subscription tier
	Subscription string `json:"subscription"`
	// Features lists the feature flags enabled for this user
	Features []string `json:"features"`
	// Attributes contains additional user attributes
	Attributes map[string]string `json:"attributes"`
	// RegisteredClaims includes standard JWT claims (iss, exp, etc.)
	jwt.RegisteredClaims
}

// JWTManager handles JWT token creation, validation, and claims extraction.
//
// This manager provides a bridge between HTTP authentication and the
// goentitlement system, converting JWT claims into Principal objects
// and managing token lifecycle.
type JWTManager struct {
	// signingKey is the secret key used for HMAC signing
	signingKey []byte
	// issuer identifies this service in JWT tokens
	issuer string
}

// NewJWTManager creates a new JWT manager with the specified signing key and issuer.
//
// The signing key should be a strong, randomly generated secret that is
// kept secure and consistent across service restarts. The issuer should
// identify your service uniquely.
//
// Example:
//
//	jwtManager := auth.NewJWTManager([]byte("your-secret-key"), "my-api-service")
func NewJWTManager(signingKey []byte, issuer string) *JWTManager {
	return &JWTManager{
		signingKey: signingKey,
		issuer:     issuer,
	}
}

// ValidateToken validates a JWT token and returns the claims
func (j *JWTManager) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.signingKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Check if token is expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, errors.New("token expired")
	}

	return claims, nil
}

// GenerateToken generates a JWT token for testing purposes
func (j *JWTManager) GenerateToken(claims *JWTClaims) (string, error) {
	// Set default claims if not provided
	if claims.RegisteredClaims.IssuedAt == nil {
		claims.RegisteredClaims.IssuedAt = jwt.NewNumericDate(time.Now())
	}
	if claims.RegisteredClaims.ExpiresAt == nil {
		claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	}
	if claims.RegisteredClaims.Issuer == "" {
		claims.RegisteredClaims.Issuer = j.issuer
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.signingKey)
}

// ClaimsToPrincipal converts JWT claims to a goentitlement Principal
func ClaimsToPrincipal(claims *JWTClaims) goentitlement.Principal {
	attributes := make(map[string]interface{})

	// Convert string attributes to interface{} map
	for k, v := range claims.Attributes {
		attributes[k] = v
	}

	// Add standard claims as attributes
	attributes["email"] = claims.Email
	attributes["role"] = claims.Role
	attributes["subscription"] = claims.Subscription

	// Add features as attributes
	if len(claims.Features) > 0 {
		attributes["features"] = claims.Features
	}

	var groups []string
	if claims.Role != "" {
		groups = append(groups, claims.Role)
	}
	if claims.Subscription != "" {
		groups = append(groups, "subscription:"+claims.Subscription)
	}

	return goentitlement.Principal{
		ID:         claims.UserID,
		Type:       goentitlement.PrincipalTypeUser,
		Attributes: attributes,
		Groups:     groups,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

// Test JWT generation functions for different user scenarios

// GenerateTestAdminToken creates a JWT for an admin user
func (j *JWTManager) GenerateTestAdminToken() (string, error) {
	claims := &JWTClaims{
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
	return j.GenerateToken(claims)
}

// GenerateTestPremiumUserToken creates a JWT for a premium user
func (j *JWTManager) GenerateTestPremiumUserToken() (string, error) {
	claims := &JWTClaims{
		UserID:       "user-456",
		Email:        "premium@example.com",
		Role:         "user",
		Subscription: "premium",
		Features:     []string{"advanced_features", "priority_support"},
		Attributes: map[string]string{
			"plan_start": time.Now().Format("2006-01-02"),
		},
	}
	return j.GenerateToken(claims)
}

// GenerateTestBasicUserToken creates a JWT for a basic user
func (j *JWTManager) GenerateTestBasicUserToken() (string, error) {
	claims := &JWTClaims{
		UserID:       "user-789",
		Email:        "basic@example.com",
		Role:         "user",
		Subscription: "basic",
		Features:     []string{"basic_features"},
		Attributes: map[string]string{
			"trial": "false",
		},
	}
	return j.GenerateToken(claims)
}

// GenerateTestTrialUserToken creates a JWT for a trial user
func (j *JWTManager) GenerateTestTrialUserToken() (string, error) {
	claims := &JWTClaims{
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
	return j.GenerateToken(claims)
}

// GenerateTestExpiredToken creates an expired JWT for testing
func (j *JWTManager) GenerateTestExpiredToken() (string, error) {
	claims := &JWTClaims{
		UserID:       "user-expired",
		Email:        "expired@example.com",
		Role:         "user",
		Subscription: "basic",
		Features:     []string{"basic_features"},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired 1 hour ago
			Issuer:    j.issuer,
		},
	}
	return j.GenerateToken(claims)
}
