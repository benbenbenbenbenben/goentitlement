package goentitlement

import (
	"context"
	"testing"
	"time"
)

func TestBasicPermissionCheck(t *testing.T) {
	// Create test entities
	user := NewPrincipal("user123", PrincipalTypeUser)
	user.Attributes["department"] = "engineering"

	document := NewResource("doc456", ResourceTypeDocument)
	document.Attributes["classification"] = "internal"

	ctx := context.Background()

	// Save entities to store
	store := NewInMemoryEntitlementStore()
	manager := NewEntitlementManagerWithStore(store)

	err := store.SavePrincipal(ctx, user)
	if err != nil {
		t.Fatalf("Failed to save principal: %v", err)
	}

	err = store.SaveResource(ctx, document)
	if err != nil {
		t.Fatalf("Failed to save resource: %v", err)
	}

	// Grant permission entitlement
	entitlement := NewEntitlement(user, EntitlementTypePermission, "read")
	entitlement.Resource = &document

	err = manager.GrantEntitlement(ctx, entitlement)
	if err != nil {
		t.Fatalf("Failed to grant entitlement: %v", err)
	}

	// Check permission
	allowed, err := manager.CheckPermission(ctx, user, "read", document)
	if err != nil {
		t.Fatalf("CheckPermission returned error: %v", err)
	}

	if !allowed {
		t.Errorf("CheckPermission = %v, want true", allowed)
	}

	// Test denied permission
	allowed, err = manager.CheckPermission(ctx, user, "delete", document)
	if err != nil {
		t.Fatalf("CheckPermission returned error: %v", err)
	}

	if allowed {
		t.Errorf("CheckPermission = %v, want false for unauthorized action", allowed)
	}
}

func TestFeatureFlags(t *testing.T) {
	store := NewInMemoryEntitlementStore()
	manager := NewEntitlementManagerWithStore(store)
	ctx := context.Background()

	user := NewPrincipal("user123", PrincipalTypeUser)

	// Save the principal first
	err := store.SavePrincipal(ctx, user)
	if err != nil {
		t.Fatalf("Failed to save principal: %v", err)
	}

	// Enable a feature
	err = manager.EnableFeature(ctx, user.ID, "premium_analytics", map[string]interface{}{
		"trial_expires": time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("Failed to enable feature: %v", err)
	}

	// Check if user has feature
	hasFeature, err := manager.HasFeature(ctx, user, "premium_analytics")
	if err != nil {
		t.Fatalf("HasFeature returned error: %v", err)
	}

	if !hasFeature {
		t.Errorf("HasFeature = %v, want true", hasFeature)
	}

	// Check feature that doesn't exist
	hasFeature, err = manager.HasFeature(ctx, user, "nonexistent_feature")
	if err != nil {
		t.Fatalf("HasFeature returned error: %v", err)
	}

	if hasFeature {
		t.Errorf("HasFeature = %v, want false for nonexistent feature", hasFeature)
	}

	// Disable the feature
	err = manager.DisableFeature(ctx, user.ID, "premium_analytics")
	if err != nil {
		t.Fatalf("Failed to disable feature: %v", err)
	}

	// Check if feature is disabled
	hasFeature, err = manager.HasFeature(ctx, user, "premium_analytics")
	if err != nil {
		t.Fatalf("HasFeature returned error: %v", err)
	}

	if hasFeature {
		t.Errorf("HasFeature = %v, want false after disabling", hasFeature)
	}
}

func TestRBAC(t *testing.T) {
	store := NewInMemoryEntitlementStore()
	manager := NewEntitlementManagerWithStore(store)
	ctx := context.Background()

	user := NewPrincipal("user123", PrincipalTypeUser)

	// Save the principal first
	err := store.SavePrincipal(ctx, user)
	if err != nil {
		t.Fatalf("Failed to save principal: %v", err)
	}

	// Assign role
	err = manager.AssignRole(ctx, user.ID, "admin")
	if err != nil {
		t.Fatalf("Failed to assign role: %v", err)
	}

	// Check if user has role
	hasRole, err := manager.HasRole(ctx, user, "admin")
	if err != nil {
		t.Fatalf("HasRole returned error: %v", err)
	}

	if !hasRole {
		t.Errorf("HasRole = %v, want true", hasRole)
	}

	// Get all roles
	roles, err := manager.GetRoles(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetRoles returned error: %v", err)
	}

	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("GetRoles = %v, want [admin]", roles)
	}

	// Remove role
	err = manager.RemoveRole(ctx, user.ID, "admin")
	if err != nil {
		t.Fatalf("Failed to remove role: %v", err)
	}

	// Check if role is removed
	hasRole, err = manager.HasRole(ctx, user, "admin")
	if err != nil {
		t.Fatalf("HasRole returned error: %v", err)
	}

	if hasRole {
		t.Errorf("HasRole = %v, want false after removing role", hasRole)
	}
}

func TestSubscriptionManagement(t *testing.T) {
	store := NewInMemoryEntitlementStore()
	manager := NewEntitlementManagerWithStore(store)
	ctx := context.Background()

	user := NewPrincipal("user123", PrincipalTypeUser)
	expiryDate := time.Now().Add(365 * 24 * time.Hour)

	// Save the principal first
	err := store.SavePrincipal(ctx, user)
	if err != nil {
		t.Fatalf("Failed to save principal: %v", err)
	}

	// Set subscription
	err = manager.SetSubscription(ctx, user.ID, "premium", &expiryDate)
	if err != nil {
		t.Fatalf("Failed to set subscription: %v", err)
	}

	// Check subscription tier
	tier, err := manager.GetSubscriptionTier(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetSubscriptionTier returned error: %v", err)
	}

	if tier != "premium" {
		t.Errorf("GetSubscriptionTier = %v, want premium", tier)
	}

	// Check if user has subscription
	hasSubscription, err := manager.HasSubscription(ctx, user, "premium")
	if err != nil {
		t.Fatalf("HasSubscription returned error: %v", err)
	}

	if !hasSubscription {
		t.Errorf("HasSubscription = %v, want true", hasSubscription)
	}

	// Check subscription that user doesn't have
	hasSubscription, err = manager.HasSubscription(ctx, user, "enterprise")
	if err != nil {
		t.Fatalf("HasSubscription returned error: %v", err)
	}

	if hasSubscription {
		t.Errorf("HasSubscription = %v, want false for unassigned subscription", hasSubscription)
	}
}

func TestBatchOperations(t *testing.T) {
	manager := NewEntitlementManager()
	ctx := context.Background()

	user1 := NewPrincipal("user1", PrincipalTypeUser)
	user2 := NewPrincipal("user2", PrincipalTypeUser)
	doc1 := NewResource("doc1", ResourceTypeDocument)
	doc2 := NewResource("doc2", ResourceTypeDocument)

	// Test batch entitlement granting
	entitlements := []Entitlement{
		NewEntitlement(user1, EntitlementTypePermission, "read"),
		NewEntitlement(user2, EntitlementTypePermission, "write"),
	}
	entitlements[0].Resource = &doc1
	entitlements[1].Resource = &doc2

	err := manager.GrantMultipleEntitlements(ctx, entitlements)
	if err != nil {
		t.Fatalf("Failed to grant multiple entitlements: %v", err)
	}

	// Test batch authorization checks
	requests := []AuthorizationRequest{
		{Principal: user1, Action: "read", Resource: doc1},
		{Principal: user2, Action: "write", Resource: doc2},
		{Principal: user1, Action: "delete", Resource: doc1}, // Should be denied
	}

	results, err := manager.CheckMultiplePermissions(ctx, requests)
	if err != nil {
		t.Fatalf("CheckMultiplePermissions returned error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	// First two should be allowed, third should be denied
	if !results[0].Allowed {
		t.Errorf("First permission should be allowed")
	}
	if !results[1].Allowed {
		t.Errorf("Second permission should be allowed")
	}
	if results[2].Allowed {
		t.Errorf("Third permission should be denied")
	}
}
