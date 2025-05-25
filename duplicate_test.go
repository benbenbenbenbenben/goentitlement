package goentitlement

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDuplicateEntitlements verifies that duplicate entitlement handling works correctly.
//
// This test demonstrates and validates the duplicate entitlement detection and
// handling logic across both InMemoryStore and FileStore implementations.
// It ensures that when logically duplicate entitlements are saved, they
// update existing entitlements rather than creating new ones.
//
// The test covers:
//   - Saving an initial entitlement
//   - Attempting to save a logically duplicate entitlement
//   - Verifying that only one entitlement exists (no duplicate created)
//   - Verifying that the existing entitlement was updated with new metadata
//
// Logical duplicates are defined as entitlements with the same:
//   - Principal ID
//   - Resource ID and Type (if resource is present)
//   - Action
//   - Entitlement Type
func TestDuplicateEntitlements(t *testing.T) {
	tests := []struct {
		name     string
		storeGen func() EntitlementStore
		cleanup  func()
	}{
		{
			name: "InMemoryStore",
			storeGen: func() EntitlementStore {
				return NewInMemoryStore()
			},
			cleanup: func() {},
		},
		{
			name: "FileStore",
			storeGen: func() EntitlementStore {
				tmpDir := filepath.Join(os.TempDir(), "goentitlement_test_"+time.Now().Format("20060102_150405"))
				store, err := NewFileStore(tmpDir)
				if err != nil {
					t.Fatalf("Failed to create FileStore: %v", err)
				}
				return store
			},
			cleanup: func() {
				tmpDir := filepath.Join(os.TempDir(), "goentitlement_test_*")
				matches, _ := filepath.Glob(tmpDir)
				for _, match := range matches {
					os.RemoveAll(match)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer tt.cleanup()

			t.Run("GrantEntitlement_CreatesDuplicates", func(t *testing.T) {
				testGrantEntitlementDuplicates(t, tt.storeGen())
			})

			t.Run("EnableFeature_CreatesDuplicates", func(t *testing.T) {
				testEnableFeatureDuplicates(t, tt.storeGen())
			})

			t.Run("AssignRole_CreatesDuplicates", func(t *testing.T) {
				testAssignRoleDuplicates(t, tt.storeGen())
			})

			t.Run("GrantMultipleEntitlements_CreatesDuplicates", func(t *testing.T) {
				testGrantMultipleEntitlementsDuplicates(t, tt.storeGen())
			})

			t.Run("GrantMultipleEntitlements_WithDuplicatesInSlice", func(t *testing.T) {
				testGrantMultipleEntitlementsWithDuplicatesInSlice(t, tt.storeGen())
			})
		})
	}
}

// testGrantEntitlementDuplicates demonstrates that multiple calls to GrantEntitlement
// with identical Principal+Resource+Action combinations create duplicate entitlements
func testGrantEntitlementDuplicates(t *testing.T, store EntitlementStore) {
	ctx := context.Background()
	manager := NewManagerWithStore(store)

	// Create test entities
	principal := createTestPrincipal(t, store, "user123")
	resource := createTestResource(t, store, "doc456", ResourceTypeDocument)

	// Create identical entitlements (same principal, resource, action)
	entitlement1 := NewEntitlement(principal, EntitlementTypePermission, "read")
	entitlement1.Resource = &resource

	entitlement2 := NewEntitlement(principal, EntitlementTypePermission, "read")
	entitlement2.Resource = &resource

	// Grant the same entitlement twice
	err := manager.GrantEntitlement(ctx, entitlement1)
	if err != nil {
		t.Fatalf("Failed to grant first entitlement: %v", err)
	}

	err = manager.GrantEntitlement(ctx, entitlement2)
	if err != nil {
		t.Fatalf("Failed to grant second entitlement: %v", err)
	}

	// Verify that duplicates were created
	entitlements, err := store.GetEntitlements(ctx, principal.ID)
	if err != nil {
		t.Fatalf("Failed to get entitlements: %v", err)
	}

	// Count entitlements with the same logical content
	duplicateCount := countLogicalDuplicates(entitlements, EntitlementTypePermission, "read", &resource)

	// FIXED: Should now be 1 instead of creating duplicates
	if duplicateCount != 1 {
		t.Errorf("Expected 1 entitlement (duplicates should be updated), got %d", duplicateCount)
	}

	// Verify total entitlements is also 1
	if len(entitlements) != 1 {
		t.Errorf("Expected 1 total entitlement, got %d", len(entitlements))
	}

	t.Logf("FIX CONFIRMED: GrantEntitlement correctly prevented duplicates, result: %d logical entitlements for Principal=%s, Resource=%s, Action=read",
		duplicateCount, principal.ID, resource.ID)
}

// testEnableFeatureDuplicates demonstrates that multiple calls to EnableFeature
// for the same principal+feature create duplicate entitlements
func testEnableFeatureDuplicates(t *testing.T, store EntitlementStore) {
	ctx := context.Background()
	manager := NewManagerWithStore(store)

	// Create test principal
	principal := createTestPrincipal(t, store, "user456")

	featureName := "premium_analytics"
	conditions := map[string]interface{}{
		"trial_expires": time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
	}

	// Enable the same feature multiple times
	err := manager.EnableFeature(ctx, principal.ID, featureName, conditions)
	if err != nil {
		t.Fatalf("Failed to enable feature first time: %v", err)
	}

	err = manager.EnableFeature(ctx, principal.ID, featureName, conditions)
	if err != nil {
		t.Fatalf("Failed to enable feature second time: %v", err)
	}

	err = manager.EnableFeature(ctx, principal.ID, featureName, conditions)
	if err != nil {
		t.Fatalf("Failed to enable feature third time: %v", err)
	}

	// Verify that duplicates were created
	entitlements, err := store.GetEntitlements(ctx, principal.ID)
	if err != nil {
		t.Fatalf("Failed to get entitlements: %v", err)
	}

	// Count feature flag entitlements for the same feature
	featureResource := &Resource{ID: featureName, Type: ResourceTypeFeature}
	duplicateCount := countLogicalDuplicates(entitlements, EntitlementTypeFeatureFlag, "use", featureResource)

	// FIXED: Should now be 1 instead of creating duplicates
	if duplicateCount != 1 {
		t.Errorf("Expected 1 feature entitlement (duplicates should be updated), got %d", duplicateCount)
	}

	// Verify total entitlements is also 1
	if len(entitlements) != 1 {
		t.Errorf("Expected 1 total entitlement, got %d", len(entitlements))
	}

	t.Logf("FIX CONFIRMED: EnableFeature correctly prevented duplicates, result: %d logical entitlements for Principal=%s, Feature=%s",
		duplicateCount, principal.ID, featureName)
}

// testAssignRoleDuplicates demonstrates that multiple calls to AssignRole
// for the same principal+role create duplicate entitlements
func testAssignRoleDuplicates(t *testing.T, store EntitlementStore) {
	ctx := context.Background()
	manager := NewManagerWithStore(store)

	// Create test principal
	principal := createTestPrincipal(t, store, "user789")

	roleName := "admin"

	// Assign the same role multiple times
	err := manager.AssignRole(ctx, principal.ID, roleName)
	if err != nil {
		t.Fatalf("Failed to assign role first time: %v", err)
	}

	err = manager.AssignRole(ctx, principal.ID, roleName)
	if err != nil {
		t.Fatalf("Failed to assign role second time: %v", err)
	}

	// Verify that duplicates were created
	entitlements, err := store.GetEntitlements(ctx, principal.ID)
	if err != nil {
		t.Fatalf("Failed to get entitlements: %v", err)
	}

	// Count role entitlements for the same role
	duplicateCount := countLogicalDuplicates(entitlements, EntitlementTypeRole, roleName, nil)

	// FIXED: Should now be 1 instead of creating duplicates
	if duplicateCount != 1 {
		t.Errorf("Expected 1 role entitlement (duplicates should be updated), got %d", duplicateCount)
	}

	// Verify total entitlements is also 1
	if len(entitlements) != 1 {
		t.Errorf("Expected 1 total entitlement, got %d", len(entitlements))
	}

	t.Logf("FIX CONFIRMED: AssignRole correctly prevented duplicates, result: %d logical entitlements for Principal=%s, Role=%s",
		duplicateCount, principal.ID, roleName)
}

// testGrantMultipleEntitlementsDuplicates demonstrates that calling GrantMultipleEntitlements
// multiple times with fresh entitlements (but same logical content) creates duplicates
func testGrantMultipleEntitlementsDuplicates(t *testing.T, store EntitlementStore) {
	ctx := context.Background()
	manager := NewManagerWithStore(store)

	// Create test entities
	principal := createTestPrincipal(t, store, "user999")
	resource1 := createTestResource(t, store, "doc1", ResourceTypeDocument)
	resource2 := createTestResource(t, store, "doc2", ResourceTypeDocument)

	// Create first batch of entitlements
	entitlements1 := []Entitlement{
		createEntitlementWithResource(principal, EntitlementTypePermission, "read", &resource1),
		createEntitlementWithResource(principal, EntitlementTypePermission, "write", &resource2),
	}

	// Create second batch with same logical content but fresh entitlement objects
	entitlements2 := []Entitlement{
		createEntitlementWithResource(principal, EntitlementTypePermission, "read", &resource1),
		createEntitlementWithResource(principal, EntitlementTypePermission, "write", &resource2),
	}

	// Grant the first batch
	err := manager.GrantMultipleEntitlements(ctx, entitlements1)
	if err != nil {
		t.Fatalf("Failed to grant multiple entitlements first time: %v", err)
	}

	// Grant the second batch (with same logical content)
	err = manager.GrantMultipleEntitlements(ctx, entitlements2)
	if err != nil {
		t.Fatalf("Failed to grant multiple entitlements second time: %v", err)
	}

	// Verify that duplicates were created
	allEntitlements, err := store.GetEntitlements(ctx, principal.ID)
	if err != nil {
		t.Fatalf("Failed to get entitlements: %v", err)
	}

	// Count duplicates for each entitlement
	readDuplicates := countLogicalDuplicates(allEntitlements, EntitlementTypePermission, "read", &resource1)
	writeDuplicates := countLogicalDuplicates(allEntitlements, EntitlementTypePermission, "write", &resource2)

	// FIXED: Each should be 1 instead of creating duplicates
	if readDuplicates != 1 {
		t.Errorf("Expected 1 read entitlement (duplicates should be updated), got %d", readDuplicates)
	}
	if writeDuplicates != 1 {
		t.Errorf("Expected 1 write entitlement (duplicates should be updated), got %d", writeDuplicates)
	}

	// Verify total entitlements is 2 (one for each unique logical entitlement)
	if len(allEntitlements) != 2 {
		t.Errorf("Expected 2 total entitlements, got %d", len(allEntitlements))
	}

	t.Logf("FIX CONFIRMED: GrantMultipleEntitlements correctly prevented duplicates, result: %d read and %d write entitlements for Principal=%s",
		readDuplicates, writeDuplicates, principal.ID)
}

// testGrantMultipleEntitlementsWithDuplicatesInSlice demonstrates that calling
// GrantMultipleEntitlements with duplicate entitlements in the same slice creates duplicates
func testGrantMultipleEntitlementsWithDuplicatesInSlice(t *testing.T, store EntitlementStore) {
	ctx := context.Background()
	manager := NewManagerWithStore(store)

	// Create test entities
	principal := createTestPrincipal(t, store, "user555")
	resource := createTestResource(t, store, "doc555", ResourceTypeDocument)

	// Create entitlements with intentional duplicates in the same slice
	entitlements := []Entitlement{
		createEntitlementWithResource(principal, EntitlementTypePermission, "read", &resource),
		createEntitlementWithResource(principal, EntitlementTypePermission, "read", &resource), // Duplicate
		createEntitlementWithResource(principal, EntitlementTypePermission, "write", &resource),
		createEntitlementWithResource(principal, EntitlementTypePermission, "read", &resource), // Another duplicate
	}

	// Grant entitlements including duplicates in the same call
	err := manager.GrantMultipleEntitlements(ctx, entitlements)
	if err != nil {
		t.Fatalf("Failed to grant multiple entitlements with duplicates: %v", err)
	}

	// Verify that all duplicates were created
	allEntitlements, err := store.GetEntitlements(ctx, principal.ID)
	if err != nil {
		t.Fatalf("Failed to get entitlements: %v", err)
	}

	// Count duplicates
	readDuplicates := countLogicalDuplicates(allEntitlements, EntitlementTypePermission, "read", &resource)
	writeDuplicates := countLogicalDuplicates(allEntitlements, EntitlementTypePermission, "write", &resource)

	// FIXED: Should be 1 read and 1 write (duplicates within slice are handled)
	if readDuplicates != 1 {
		t.Errorf("Expected 1 read entitlement (duplicates should be updated), got %d", readDuplicates)
	}
	if writeDuplicates != 1 {
		t.Errorf("Expected 1 write entitlement, got %d", writeDuplicates)
	}

	// Verify total entitlements is 2 (one for each unique logical entitlement)
	if len(allEntitlements) != 2 {
		t.Errorf("Expected 2 total entitlements, got %d", len(allEntitlements))
	}

	t.Logf("FIX CONFIRMED: GrantMultipleEntitlements with duplicates in slice correctly handled duplicates, result: %d read and %d write entitlements for Principal=%s",
		readDuplicates, writeDuplicates, principal.ID)
}

// Helper functions

// createTestPrincipal creates and saves a test principal
func createTestPrincipal(t *testing.T, store EntitlementStore, id string) Principal {
	principal := NewPrincipal(id, PrincipalTypeUser)
	principal.Attributes["department"] = "engineering"

	ctx := context.Background()
	err := store.SavePrincipal(ctx, principal)
	if err != nil {
		t.Fatalf("Failed to save principal: %v", err)
	}

	return principal
}

// createTestResource creates and saves a test resource
func createTestResource(t *testing.T, store EntitlementStore, id string, resourceType ResourceType) Resource {
	resource := NewResource(id, resourceType)
	resource.Attributes["classification"] = "internal"

	ctx := context.Background()
	err := store.SaveResource(ctx, resource)
	if err != nil {
		t.Fatalf("Failed to save resource: %v", err)
	}

	return resource
}

// createEntitlementWithResource creates an entitlement with the specified resource
func createEntitlementWithResource(principal Principal, entType EntitlementType, action string, resource *Resource) Entitlement {
	entitlement := NewEntitlement(principal, entType, action)
	entitlement.Resource = resource
	return entitlement
}

// countLogicalDuplicates counts how many entitlements match the logical combination
// of type, action, and resource (ignoring ID differences)
func countLogicalDuplicates(entitlements []Entitlement, entType EntitlementType, action string, resource *Resource) int {
	count := 0
	for _, ent := range entitlements {
		if ent.Type == entType && ent.Action == action {
			// Check resource match
			if resource == nil && ent.Resource == nil {
				count++
			} else if resource != nil && ent.Resource != nil &&
				ent.Resource.ID == resource.ID && ent.Resource.Type == resource.Type {
				count++
			}
		}
	}
	return count
}

// TestDuplicateEntitlementsImpactOnAuthorization demonstrates how duplicate entitlements
// might impact authorization decisions (though the current simple implementation may not show this)
func TestDuplicateEntitlementsImpactOnAuthorization(t *testing.T) {
	stores := []struct {
		name     string
		storeGen func() EntitlementStore
	}{
		{
			name: "InMemoryStore",
			storeGen: func() EntitlementStore {
				return NewInMemoryStore()
			},
		},
		{
			name: "FileStore",
			storeGen: func() EntitlementStore {
				tmpDir := filepath.Join(os.TempDir(), "goentitlement_auth_test_"+time.Now().Format("20060102_150405"))
				store, err := NewFileStore(tmpDir)
				if err != nil {
					t.Fatalf("Failed to create FileStore: %v", err)
				}
				return store
			},
		},
	}

	for _, tt := range stores {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := tt.storeGen()
			manager := NewManagerWithStore(store)

			// Create test entities
			principal := createTestPrincipal(t, store, "authuser")
			resource := createTestResource(t, store, "authdoc", ResourceTypeDocument)

			// Create multiple identical entitlements (demonstrating the bug)
			for i := 0; i < 5; i++ {
				entitlement := NewEntitlement(principal, EntitlementTypePermission, "read")
				entitlement.Resource = &resource

				err := manager.GrantEntitlement(ctx, entitlement)
				if err != nil {
					t.Fatalf("Failed to grant entitlement %d: %v", i, err)
				}
			}

			// Check that we have duplicates
			entitlements, err := store.GetEntitlements(ctx, principal.ID)
			if err != nil {
				t.Fatalf("Failed to get entitlements: %v", err)
			}

			duplicateCount := countLogicalDuplicates(entitlements, EntitlementTypePermission, "read", &resource)
			if duplicateCount != 1 {
				t.Errorf("Expected 1 entitlement (duplicates should be updated), got %d", duplicateCount)
			}

			// Verify total entitlements is also 1
			if len(entitlements) != 1 {
				t.Errorf("Expected 1 total entitlement, got %d", len(entitlements))
			}

			// Check authorization (should still work)
			allowed, err := manager.CheckPermission(ctx, principal, "read", resource)
			if err != nil {
				t.Fatalf("CheckPermission failed: %v", err)
			}

			if !allowed {
				t.Errorf("Authorization should be allowed")
			}

			t.Logf("PERFORMANCE IMPROVEMENT: Authorization check processed %d entitlement (no duplicates) instead of 5", duplicateCount)

			// Clean up for FileStore
			if tt.name == "FileStore" {
				tmpDir := filepath.Join(os.TempDir(), "goentitlement_auth_test_*")
				matches, _ := filepath.Glob(tmpDir)
				for _, match := range matches {
					os.RemoveAll(match)
				}
			}
		})
	}
}
