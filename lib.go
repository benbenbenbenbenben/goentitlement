package goentitlement

import "time"

// This file provides the main public API entry points for the goentitlement library.
// The core implementation is in manager.go, types.go, and store.go

// Re-export the main factory functions for easy access

// NewManager creates a new EntitlementManager with default in-memory storage
func NewEntitlementManager(opts ...ManagerOption) EntitlementManager {
	return NewManager(opts...)
}

// NewEntitlementManagerWithStore creates a manager with a custom store
func NewEntitlementManagerWithStore(store EntitlementStore, opts ...ManagerOption) EntitlementManager {
	return NewManagerWithStore(store, opts...)
}

// Factory functions for stores

// NewInMemoryEntitlementStore creates a new in-memory store
func NewInMemoryEntitlementStore() EntitlementStore {
	return NewInMemoryStore()
}

func NewFileEntitlementStore(baseDir string) (EntitlementStore, error) {
	return NewFileStore(baseDir)
}

// Utility functions for creating entities

// NewPrincipal creates a new Principal with current timestamps
func NewPrincipal(id string, principalType PrincipalType) Principal {
	now := time.Now()
	return Principal{
		ID:         id,
		Type:       principalType,
		Attributes: make(map[string]interface{}),
		Groups:     []string{},
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// NewResource creates a new Resource with current timestamps
func NewResource(id string, resourceType ResourceType) Resource {
	now := time.Now()
	return Resource{
		ID:         id,
		Type:       resourceType,
		Attributes: make(map[string]interface{}),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// NewEntitlement creates a new Entitlement with current timestamps
func NewEntitlement(principal Principal, entitlementType EntitlementType, action string) Entitlement {
	now := time.Now()
	return Entitlement{
		Type:       entitlementType,
		Principal:  principal,
		Action:     action,
		Conditions: make(map[string]interface{}),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}
