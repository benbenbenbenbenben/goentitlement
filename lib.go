// Package goentitlement provides a comprehensive entitlement management library for Go applications.
//
// This library offers authorization, feature flag management, subscription handling, and role-based
// access control (RBAC) functionality. It supports both in-memory and file-based storage backends
// and integrates with the Cedar policy engine for advanced authorization scenarios.
//
// Key features:
//   - Simple permission checking and authorization
//   - Feature flag management and evaluation
//   - Subscription tier management with expiration support
//   - Role-based access control (RBAC)
//   - Batch operations for performance
//   - Pluggable storage backends (in-memory, file-based)
//   - Audit logging and metrics collection
//   - Cedar policy integration for complex authorization rules
//
// Basic usage:
//
//	manager := goentitlement.NewEntitlementManager()
//	principal := goentitlement.NewPrincipal("user123", goentitlement.PrincipalTypeUser)
//	resource := goentitlement.NewResource("doc456", goentitlement.ResourceTypeDocument)
//
//	allowed, err := manager.CheckPermission(ctx, principal, "read", resource)
//	if err != nil {
//		log.Fatal(err)
//	}
//	if allowed {
//		// Grant access
//	}
package goentitlement

import "time"

// NewEntitlementManager creates a new EntitlementManager with default in-memory storage.
//
// This is the primary entry point for creating an entitlement manager. The manager
// provides all core functionality including authorization checks, feature flag management,
// subscription handling, and role-based access control.
//
// Example:
//
//	manager := goentitlement.NewEntitlementManager(
//		goentitlement.WithCache(5*time.Minute),
//		goentitlement.WithAuditLogger(myLogger),
//	)
func NewEntitlementManager(opts ...ManagerOption) EntitlementManager {
	return NewManager(opts...)
}

// NewEntitlementManagerWithStore creates an EntitlementManager with a custom storage backend.
//
// Use this function when you need to specify a custom storage implementation, such as
// a file-based store or a database-backed store. The store parameter must implement
// the EntitlementStore interface.
//
// Example:
//
//	store, err := goentitlement.NewFileEntitlementStore("/path/to/data")
//	if err != nil {
//		log.Fatal(err)
//	}
//	manager := goentitlement.NewEntitlementManagerWithStore(store)
func NewEntitlementManagerWithStore(store EntitlementStore, opts ...ManagerOption) EntitlementManager {
	return NewManagerWithStore(store, opts...)
}

// NewInMemoryEntitlementStore creates a new in-memory storage backend.
//
// The in-memory store is suitable for development, testing, or applications
// that don't require persistent storage. All data is lost when the application
// terminates.
//
// This store is thread-safe and provides good performance for read-heavy workloads.
func NewInMemoryEntitlementStore() EntitlementStore {
	return NewInMemoryStore()
}

// NewFileEntitlementStore creates a new file-based storage backend.
//
// The file store persists data as JSON files in the specified base directory.
// It automatically creates the necessary subdirectories for different entity types.
// This store is suitable for applications that need persistence but don't require
// a full database.
//
// The baseDir parameter specifies the root directory where data will be stored.
// Subdirectories will be created for principals, resources, entitlements, and policies.
//
// Example:
//
//	store, err := goentitlement.NewFileEntitlementStore("/var/lib/myapp/entitlements")
//	if err != nil {
//		log.Fatal(err)
//	}
func NewFileEntitlementStore(baseDir string) (EntitlementStore, error) {
	return NewFileStore(baseDir)
}

// NewPrincipal creates a new Principal entity with current timestamps.
//
// A Principal represents an entity that can be granted entitlements, such as
// a user, service account, role, or group. The principal serves as the subject
// in authorization decisions.
//
// The id parameter should be unique within your system. The principalType
// parameter categorizes the principal for organizational and policy purposes.
//
// Example:
//
//	user := goentitlement.NewPrincipal("user123", goentitlement.PrincipalTypeUser)
//	service := goentitlement.NewPrincipal("api-service", goentitlement.PrincipalTypeService)
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

// NewResource creates a new Resource entity with current timestamps.
//
// A Resource represents something that can be accessed or acted upon in your system,
// such as documents, API endpoints, features, or subscription tiers. Resources serve
// as the object in authorization decisions.
//
// The id parameter should be unique within your system for the given resource type.
// The resourceType parameter categorizes the resource for organizational and policy purposes.
//
// Example:
//
//	document := goentitlement.NewResource("doc123", goentitlement.ResourceTypeDocument)
//	apiEndpoint := goentitlement.NewResource("/api/users", goentitlement.ResourceTypeAPI)
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

// NewEntitlement creates a new Entitlement with current timestamps.
//
// An Entitlement grants a specific capability or permission to a principal.
// This is a low-level function for creating entitlements directly. In most cases,
// you should use the higher-level manager methods like GrantEntitlement,
// EnableFeature, AssignRole, or SetSubscription.
//
// The principal parameter specifies who is granted the entitlement.
// The entitlementType parameter categorizes the type of entitlement being granted.
// The action parameter specifies what action is being authorized.
//
// Example:
//
//	principal := goentitlement.NewPrincipal("user123", goentitlement.PrincipalTypeUser)
//	entitlement := goentitlement.NewEntitlement(
//		principal,
//		goentitlement.EntitlementTypePermission,
//		"read",
//	)
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
