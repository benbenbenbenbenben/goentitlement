package goentitlement

import (
	"context"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
)

// PrincipalType represents the category of a principal entity.
//
// Principal types help organize and categorize different kinds of entities
// that can be granted entitlements in your system.
type PrincipalType string

const (
	// PrincipalTypeUser represents individual human users
	PrincipalTypeUser PrincipalType = "user"
	// PrincipalTypeService represents automated services or applications
	PrincipalTypeService PrincipalType = "service"
	// PrincipalTypeRole represents a collection of permissions that can be assigned
	PrincipalTypeRole PrincipalType = "role"
	// PrincipalTypeGroup represents a collection of users or other principals
	PrincipalTypeGroup PrincipalType = "group"
)

// Principal represents an entity that can be granted entitlements.
//
// Principals are the subjects in authorization decisions. They can represent users,
// services, roles, or groups within your system. Each principal has a unique ID
// and can have custom attributes and group memberships.
//
// Example:
//
//	user := Principal{
//		ID:   "user123",
//		Type: PrincipalTypeUser,
//		Attributes: map[string]interface{}{
//			"department": "engineering",
//			"level":      "senior",
//		},
//		Groups: []string{"developers", "admins"},
//	}
type Principal struct {
	// ID is the unique identifier for this principal
	ID string `json:"id"`
	// Type categorizes the kind of principal (user, service, role, group)
	Type PrincipalType `json:"type"`
	// Attributes stores custom key-value pairs for this principal
	Attributes map[string]interface{} `json:"attributes"`
	// Groups lists the group memberships for this principal
	Groups []string `json:"groups"`
	// CreatedAt records when this principal was first created
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt records when this principal was last modified
	UpdatedAt time.Time `json:"updated_at"`
}

// ResourceType represents the category of a resource entity.
//
// Resource types help organize and categorize different kinds of objects
// that can be protected by entitlements in your system.
type ResourceType string

const (
	// ResourceTypeDocument represents files, documents, or content items
	ResourceTypeDocument ResourceType = "document"
	// ResourceTypeAPI represents API endpoints or web services
	ResourceTypeAPI ResourceType = "api"
	// ResourceTypeFeature represents application features or capabilities
	ResourceTypeFeature ResourceType = "feature"
	// ResourceTypeSubscription represents subscription tiers or plans
	ResourceTypeSubscription ResourceType = "subscription"
	// ResourceTypeCustom represents application-specific resource types
	ResourceTypeCustom ResourceType = "custom"
)

// Resource represents something that can be accessed or acted upon.
//
// Resources are the objects in authorization decisions. They represent
// anything that needs to be protected or controlled in your system,
// such as documents, API endpoints, features, or subscription tiers.
//
// Example:
//
//	document := Resource{
//		ID:   "doc123",
//		Type: ResourceTypeDocument,
//		Attributes: map[string]interface{}{
//			"classification": "confidential",
//			"project":        "alpha",
//		},
//	}
type Resource struct {
	// ID is the unique identifier for this resource
	ID string `json:"id"`
	// Type categorizes the kind of resource
	Type ResourceType `json:"type"`
	// Attributes stores custom key-value pairs for this resource
	Attributes map[string]interface{} `json:"attributes"`
	// Owner optionally specifies the principal that owns this resource
	Owner *Principal `json:"owner,omitempty"`
	// CreatedAt records when this resource was first created
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt records when this resource was last modified
	UpdatedAt time.Time `json:"updated_at"`
}

// EntitlementType represents the category of an entitlement.
//
// Entitlement types help organize different kinds of capabilities
// or permissions that can be granted to principals.
type EntitlementType string

const (
	// EntitlementTypePermission represents standard access permissions
	EntitlementTypePermission EntitlementType = "permission"
	// EntitlementTypeFeatureFlag represents feature toggles or capabilities
	EntitlementTypeFeatureFlag EntitlementType = "feature_flag"
	// EntitlementTypeSubscription represents subscription-based access
	EntitlementTypeSubscription EntitlementType = "subscription"
	// EntitlementTypeRole represents role assignments
	EntitlementTypeRole EntitlementType = "role"
)

// Entitlement represents a specific permission or capability granted to a principal.
//
// Entitlements are the core authorization grants in the system. They specify
// what a principal is allowed to do, optionally on specific resources,
// with optional conditions and expiration times.
//
// Example:
//
//	entitlement := Entitlement{
//		ID:        "ent123",
//		Type:      EntitlementTypePermission,
//		Principal: user,
//		Resource:  &document,
//		Action:    "read",
//		Conditions: map[string]interface{}{
//			"time_of_day": "business_hours",
//		},
//		ExpiresAt: &expirationTime,
//	}
type Entitlement struct {
	// ID is the unique identifier for this entitlement
	ID string `json:"id"`
	// Type categorizes the kind of entitlement
	Type EntitlementType `json:"type"`
	// Principal specifies who is granted this entitlement
	Principal Principal `json:"principal"`
	// Resource optionally specifies what resource this entitlement applies to
	Resource *Resource `json:"resource,omitempty"`
	// Action specifies what action is being authorized
	Action string `json:"action"`
	// Conditions optionally specifies additional constraints for this entitlement
	Conditions map[string]interface{} `json:"conditions,omitempty"`
	// ExpiresAt optionally specifies when this entitlement expires
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// CreatedAt records when this entitlement was first created
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt records when this entitlement was last modified
	UpdatedAt time.Time `json:"updated_at"`
}

// AuthorizationRequest represents a request for authorization evaluation.
//
// This structure encapsulates all the information needed to make an authorization
// decision: who is requesting access (Principal), what they want to do (Action),
// what they want to access (Resource), and any additional context.
//
// Example:
//
//	request := AuthorizationRequest{
//		Principal: user,
//		Action:    "read",
//		Resource:  document,
//		Context: map[string]interface{}{
//			"ip_address": "192.168.1.1",
//			"user_agent": "MyApp/1.0",
//		},
//	}
type AuthorizationRequest struct {
	// Principal specifies who is making the request
	Principal Principal `json:"principal"`
	// Action specifies what operation is being requested
	Action string `json:"action"`
	// Resource specifies what is being accessed
	Resource Resource `json:"resource"`
	// Context provides additional information for authorization decisions
	Context map[string]interface{} `json:"context,omitempty"`
}

// AuthorizationResult represents the outcome of an authorization evaluation.
//
// This structure contains the authorization decision along with supporting
// information such as the reasoning behind the decision, applicable policies,
// and performance metrics.
//
// Example:
//
//	result := AuthorizationResult{
//		Allowed:  true,
//		Reasons:  []string{"user has read permission on document"},
//		Policies: []string{"document-access-policy"},
//		Duration: 2 * time.Millisecond,
//	}
type AuthorizationResult struct {
	// Allowed indicates whether the request is authorized
	Allowed bool `json:"allowed"`
	// Reasons provides human-readable explanations for the decision
	Reasons []string `json:"reasons,omitempty"`
	// Policies lists the policies that influenced the decision
	Policies []string `json:"policies,omitempty"`
	// Duration records how long the authorization evaluation took
	Duration time.Duration `json:"duration"`
}

// Policy represents a Cedar authorization policy.
//
// Policies define the rules that govern authorization decisions in the system.
// They are written in the Cedar policy language and can express complex
// authorization logic including conditions, context evaluation, and hierarchical
// permissions.
//
// Example:
//
//	policy := Policy{
//		ID:          "doc-read-policy",
//		Name:        "Document Read Access",
//		Description: "Allows users to read documents they own",
//		Cedar:       `permit(principal, action == "read", resource) when { principal == resource.owner };`,
//	}
type Policy struct {
	// ID is the unique identifier for this policy
	ID string `json:"id"`
	// Name is a human-readable name for this policy
	Name string `json:"name"`
	// Description explains what this policy does
	Description string `json:"description"`
	// Cedar contains the policy definition in Cedar language syntax
	Cedar string `json:"cedar"`
	// CreatedAt records when this policy was first created
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt records when this policy was last modified
	UpdatedAt time.Time `json:"updated_at"`
}

// PrincipalFilter specifies criteria for querying principals.
//
// This structure allows filtering principals by type, group membership,
// and provides pagination support for large result sets.
//
// Example:
//
//	filter := PrincipalFilter{
//		Type:   &goentitlement.PrincipalTypeUser,
//		Groups: []string{"admins", "developers"},
//		Limit:  50,
//		Offset: 100,
//	}
type PrincipalFilter struct {
	// Type optionally filters by principal type
	Type *PrincipalType `json:"type,omitempty"`
	// Groups optionally filters by group membership
	Groups []string `json:"groups,omitempty"`
	// Limit optionally limits the number of results returned
	Limit int `json:"limit,omitempty"`
	// Offset optionally skips a number of results for pagination
	Offset int `json:"offset,omitempty"`
}

// ResourceFilter specifies criteria for querying resources.
//
// This structure allows filtering resources by type, ownership,
// and provides pagination support for large result sets.
//
// Example:
//
//	ownerID := "user123"
//	filter := ResourceFilter{
//		Type:    &goentitlement.ResourceTypeDocument,
//		OwnerID: &ownerID,
//		Limit:   25,
//	}
type ResourceFilter struct {
	// Type optionally filters by resource type
	Type *ResourceType `json:"type,omitempty"`
	// OwnerID optionally filters by the resource owner's ID
	OwnerID *string `json:"owner_id,omitempty"`
	// Limit optionally limits the number of results returned
	Limit int `json:"limit,omitempty"`
	// Offset optionally skips a number of results for pagination
	Offset int `json:"offset,omitempty"`
}

// EntitlementChange represents a modification to an entitlement for audit logging.
//
// This structure captures all the information needed to audit changes to
// entitlements in the system, including what changed, who made the change,
// and when it occurred.
//
// Example:
//
//	change := EntitlementChange{
//		Operation:   "grant",
//		Entitlement: newEntitlement,
//		Actor:       adminUser,
//		Timestamp:   time.Now(),
//	}
type EntitlementChange struct {
	// Operation describes what kind of change was made (grant, revoke, update, etc.)
	Operation string `json:"operation"`
	// Entitlement is the entitlement that was modified
	Entitlement Entitlement `json:"entitlement"`
	// Actor is the principal who made the change
	Actor Principal `json:"actor"`
	// Timestamp records when the change occurred
	Timestamp time.Time `json:"timestamp"`
}

// ErrorCode represents specific categories of errors that can occur in the system.
//
// Error codes provide a standardized way to categorize and handle different
// types of failures, making it easier for applications to respond appropriately
// to different error conditions.
type ErrorCode string

const (
	// ErrorCodeNotFound indicates a requested entity was not found
	ErrorCodeNotFound ErrorCode = "NOT_FOUND"
	// ErrorCodeUnauthorized indicates a request was not authorized
	ErrorCodeUnauthorized ErrorCode = "UNAUTHORIZED"
	// ErrorCodeInvalidInput indicates invalid or malformed input data
	ErrorCodeInvalidInput ErrorCode = "INVALID_INPUT"
	// ErrorCodeStorageError indicates a problem with the storage backend
	ErrorCodeStorageError ErrorCode = "STORAGE_ERROR"
	// ErrorCodePolicyError indicates a problem with policy evaluation
	ErrorCodePolicyError ErrorCode = "POLICY_ERROR"
	// ErrorCodeDuplicateEntitlement indicates an attempt to create a duplicate entitlement
	ErrorCodeDuplicateEntitlement ErrorCode = "DUPLICATE_ENTITLEMENT"
)

// EntitlementError represents a structured error with categorization and context.
//
// This error type provides detailed information about failures in the entitlement
// system, including error codes for programmatic handling and optional cause
// chaining for debugging.
//
// Example:
//
//	err := &EntitlementError{
//		Code:    ErrorCodeNotFound,
//		Message: "principal not found",
//		Cause:   originalError,
//	}
type EntitlementError struct {
	// Code categorizes the type of error
	Code ErrorCode `json:"code"`
	// Message provides a human-readable description of the error
	Message string `json:"message"`
	// Cause optionally wraps the underlying error that caused this failure
	Cause error `json:"cause,omitempty"`
}

// Error implements the error interface for EntitlementError.
//
// It returns a formatted error message that includes the main message
// and any underlying cause information.
func (e *EntitlementError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// ManagerConfig represents configuration options for the EntitlementManager.
//
// This structure allows customization of various aspects of the manager's
// behavior including storage, performance, observability, and security settings.
//
// Example:
//
//	config := ManagerConfig{
//		Store:            fileStore,
//		CacheEnabled:     true,
//		CacheTTL:         5 * time.Minute,
//		MaxConcurrency:   20,
//		AuditLogger:      myAuditLogger,
//		MetricsCollector: myMetricsCollector,
//	}
type ManagerConfig struct {
	// Store specifies the storage backend for persistent data
	Store EntitlementStore
	// PolicyDir optionally specifies a directory containing Cedar policy files
	PolicyDir string

	// CacheEnabled determines whether to enable in-memory caching
	CacheEnabled bool
	// CacheTTL specifies how long cached items remain valid
	CacheTTL time.Duration
	// MaxConcurrency limits the number of concurrent operations
	MaxConcurrency int

	// AuditLogger optionally provides audit logging functionality
	AuditLogger AuditLogger
	// MetricsCollector optionally provides metrics collection functionality
	MetricsCollector MetricsCollector

	// EncryptionKey optionally provides a key for data encryption
	EncryptionKey []byte
	// SigningKey optionally provides a key for data signing
	SigningKey []byte
}

// AuditLogger defines the interface for audit logging implementations.
//
// Audit loggers capture important security events in the entitlement system,
// including authorization decisions and entitlement changes. This enables
// compliance reporting, security monitoring, and forensic analysis.
//
// Example implementation:
//
//	type MyAuditLogger struct{}
//
//	func (l *MyAuditLogger) LogAuthorization(ctx context.Context, req AuthorizationRequest, result AuthorizationResult) {
//		log.Printf("Authorization: %s %s %s -> %v", req.Principal.ID, req.Action, req.Resource.ID, result.Allowed)
//	}
//
//	func (l *MyAuditLogger) LogEntitlementChange(ctx context.Context, change EntitlementChange) {
//		log.Printf("Entitlement %s: %s by %s", change.Operation, change.Entitlement.ID, change.Actor.ID)
//	}
type AuditLogger interface {
	// LogAuthorization records authorization decisions for audit purposes
	LogAuthorization(ctx context.Context, req AuthorizationRequest, result AuthorizationResult)
	// LogEntitlementChange records changes to entitlements for audit purposes
	LogEntitlementChange(ctx context.Context, change EntitlementChange)
}

// MetricsCollector defines the interface for metrics collection implementations.
//
// Metrics collectors gather performance and usage statistics from the entitlement
// system, enabling monitoring, alerting, and capacity planning.
//
// Example implementation:
//
//	type MyMetricsCollector struct{}
//
//	func (m *MyMetricsCollector) IncrementAuthorizationCount(allowed bool) {
//		if allowed {
//			authorizedCounter.Inc()
//		} else {
//			deniedCounter.Inc()
//		}
//	}
//
//	func (m *MyMetricsCollector) RecordAuthorizationDuration(duration time.Duration) {
//		authorizationDurationHistogram.Observe(duration.Seconds())
//	}
type MetricsCollector interface {
	// IncrementAuthorizationCount tracks the number of authorization requests
	IncrementAuthorizationCount(allowed bool)
	// RecordAuthorizationDuration tracks how long authorization requests take
	RecordAuthorizationDuration(duration time.Duration)
	// IncrementEntitlementCount tracks the number of entitlement operations
	IncrementEntitlementCount(operation string)
}

// EntitlementStore defines the interface for persistent storage backends.
//
// This interface abstracts the storage layer, allowing different implementations
// such as in-memory, file-based, or database-backed storage. All storage
// operations are context-aware and support proper error handling.
//
// The interface is organized into logical groups:
//   - Policy storage: For Cedar policies
//   - Entity storage: For principals and resources
//   - Entitlement storage: For entitlement grants
//   - Batch operations: For performance optimization
//   - Health and maintenance: For operational concerns
//
// Example implementation structure:
//
//	type MyStore struct {
//		// Implementation-specific fields
//	}
//
//	func (s *MyStore) SavePolicy(ctx context.Context, policy Policy) error {
//		// Store the policy
//		return nil
//	}
type EntitlementStore interface {
	// SavePolicy persists a policy to storage
	SavePolicy(ctx context.Context, policy Policy) error
	// GetPolicy retrieves a policy by ID
	GetPolicy(ctx context.Context, id string) (Policy, error)
	// ListPolicies retrieves all policies from storage
	ListPolicies(ctx context.Context) ([]Policy, error)
	// DeletePolicy removes a policy from storage
	DeletePolicy(ctx context.Context, id string) error

	// SavePrincipal persists a principal to storage
	SavePrincipal(ctx context.Context, principal Principal) error
	// GetPrincipal retrieves a principal by ID
	GetPrincipal(ctx context.Context, id string) (Principal, error)
	// SaveResource persists a resource to storage
	SaveResource(ctx context.Context, resource Resource) error
	// GetResource retrieves a resource by ID
	GetResource(ctx context.Context, id string) (Resource, error)

	// SaveEntitlement persists an entitlement to storage, handling duplicates appropriately
	SaveEntitlement(ctx context.Context, entitlement Entitlement) error
	// GetEntitlement retrieves an entitlement by ID
	GetEntitlement(ctx context.Context, id string) (Entitlement, error)
	// GetEntitlements retrieves all entitlements for a specific principal
	GetEntitlements(ctx context.Context, principalID string) ([]Entitlement, error)
	// DeleteEntitlement removes an entitlement from storage
	DeleteEntitlement(ctx context.Context, id string) error

	// SaveEntitlements persists multiple entitlements in a batch operation
	SaveEntitlements(ctx context.Context, entitlements []Entitlement) error

	// Health checks the storage backend's health status
	Health(ctx context.Context) error
	// Close gracefully shuts down the storage backend
	Close() error
}

// EntitlementManager defines the main interface for the entitlement management system.
//
// This is the primary interface that applications use to interact with the entitlement
// system. It provides high-level methods for authorization checks, feature flag
// management, subscription handling, role-based access control, and entitlement
// administration.
//
// The interface is organized into logical groups:
//   - Authorization: CheckPermission, CanAccess, RawAuthorize
//   - Feature Flags: HasFeature, IsFeatureEnabled, EnableFeature, DisableFeature
//   - Subscriptions: HasSubscription, GetSubscriptionTier, SetSubscription
//   - RBAC: HasRole, AssignRole, RemoveRole, GetRoles
//   - Entitlements: GrantEntitlement, RevokeEntitlement, ListEntitlements
//   - Batch Operations: CheckMultiplePermissions, GrantMultipleEntitlements
//
// Example usage:
//
//	manager := goentitlement.NewEntitlementManager()
//
//	// Check if user can read a document
//	allowed, err := manager.CheckPermission(ctx, user, "read", document)
//
//	// Check if user has premium features
//	hasPremium, err := manager.HasSubscription(ctx, user, "premium")
//
//	// Enable a feature for a user
//	err = manager.EnableFeature(ctx, user.ID, "advanced_analytics", nil)
type EntitlementManager interface {
	// CheckPermission verifies if a principal can perform an action on a resource
	CheckPermission(ctx context.Context, principal Principal, action string, resource Resource) (bool, error)
	// CanAccess is a convenience method for checking access using entity IDs
	CanAccess(ctx context.Context, principalID, resourceID, action string) (bool, error)

	// HasFeature checks if a principal has access to a specific feature
	HasFeature(ctx context.Context, principal Principal, feature string) (bool, error)
	// IsFeatureEnabled is a convenience method for checking features using principal ID
	IsFeatureEnabled(ctx context.Context, principalID, feature string) (bool, error)
	// EnableFeature grants access to a feature for a principal with optional conditions
	EnableFeature(ctx context.Context, principalID, feature string, conditions map[string]interface{}) error
	// DisableFeature revokes access to a feature for a principal
	DisableFeature(ctx context.Context, principalID, feature string) error

	// HasSubscription checks if a principal has a specific subscription tier
	HasSubscription(ctx context.Context, principal Principal, tier string) (bool, error)
	// GetSubscriptionTier returns the current subscription tier for a principal
	GetSubscriptionTier(ctx context.Context, principalID string) (string, error)
	// SetSubscription assigns a subscription tier to a principal with optional expiration
	SetSubscription(ctx context.Context, principalID, tier string, expiresAt *time.Time) error

	// HasRole checks if a principal has a specific role
	HasRole(ctx context.Context, principal Principal, role string) (bool, error)
	// AssignRole grants a role to a principal
	AssignRole(ctx context.Context, principalID, role string) error
	// RemoveRole revokes a role from a principal
	RemoveRole(ctx context.Context, principalID, role string) error
	// GetRoles returns all roles assigned to a principal
	GetRoles(ctx context.Context, principalID string) ([]string, error)

	// GrantEntitlement creates a new entitlement for a principal
	GrantEntitlement(ctx context.Context, entitlement Entitlement) error
	// RevokeEntitlement removes an existing entitlement
	RevokeEntitlement(ctx context.Context, entitlementID string) error
	// ListEntitlements returns all entitlements for a principal
	ListEntitlements(ctx context.Context, principal Principal) ([]Entitlement, error)

	// CheckMultiplePermissions efficiently checks multiple authorization requests
	CheckMultiplePermissions(ctx context.Context, requests []AuthorizationRequest) ([]AuthorizationResult, error)
	// GrantMultipleEntitlements efficiently creates multiple entitlements
	GrantMultipleEntitlements(ctx context.Context, entitlements []Entitlement) error

	// RawAuthorize performs low-level authorization with full request/response details
	RawAuthorize(ctx context.Context, req AuthorizationRequest) (AuthorizationResult, error)
}

// EntityManager interface for entity management
type EntityManager interface {
	// Principal management
	CreatePrincipal(ctx context.Context, principal Principal) error
	GetPrincipal(ctx context.Context, id string) (Principal, error)
	UpdatePrincipal(ctx context.Context, principal Principal) error
	DeletePrincipal(ctx context.Context, id string) error
	ListPrincipals(ctx context.Context, filter PrincipalFilter) ([]Principal, error)

	// Resource management
	CreateResource(ctx context.Context, resource Resource) error
	GetResource(ctx context.Context, id string) (Resource, error)
	UpdateResource(ctx context.Context, resource Resource) error
	DeleteResource(ctx context.Context, id string) error
	ListResources(ctx context.Context, filter ResourceFilter) ([]Resource, error)
}

// PolicyBuilder interface for building policies programmatically
type PolicyBuilder interface {
	// Create policies programmatically
	NewPolicy(name string) PolicyBuilder

	// Set policy components
	WithPrincipal(principal string) PolicyBuilder
	WithAction(action string) PolicyBuilder
	WithResource(resource string) PolicyBuilder
	WithCondition(condition string) PolicyBuilder

	// Build the policy
	Build() (Policy, error)

	// Generate Cedar policy text
	ToCedar() (string, error)
}

// CedarEngine interface for direct Cedar access
type CedarEngine interface {
	// Direct Cedar policy operations
	AddCedarPolicy(ctx context.Context, policyID, cedar string) error
	RemoveCedarPolicy(ctx context.Context, policyID string) error

	// Direct entity operations
	AddCedarEntity(ctx context.Context, entity cedar.Entity) error
	RemoveCedarEntity(ctx context.Context, entityID cedar.EntityUID) error

	// Raw authorization
	Authorize(ctx context.Context, req cedar.Request) (cedar.Decision, error)

	// Schema management
	SetSchema(ctx context.Context, schema string) error
	ValidatePolicy(ctx context.Context, policy string) error
}

// isLogicalDuplicate checks if two entitlements have the same logical content
// (same Principal.ID + Resource.ID + Action + Type combination)
func isLogicalDuplicate(ent1, ent2 Entitlement) bool {
	// Check principal ID
	if ent1.Principal.ID != ent2.Principal.ID {
		return false
	}

	// Check action
	if ent1.Action != ent2.Action {
		return false
	}

	// Check type
	if ent1.Type != ent2.Type {
		return false
	}

	// Check resource - both nil or both have same ID and Type
	if ent1.Resource == nil && ent2.Resource == nil {
		return true
	}
	if ent1.Resource == nil || ent2.Resource == nil {
		return false
	}
	return ent1.Resource.ID == ent2.Resource.ID && ent1.Resource.Type == ent2.Resource.Type
}

// ManagerOption configures the EntitlementManager
type ManagerOption func(*ManagerConfig)
