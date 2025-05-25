package goentitlement

import (
	"context"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
)

// PrincipalType represents the type of principal
type PrincipalType string

const (
	PrincipalTypeUser    PrincipalType = "user"
	PrincipalTypeService PrincipalType = "service"
	PrincipalTypeRole    PrincipalType = "role"
	PrincipalTypeGroup   PrincipalType = "group"
)

// Principal represents an entity that can be granted entitlements
type Principal struct {
	ID         string                 `json:"id"`
	Type       PrincipalType          `json:"type"`
	Attributes map[string]interface{} `json:"attributes"`
	Groups     []string               `json:"groups"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// ResourceType represents the type of resource
type ResourceType string

const (
	ResourceTypeDocument     ResourceType = "document"
	ResourceTypeAPI          ResourceType = "api"
	ResourceTypeFeature      ResourceType = "feature"
	ResourceTypeSubscription ResourceType = "subscription"
	ResourceTypeCustom       ResourceType = "custom"
)

// Resource represents something that can be accessed or acted upon
type Resource struct {
	ID         string                 `json:"id"`
	Type       ResourceType           `json:"type"`
	Attributes map[string]interface{} `json:"attributes"`
	Owner      *Principal             `json:"owner,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// EntitlementType represents the type of entitlement
type EntitlementType string

const (
	EntitlementTypePermission   EntitlementType = "permission"
	EntitlementTypeFeatureFlag  EntitlementType = "feature_flag"
	EntitlementTypeSubscription EntitlementType = "subscription"
	EntitlementTypeRole         EntitlementType = "role"
)

// Entitlement represents a specific permission or capability
type Entitlement struct {
	ID         string                 `json:"id"`
	Type       EntitlementType        `json:"type"`
	Principal  Principal              `json:"principal"`
	Resource   *Resource              `json:"resource,omitempty"`
	Action     string                 `json:"action"`
	Conditions map[string]interface{} `json:"conditions,omitempty"`
	ExpiresAt  *time.Time             `json:"expires_at,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// AuthorizationRequest represents a request for authorization
type AuthorizationRequest struct {
	Principal Principal              `json:"principal"`
	Action    string                 `json:"action"`
	Resource  Resource               `json:"resource"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

// AuthorizationResult represents the result of an authorization check
type AuthorizationResult struct {
	Allowed  bool          `json:"allowed"`
	Reasons  []string      `json:"reasons,omitempty"`
	Policies []string      `json:"policies,omitempty"`
	Duration time.Duration `json:"duration"`
}

// Policy represents a Cedar policy
type Policy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Cedar       string    `json:"cedar"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PrincipalFilter represents filters for querying principals
type PrincipalFilter struct {
	Type   *PrincipalType `json:"type,omitempty"`
	Groups []string       `json:"groups,omitempty"`
	Limit  int            `json:"limit,omitempty"`
	Offset int            `json:"offset,omitempty"`
}

// ResourceFilter represents filters for querying resources
type ResourceFilter struct {
	Type    *ResourceType `json:"type,omitempty"`
	OwnerID *string       `json:"owner_id,omitempty"`
	Limit   int           `json:"limit,omitempty"`
	Offset  int           `json:"offset,omitempty"`
}

// EntitlementChange represents a change to an entitlement for audit logging
type EntitlementChange struct {
	Operation   string      `json:"operation"`
	Entitlement Entitlement `json:"entitlement"`
	Actor       Principal   `json:"actor"`
	Timestamp   time.Time   `json:"timestamp"`
}

// ErrorCode represents specific error types
type ErrorCode string

const (
	ErrorCodeNotFound             ErrorCode = "NOT_FOUND"
	ErrorCodeUnauthorized         ErrorCode = "UNAUTHORIZED"
	ErrorCodeInvalidInput         ErrorCode = "INVALID_INPUT"
	ErrorCodeStorageError         ErrorCode = "STORAGE_ERROR"
	ErrorCodePolicyError          ErrorCode = "POLICY_ERROR"
	ErrorCodeDuplicateEntitlement ErrorCode = "DUPLICATE_ENTITLEMENT"
)

// EntitlementError represents a custom error with error codes
type EntitlementError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Cause   error     `json:"cause,omitempty"`
}

func (e *EntitlementError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// ManagerConfig represents configuration for the EntitlementManager
type ManagerConfig struct {
	// Storage configuration
	Store     EntitlementStore
	PolicyDir string

	// Performance settings
	CacheEnabled   bool
	CacheTTL       time.Duration
	MaxConcurrency int

	// Observability
	AuditLogger      AuditLogger
	MetricsCollector MetricsCollector

	// Security
	EncryptionKey []byte
	SigningKey    []byte
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogAuthorization(ctx context.Context, req AuthorizationRequest, result AuthorizationResult)
	LogEntitlementChange(ctx context.Context, change EntitlementChange)
}

// MetricsCollector interface for metrics collection
type MetricsCollector interface {
	IncrementAuthorizationCount(allowed bool)
	RecordAuthorizationDuration(duration time.Duration)
	IncrementEntitlementCount(operation string)
}

// EntitlementStore interface for persistent storage
type EntitlementStore interface {
	// Policy storage
	SavePolicy(ctx context.Context, policy Policy) error
	GetPolicy(ctx context.Context, id string) (Policy, error)
	ListPolicies(ctx context.Context) ([]Policy, error)
	DeletePolicy(ctx context.Context, id string) error

	// Entity storage
	SavePrincipal(ctx context.Context, principal Principal) error
	GetPrincipal(ctx context.Context, id string) (Principal, error)
	SaveResource(ctx context.Context, resource Resource) error
	GetResource(ctx context.Context, id string) (Resource, error)

	// Entitlement storage
	SaveEntitlement(ctx context.Context, entitlement Entitlement) error
	GetEntitlement(ctx context.Context, id string) (Entitlement, error)
	GetEntitlements(ctx context.Context, principalID string) ([]Entitlement, error)
	DeleteEntitlement(ctx context.Context, id string) error

	// Batch operations
	SaveEntitlements(ctx context.Context, entitlements []Entitlement) error

	// Health and maintenance
	Health(ctx context.Context) error
	Close() error
}

// EntitlementManager interface - the main entry point for the library
type EntitlementManager interface {
	// Simple authorization checks
	CheckPermission(ctx context.Context, principal Principal, action string, resource Resource) (bool, error)
	CanAccess(ctx context.Context, principalID, resourceID, action string) (bool, error)

	// Feature flag operations
	HasFeature(ctx context.Context, principal Principal, feature string) (bool, error)
	IsFeatureEnabled(ctx context.Context, principalID, feature string) (bool, error)
	EnableFeature(ctx context.Context, principalID, feature string, conditions map[string]interface{}) error
	DisableFeature(ctx context.Context, principalID, feature string) error

	// Subscription management
	HasSubscription(ctx context.Context, principal Principal, tier string) (bool, error)
	GetSubscriptionTier(ctx context.Context, principalID string) (string, error)
	SetSubscription(ctx context.Context, principalID, tier string, expiresAt *time.Time) error

	// RBAC helpers
	HasRole(ctx context.Context, principal Principal, role string) (bool, error)
	AssignRole(ctx context.Context, principalID, role string) error
	RemoveRole(ctx context.Context, principalID, role string) error
	GetRoles(ctx context.Context, principalID string) ([]string, error)

	// Entitlement management
	GrantEntitlement(ctx context.Context, entitlement Entitlement) error
	RevokeEntitlement(ctx context.Context, entitlementID string) error
	ListEntitlements(ctx context.Context, principal Principal) ([]Entitlement, error)

	// Batch operations
	CheckMultiplePermissions(ctx context.Context, requests []AuthorizationRequest) ([]AuthorizationResult, error)
	GrantMultipleEntitlements(ctx context.Context, entitlements []Entitlement) error

	// Low-level access
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
