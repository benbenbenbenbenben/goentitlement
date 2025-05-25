package goentitlement

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// manager implements the EntitlementManager interface
type manager struct {
	store            EntitlementStore
	config           *ManagerConfig
	cache            map[string]cacheEntry
	cacheMu          sync.RWMutex
	auditLogger      AuditLogger
	metricsCollector MetricsCollector
}

type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
}

// NewManager creates a new EntitlementManager with default configuration
func NewManager(opts ...ManagerOption) EntitlementManager {
	return NewManagerWithStore(NewInMemoryStore(), opts...)
}

// NewManagerWithStore creates a manager with a custom store
func NewManagerWithStore(store EntitlementStore, opts ...ManagerOption) EntitlementManager {
	config := &ManagerConfig{
		Store:          store,
		CacheEnabled:   false,
		CacheTTL:       5 * time.Minute,
		MaxConcurrency: 10,
	}

	for _, opt := range opts {
		opt(config)
	}

	m := &manager{
		store:            store,
		config:           config,
		auditLogger:      config.AuditLogger,
		metricsCollector: config.MetricsCollector,
	}

	if config.CacheEnabled {
		m.cache = make(map[string]cacheEntry)
	}

	return m
}

// Simple authorization checks

func (m *manager) CheckPermission(ctx context.Context, principal Principal, action string, resource Resource) (bool, error) {
	start := time.Now()
	defer func() {
		if m.metricsCollector != nil {
			m.metricsCollector.RecordAuthorizationDuration(time.Since(start))
		}
	}()

	req := AuthorizationRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
	}

	result, err := m.RawAuthorize(ctx, req)
	if err != nil {
		return false, err
	}

	if m.metricsCollector != nil {
		m.metricsCollector.IncrementAuthorizationCount(result.Allowed)
	}

	if m.auditLogger != nil {
		m.auditLogger.LogAuthorization(ctx, req, result)
	}

	return result.Allowed, nil
}

func (m *manager) CanAccess(ctx context.Context, principalID, resourceID, action string) (bool, error) {
	principal, err := m.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return false, fmt.Errorf("failed to get principal: %w", err)
	}

	resource, err := m.store.GetResource(ctx, resourceID)
	if err != nil {
		return false, fmt.Errorf("failed to get resource: %w", err)
	}

	return m.CheckPermission(ctx, principal, action, resource)
}

// Feature flag operations

func (m *manager) HasFeature(ctx context.Context, principal Principal, feature string) (bool, error) {
	return m.hasEntitlementType(ctx, principal, EntitlementTypeFeatureFlag, feature, "")
}

func (m *manager) IsFeatureEnabled(ctx context.Context, principalID, feature string) (bool, error) {
	principal, err := m.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return false, fmt.Errorf("failed to get principal: %w", err)
	}

	return m.HasFeature(ctx, principal, feature)
}

func (m *manager) EnableFeature(ctx context.Context, principalID, feature string, conditions map[string]interface{}) error {
	principal, err := m.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return fmt.Errorf("failed to get principal: %w", err)
	}

	entitlement := Entitlement{
		ID:         uuid.New().String(),
		Type:       EntitlementTypeFeatureFlag,
		Principal:  principal,
		Action:     "use",
		Conditions: conditions,
		Resource: &Resource{
			ID:   feature,
			Type: ResourceTypeFeature,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = m.store.SaveEntitlement(ctx, entitlement)
	if err != nil {
		return fmt.Errorf("failed to save entitlement: %w", err)
	}

	if m.auditLogger != nil {
		change := EntitlementChange{
			Operation:   "enable_feature",
			Entitlement: entitlement,
			Actor:       principal,
			Timestamp:   time.Now(),
		}
		m.auditLogger.LogEntitlementChange(ctx, change)
	}

	if m.metricsCollector != nil {
		m.metricsCollector.IncrementEntitlementCount("enable_feature")
	}

	return nil
}

func (m *manager) DisableFeature(ctx context.Context, principalID, feature string) error {
	entitlements, err := m.store.GetEntitlements(ctx, principalID)
	if err != nil {
		return fmt.Errorf("failed to get entitlements: %w", err)
	}

	for _, entitlement := range entitlements {
		if entitlement.Type == EntitlementTypeFeatureFlag &&
			entitlement.Resource != nil &&
			entitlement.Resource.ID == feature {

			err = m.store.DeleteEntitlement(ctx, entitlement.ID)
			if err != nil {
				return fmt.Errorf("failed to delete entitlement: %w", err)
			}

			if m.auditLogger != nil {
				change := EntitlementChange{
					Operation:   "disable_feature",
					Entitlement: entitlement,
					Actor:       entitlement.Principal,
					Timestamp:   time.Now(),
				}
				m.auditLogger.LogEntitlementChange(ctx, change)
			}

			if m.metricsCollector != nil {
				m.metricsCollector.IncrementEntitlementCount("disable_feature")
			}
		}
	}

	return nil
}

// Subscription management

func (m *manager) HasSubscription(ctx context.Context, principal Principal, tier string) (bool, error) {
	return m.hasEntitlementType(ctx, principal, EntitlementTypeSubscription, tier, "")
}

func (m *manager) GetSubscriptionTier(ctx context.Context, principalID string) (string, error) {
	entitlements, err := m.store.GetEntitlements(ctx, principalID)
	if err != nil {
		return "", fmt.Errorf("failed to get entitlements: %w", err)
	}

	for _, entitlement := range entitlements {
		if entitlement.Type == EntitlementTypeSubscription &&
			entitlement.Resource != nil &&
			entitlement.Resource.Type == ResourceTypeSubscription {
			return entitlement.Resource.ID, nil
		}
	}

	return "", &EntitlementError{
		Code:    ErrorCodeNotFound,
		Message: "no subscription found for principal",
	}
}

func (m *manager) SetSubscription(ctx context.Context, principalID, tier string, expiresAt *time.Time) error {
	principal, err := m.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return fmt.Errorf("failed to get principal: %w", err)
	}

	// Remove existing subscription
	entitlements, err := m.store.GetEntitlements(ctx, principalID)
	if err != nil {
		return fmt.Errorf("failed to get entitlements: %w", err)
	}

	for _, entitlement := range entitlements {
		if entitlement.Type == EntitlementTypeSubscription {
			err = m.store.DeleteEntitlement(ctx, entitlement.ID)
			if err != nil {
				return fmt.Errorf("failed to delete existing subscription: %w", err)
			}
		}
	}

	// Create new subscription
	entitlement := Entitlement{
		ID:        uuid.New().String(),
		Type:      EntitlementTypeSubscription,
		Principal: principal,
		Action:    "use",
		Resource: &Resource{
			ID:   tier,
			Type: ResourceTypeSubscription,
		},
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = m.store.SaveEntitlement(ctx, entitlement)
	if err != nil {
		return fmt.Errorf("failed to save subscription: %w", err)
	}

	if m.auditLogger != nil {
		change := EntitlementChange{
			Operation:   "set_subscription",
			Entitlement: entitlement,
			Actor:       principal,
			Timestamp:   time.Now(),
		}
		m.auditLogger.LogEntitlementChange(ctx, change)
	}

	if m.metricsCollector != nil {
		m.metricsCollector.IncrementEntitlementCount("set_subscription")
	}

	return nil
}

// RBAC helpers

func (m *manager) HasRole(ctx context.Context, principal Principal, role string) (bool, error) {
	return m.hasEntitlementType(ctx, principal, EntitlementTypeRole, role, "")
}

func (m *manager) AssignRole(ctx context.Context, principalID, role string) error {
	principal, err := m.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return fmt.Errorf("failed to get principal: %w", err)
	}

	entitlement := Entitlement{
		ID:        uuid.New().String(),
		Type:      EntitlementTypeRole,
		Principal: principal,
		Action:    role,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = m.store.SaveEntitlement(ctx, entitlement)
	if err != nil {
		return fmt.Errorf("failed to save role entitlement: %w", err)
	}

	if m.auditLogger != nil {
		change := EntitlementChange{
			Operation:   "assign_role",
			Entitlement: entitlement,
			Actor:       principal,
			Timestamp:   time.Now(),
		}
		m.auditLogger.LogEntitlementChange(ctx, change)
	}

	if m.metricsCollector != nil {
		m.metricsCollector.IncrementEntitlementCount("assign_role")
	}

	return nil
}

func (m *manager) RemoveRole(ctx context.Context, principalID, role string) error {
	entitlements, err := m.store.GetEntitlements(ctx, principalID)
	if err != nil {
		return fmt.Errorf("failed to get entitlements: %w", err)
	}

	for _, entitlement := range entitlements {
		if entitlement.Type == EntitlementTypeRole && entitlement.Action == role {
			err = m.store.DeleteEntitlement(ctx, entitlement.ID)
			if err != nil {
				return fmt.Errorf("failed to delete role entitlement: %w", err)
			}

			if m.auditLogger != nil {
				change := EntitlementChange{
					Operation:   "remove_role",
					Entitlement: entitlement,
					Actor:       entitlement.Principal,
					Timestamp:   time.Now(),
				}
				m.auditLogger.LogEntitlementChange(ctx, change)
			}

			if m.metricsCollector != nil {
				m.metricsCollector.IncrementEntitlementCount("remove_role")
			}
		}
	}

	return nil
}

func (m *manager) GetRoles(ctx context.Context, principalID string) ([]string, error) {
	entitlements, err := m.store.GetEntitlements(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get entitlements: %w", err)
	}

	var roles []string
	for _, entitlement := range entitlements {
		if entitlement.Type == EntitlementTypeRole {
			roles = append(roles, entitlement.Action)
		}
	}

	return roles, nil
}

// Entitlement management

func (m *manager) GrantEntitlement(ctx context.Context, entitlement Entitlement) error {
	if entitlement.ID == "" {
		entitlement.ID = uuid.New().String()
	}

	entitlement.CreatedAt = time.Now()
	entitlement.UpdatedAt = time.Now()

	err := m.store.SaveEntitlement(ctx, entitlement)
	if err != nil {
		return fmt.Errorf("failed to save entitlement: %w", err)
	}

	if m.auditLogger != nil {
		change := EntitlementChange{
			Operation:   "grant",
			Entitlement: entitlement,
			Actor:       entitlement.Principal,
			Timestamp:   time.Now(),
		}
		m.auditLogger.LogEntitlementChange(ctx, change)
	}

	if m.metricsCollector != nil {
		m.metricsCollector.IncrementEntitlementCount("grant")
	}

	return nil
}

func (m *manager) RevokeEntitlement(ctx context.Context, entitlementID string) error {
	entitlement, err := m.store.GetEntitlement(ctx, entitlementID)
	if err != nil {
		return fmt.Errorf("failed to get entitlement: %w", err)
	}

	err = m.store.DeleteEntitlement(ctx, entitlementID)
	if err != nil {
		return fmt.Errorf("failed to delete entitlement: %w", err)
	}

	if m.auditLogger != nil {
		change := EntitlementChange{
			Operation:   "revoke",
			Entitlement: entitlement,
			Actor:       entitlement.Principal,
			Timestamp:   time.Now(),
		}
		m.auditLogger.LogEntitlementChange(ctx, change)
	}

	if m.metricsCollector != nil {
		m.metricsCollector.IncrementEntitlementCount("revoke")
	}

	return nil
}

func (m *manager) ListEntitlements(ctx context.Context, principal Principal) ([]Entitlement, error) {
	return m.store.GetEntitlements(ctx, principal.ID)
}

// Batch operations

func (m *manager) CheckMultiplePermissions(ctx context.Context, requests []AuthorizationRequest) ([]AuthorizationResult, error) {
	results := make([]AuthorizationResult, len(requests))

	for i, req := range requests {
		result, err := m.RawAuthorize(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to authorize request %d: %w", i, err)
		}
		results[i] = result

		if m.auditLogger != nil {
			m.auditLogger.LogAuthorization(ctx, req, result)
		}

		if m.metricsCollector != nil {
			m.metricsCollector.IncrementAuthorizationCount(result.Allowed)
		}
	}

	return results, nil
}

func (m *manager) GrantMultipleEntitlements(ctx context.Context, entitlements []Entitlement) error {
	for i := range entitlements {
		if entitlements[i].ID == "" {
			entitlements[i].ID = uuid.New().String()
		}
		entitlements[i].CreatedAt = time.Now()
		entitlements[i].UpdatedAt = time.Now()
	}

	err := m.store.SaveEntitlements(ctx, entitlements)
	if err != nil {
		return fmt.Errorf("failed to save entitlements: %w", err)
	}

	if m.auditLogger != nil {
		for _, entitlement := range entitlements {
			change := EntitlementChange{
				Operation:   "grant_batch",
				Entitlement: entitlement,
				Actor:       entitlement.Principal,
				Timestamp:   time.Now(),
			}
			m.auditLogger.LogEntitlementChange(ctx, change)
		}
	}

	if m.metricsCollector != nil {
		m.metricsCollector.IncrementEntitlementCount("grant_batch")
	}

	return nil
}

// Low-level access

func (m *manager) RawAuthorize(ctx context.Context, req AuthorizationRequest) (AuthorizationResult, error) {
	start := time.Now()

	// Basic entitlement-based authorization
	entitlements, err := m.store.GetEntitlements(ctx, req.Principal.ID)
	if err != nil {
		return AuthorizationResult{
			Allowed:  false,
			Reasons:  []string{"failed to retrieve entitlements"},
			Duration: time.Since(start),
		}, fmt.Errorf("failed to get entitlements: %w", err)
	}

	reasons := []string{}
	allowed := false

	// Check direct entitlements
	for _, entitlement := range entitlements {
		if m.matchesEntitlement(entitlement, req) {
			allowed = true
			reasons = append(reasons, fmt.Sprintf("entitlement %s grants access", entitlement.ID))
			break
		}
	}

	if !allowed {
		reasons = append(reasons, "no matching entitlements found")
	}

	return AuthorizationResult{
		Allowed:  allowed,
		Reasons:  reasons,
		Duration: time.Since(start),
	}, nil
}

// Helper methods

func (m *manager) hasEntitlementType(ctx context.Context, principal Principal, entType EntitlementType, identifier, action string) (bool, error) {
	entitlements, err := m.store.GetEntitlements(ctx, principal.ID)
	if err != nil {
		return false, fmt.Errorf("failed to get entitlements: %w", err)
	}

	for _, entitlement := range entitlements {
		if entitlement.Type == entType {
			switch entType {
			case EntitlementTypeFeatureFlag, EntitlementTypeSubscription:
				if entitlement.Resource != nil && entitlement.Resource.ID == identifier {
					return true, nil
				}
			case EntitlementTypeRole:
				if entitlement.Action == identifier {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func (m *manager) matchesEntitlement(entitlement Entitlement, req AuthorizationRequest) bool {
	// Check action match
	if entitlement.Action != "" && entitlement.Action != req.Action {
		return false
	}

	// Check resource match
	if entitlement.Resource != nil {
		if entitlement.Resource.ID != req.Resource.ID {
			return false
		}
		if entitlement.Resource.Type != "" && entitlement.Resource.Type != req.Resource.Type {
			return false
		}
	}

	// Basic condition checking (simplified)
	if entitlement.Conditions != nil && len(entitlement.Conditions) > 0 {
		// In a real implementation, this would evaluate complex conditions
		// For now, we'll just check basic equality
		for key, expectedValue := range entitlement.Conditions {
			if contextValue, exists := req.Context[key]; !exists || contextValue != expectedValue {
				return false
			}
		}
	}

	return true
}

// Configuration option functions

func WithPolicyDir(dir string) ManagerOption {
	return func(config *ManagerConfig) {
		config.PolicyDir = dir
	}
}

func WithCache(ttl time.Duration) ManagerOption {
	return func(config *ManagerConfig) {
		config.CacheEnabled = true
		config.CacheTTL = ttl
	}
}

func WithAuditLogger(logger AuditLogger) ManagerOption {
	return func(config *ManagerConfig) {
		config.AuditLogger = logger
	}
}

func WithMetrics(collector MetricsCollector) ManagerOption {
	return func(config *ManagerConfig) {
		config.MetricsCollector = collector
	}
}
