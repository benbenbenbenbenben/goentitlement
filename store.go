package goentitlement

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// InMemoryStore implements EntitlementStore using in-memory storage.
//
// This implementation stores all data in memory using Go maps, making it
// suitable for development, testing, or applications that don't require
// data persistence. All data is lost when the application terminates.
//
// The store is thread-safe and uses read-write mutexes for optimal
// performance on read-heavy workloads. It includes an index for efficient
// principal-to-entitlement lookups and automatic duplicate handling.
//
// Performance characteristics:
//   - Reads: O(1) for direct lookups, O(n) for filtered operations
//   - Writes: O(1) for single operations, O(n) for batch operations
//   - Memory usage: Linear with the number of stored entities
type InMemoryStore struct {
	// mu protects all data structures from concurrent access
	mu sync.RWMutex
	// policies maps policy IDs to Policy structs
	policies map[string]Policy
	// principals maps principal IDs to Principal structs
	principals map[string]Principal
	// resources maps resource IDs to Resource structs
	resources map[string]Resource
	// entitlements maps entitlement IDs to Entitlement structs
	entitlements map[string]Entitlement
	// principalEntitlements provides an index from principal IDs to their entitlement IDs
	principalEntitlements map[string][]string
}

// NewInMemoryStore creates a new in-memory storage backend.
//
// The returned store is immediately ready for use and requires no
// initialization or cleanup. All internal data structures are
// properly initialized.
//
// Example:
//
//	store := NewInMemoryStore()
//	manager := NewEntitlementManagerWithStore(store)
func NewInMemoryStore() EntitlementStore {
	return &InMemoryStore{
		policies:              make(map[string]Policy),
		principals:            make(map[string]Principal),
		resources:             make(map[string]Resource),
		entitlements:          make(map[string]Entitlement),
		principalEntitlements: make(map[string][]string),
	}
}

// Policy storage methods

func (s *InMemoryStore) SavePolicy(ctx context.Context, policy Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	s.policies[policy.ID] = policy
	return nil
}

func (s *InMemoryStore) GetPolicy(ctx context.Context, id string) (Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policy, exists := s.policies[id]
	if !exists {
		return Policy{}, &EntitlementError{
			Code:    ErrorCodeNotFound,
			Message: fmt.Sprintf("policy with ID %s not found", id),
		}
	}
	return policy, nil
}

func (s *InMemoryStore) ListPolicies(ctx context.Context) ([]Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policies := make([]Policy, 0, len(s.policies))
	for _, policy := range s.policies {
		policies = append(policies, policy)
	}
	return policies, nil
}

func (s *InMemoryStore) DeletePolicy(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.policies[id]; !exists {
		return &EntitlementError{
			Code:    ErrorCodeNotFound,
			Message: fmt.Sprintf("policy with ID %s not found", id),
		}
	}

	delete(s.policies, id)
	return nil
}

// Entity storage methods

func (s *InMemoryStore) SavePrincipal(ctx context.Context, principal Principal) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if principal.CreatedAt.IsZero() {
		principal.CreatedAt = now
	}
	principal.UpdatedAt = now

	s.principals[principal.ID] = principal
	return nil
}

func (s *InMemoryStore) GetPrincipal(ctx context.Context, id string) (Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	principal, exists := s.principals[id]
	if !exists {
		return Principal{}, &EntitlementError{
			Code:    ErrorCodeNotFound,
			Message: fmt.Sprintf("principal with ID %s not found", id),
		}
	}
	return principal, nil
}

func (s *InMemoryStore) SaveResource(ctx context.Context, resource Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if resource.CreatedAt.IsZero() {
		resource.CreatedAt = now
	}
	resource.UpdatedAt = now

	s.resources[resource.ID] = resource
	return nil
}

func (s *InMemoryStore) GetResource(ctx context.Context, id string) (Resource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resource, exists := s.resources[id]
	if !exists {
		return Resource{}, &EntitlementError{
			Code:    ErrorCodeNotFound,
			Message: fmt.Sprintf("resource with ID %s not found", id),
		}
	}
	return resource, nil
}

// Entitlement storage methods

func (s *InMemoryStore) SaveEntitlement(ctx context.Context, entitlement Entitlement) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if entitlement.CreatedAt.IsZero() {
		entitlement.CreatedAt = now
	}
	entitlement.UpdatedAt = now

	// Check for existing logical duplicate and update it instead of creating a new one
	principalID := entitlement.Principal.ID
	entitlementIDs := s.principalEntitlements[principalID]

	for _, id := range entitlementIDs {
		existingEnt, exists := s.entitlements[id]
		if !exists {
			continue
		}

		// If we find a logical duplicate, update the existing entitlement
		if isLogicalDuplicate(entitlement, existingEnt) {
			// Preserve the original ID and CreatedAt
			entitlement.ID = existingEnt.ID
			entitlement.CreatedAt = existingEnt.CreatedAt
			entitlement.UpdatedAt = now
			s.entitlements[entitlement.ID] = entitlement
			return nil
		}
	}

	// No duplicate found, save as new entitlement
	s.entitlements[entitlement.ID] = entitlement

	// Update principal entitlements index
	// Check if already exists
	exists := false
	for _, id := range entitlementIDs {
		if id == entitlement.ID {
			exists = true
			break
		}
	}

	if !exists {
		s.principalEntitlements[principalID] = append(entitlementIDs, entitlement.ID)
	}

	return nil
}

func (s *InMemoryStore) GetEntitlement(ctx context.Context, id string) (Entitlement, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entitlement, exists := s.entitlements[id]
	if !exists {
		return Entitlement{}, &EntitlementError{
			Code:    ErrorCodeNotFound,
			Message: fmt.Sprintf("entitlement with ID %s not found", id),
		}
	}
	return entitlement, nil
}

func (s *InMemoryStore) GetEntitlements(ctx context.Context, principalID string) ([]Entitlement, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entitlementIDs, exists := s.principalEntitlements[principalID]
	if !exists {
		return []Entitlement{}, nil
	}

	entitlements := make([]Entitlement, 0, len(entitlementIDs))
	for _, id := range entitlementIDs {
		if entitlement, exists := s.entitlements[id]; exists {
			// Check if entitlement hasn't expired
			if entitlement.ExpiresAt == nil || entitlement.ExpiresAt.After(time.Now()) {
				entitlements = append(entitlements, entitlement)
			}
		}
	}

	return entitlements, nil
}

func (s *InMemoryStore) DeleteEntitlement(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entitlement, exists := s.entitlements[id]
	if !exists {
		return &EntitlementError{
			Code:    ErrorCodeNotFound,
			Message: fmt.Sprintf("entitlement with ID %s not found", id),
		}
	}

	// Remove from entitlements map
	delete(s.entitlements, id)

	// Remove from principal entitlements index
	principalID := entitlement.Principal.ID
	entitlementIDs := s.principalEntitlements[principalID]
	for i, entitlementID := range entitlementIDs {
		if entitlementID == id {
			s.principalEntitlements[principalID] = append(entitlementIDs[:i], entitlementIDs[i+1:]...)
			break
		}
	}

	return nil
}

// Batch operations

func (s *InMemoryStore) SaveEntitlements(ctx context.Context, entitlements []Entitlement) error {
	for _, entitlement := range entitlements {
		// Use SaveEntitlement to handle duplicate logic for each entitlement
		if err := s.SaveEntitlement(ctx, entitlement); err != nil {
			return err
		}
	}
	return nil
}

// Health and maintenance

func (s *InMemoryStore) Health(ctx context.Context) error {
	// In-memory store is always healthy if it exists
	return nil
}

func (s *InMemoryStore) Close() error {
	// Nothing to close for in-memory store
	return nil
}
