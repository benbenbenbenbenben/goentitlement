package goentitlement

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileStore implements the EntitlementStore interface using the local filesystem.
// Data is stored in JSON files.
type FileStore struct {
	principalsDir   string
	resourcesDir    string
	entitlementsDir string
	policiesDir     string
}

// NewFileStore creates a new FileStore instance.
// It will create the necessary directories if they don't exist.
func NewFileStore(baseDir string) (*FileStore, error) {
	principalsDir := filepath.Join(baseDir, "principals")
	resourcesDir := filepath.Join(baseDir, "resources")
	entitlementsDir := filepath.Join(baseDir, "entitlements")
	policiesDir := filepath.Join(baseDir, "policies")

	dirs := []string{principalsDir, resourcesDir, entitlementsDir, policiesDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return &FileStore{
		principalsDir:   principalsDir,
		resourcesDir:    resourcesDir,
		entitlementsDir: entitlementsDir,
		policiesDir:     policiesDir,
	}, nil
}

// SavePolicy saves a policy to a JSON file.
func (fs *FileStore) SavePolicy(ctx context.Context, policy Policy) error {
	filePath := filepath.Join(fs.policiesDir, policy.ID+".json")
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}
	return os.WriteFile(filePath, data, 0644)
}

// GetPolicy retrieves a policy from a JSON file.
func (fs *FileStore) GetPolicy(ctx context.Context, id string) (Policy, error) {
	filePath := filepath.Join(fs.policiesDir, id+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return Policy{}, &EntitlementError{Code: ErrorCodeNotFound, Message: "policy not found"}
		}
		return Policy{}, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return Policy{}, fmt.Errorf("failed to unmarshal policy: %w", err)
	}
	return policy, nil
}

// ListPolicies retrieves all policies from the policies directory.
func (fs *FileStore) ListPolicies(ctx context.Context) ([]Policy, error) {
	files, err := os.ReadDir(fs.policiesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read policies directory: %w", err)
	}

	var policies []Policy
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".json" {
			policyID := file.Name()[:len(file.Name())-len(filepath.Ext(file.Name()))]
			policy, err := fs.GetPolicy(ctx, policyID)
			if err != nil {
				// Log or handle error, e.g., skip corrupted file
				continue
			}
			policies = append(policies, policy)
		}
	}
	return policies, nil
}

// DeletePolicy deletes a policy JSON file.
func (fs *FileStore) DeletePolicy(ctx context.Context, id string) error {
	filePath := filepath.Join(fs.policiesDir, id+".json")
	err := os.Remove(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &EntitlementError{Code: ErrorCodeNotFound, Message: "policy not found"}
		}
		return fmt.Errorf("failed to delete policy file: %w", err)
	}
	return nil
}

// SavePrincipal saves a principal to a JSON file.
func (fs *FileStore) SavePrincipal(ctx context.Context, principal Principal) error {
	filePath := filepath.Join(fs.principalsDir, principal.ID+".json")
	data, err := json.MarshalIndent(principal, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal principal: %w", err)
	}
	return os.WriteFile(filePath, data, 0644)
}

// GetPrincipal retrieves a principal from a JSON file.
func (fs *FileStore) GetPrincipal(ctx context.Context, id string) (Principal, error) {
	filePath := filepath.Join(fs.principalsDir, id+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return Principal{}, &EntitlementError{Code: ErrorCodeNotFound, Message: "principal not found"}
		}
		return Principal{}, fmt.Errorf("failed to read principal file: %w", err)
	}

	var principal Principal
	if err := json.Unmarshal(data, &principal); err != nil {
		return Principal{}, fmt.Errorf("failed to unmarshal principal: %w", err)
	}
	return principal, nil
}

// SaveResource saves a resource to a JSON file.
func (fs *FileStore) SaveResource(ctx context.Context, resource Resource) error {
	filePath := filepath.Join(fs.resourcesDir, resource.ID+".json")
	data, err := json.MarshalIndent(resource, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal resource: %w", err)
	}
	return os.WriteFile(filePath, data, 0644)
}

// GetResource retrieves a resource from a JSON file.
func (fs *FileStore) GetResource(ctx context.Context, id string) (Resource, error) {
	filePath := filepath.Join(fs.resourcesDir, id+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return Resource{}, &EntitlementError{Code: ErrorCodeNotFound, Message: "resource not found"}
		}
		return Resource{}, fmt.Errorf("failed to read resource file: %w", err)
	}

	var resource Resource
	if err := json.Unmarshal(data, &resource); err != nil {
		return Resource{}, fmt.Errorf("failed to unmarshal resource: %w", err)
	}
	return resource, nil
}

// SaveEntitlement saves an entitlement to a JSON file.
func (fs *FileStore) SaveEntitlement(ctx context.Context, entitlement Entitlement) error {
	// Check for existing logical duplicate and update it instead of creating a new one
	existingEntitlements, err := fs.GetEntitlements(ctx, entitlement.Principal.ID)
	if err != nil {
		return fmt.Errorf("failed to get existing entitlements: %w", err)
	}

	// Look for logical duplicates
	for _, existingEnt := range existingEntitlements {
		if isLogicalDuplicate(entitlement, existingEnt) {
			// Update the existing entitlement: preserve ID and CreatedAt, update other fields
			entitlement.ID = existingEnt.ID
			entitlement.CreatedAt = existingEnt.CreatedAt
			entitlement.UpdatedAt = time.Now()
			break
		}
	}

	// If no CreatedAt was set (new entitlement), set it now
	if entitlement.CreatedAt.IsZero() {
		entitlement.CreatedAt = time.Now()
	}
	entitlement.UpdatedAt = time.Now()

	filePath := filepath.Join(fs.entitlementsDir, entitlement.ID+".json")
	data, err := json.MarshalIndent(entitlement, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal entitlement: %w", err)
	}
	return os.WriteFile(filePath, data, 0644)
}

// GetEntitlement retrieves an entitlement from a JSON file.
func (fs *FileStore) GetEntitlement(ctx context.Context, id string) (Entitlement, error) {
	filePath := filepath.Join(fs.entitlementsDir, id+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return Entitlement{}, &EntitlementError{Code: ErrorCodeNotFound, Message: "entitlement not found"}
		}
		return Entitlement{}, fmt.Errorf("failed to read entitlement file: %w", err)
	}

	var entitlement Entitlement
	if err := json.Unmarshal(data, &entitlement); err != nil {
		return Entitlement{}, fmt.Errorf("failed to unmarshal entitlement: %w", err)
	}
	return entitlement, nil
}

// GetEntitlements retrieves all entitlements for a given principalID.
// This is a simplified implementation; a real one might need more complex querying or indexing.
func (fs *FileStore) GetEntitlements(ctx context.Context, principalID string) ([]Entitlement, error) {
	var entitlements []Entitlement
	files, err := os.ReadDir(fs.entitlementsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read entitlements directory: %w", err)
	}

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".json" {
			entitlementID := file.Name()[:len(file.Name())-len(filepath.Ext(file.Name()))]
			ent, err := fs.GetEntitlement(ctx, entitlementID)
			if err != nil {
				// Log or handle error
				continue
			}
			if ent.Principal.ID == principalID {
				entitlements = append(entitlements, ent)
			}
		}
	}
	return entitlements, nil
}

// DeleteEntitlement deletes an entitlement JSON file.
func (fs *FileStore) DeleteEntitlement(ctx context.Context, id string) error {
	filePath := filepath.Join(fs.entitlementsDir, id+".json")
	err := os.Remove(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &EntitlementError{Code: ErrorCodeNotFound, Message: "entitlement not found"}
		}
		return fmt.Errorf("failed to delete entitlement file: %w", err)
	}
	return nil
}

// SaveEntitlements saves multiple entitlements.
// This is a basic implementation that calls SaveEntitlement for each.
// For performance, a real implementation might batch writes or use a transactional approach.
func (fs *FileStore) SaveEntitlements(ctx context.Context, entitlements []Entitlement) error {
	for _, ent := range entitlements {
		if err := fs.SaveEntitlement(ctx, ent); err != nil {
			return fmt.Errorf("failed to save entitlement %s: %w", ent.ID, err)
		}
	}
	return nil
}

// Health checks if the base directories are accessible.
func (fs *FileStore) Health(ctx context.Context) error {
	dirs := []string{fs.principalsDir, fs.resourcesDir, fs.entitlementsDir, fs.policiesDir}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("directory %s not found: %w", dir, err)
		} else if err != nil {
			return fmt.Errorf("failed to access directory %s: %w", dir, err)
		}
	}
	return nil
}

// Close is a no-op for FileStore as files are closed after each operation.
func (fs *FileStore) Close() error {
	return nil
}

// Ensure FileStore implements EntitlementStore
var _ EntitlementStore = (*FileStore)(nil)
