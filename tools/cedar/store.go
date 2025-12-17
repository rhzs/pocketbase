package cedar

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// PolicyStore provides an interface for policy storage.
type PolicyStore interface {
	// Add adds or updates a policy.
	Add(policy *Policy) error

	// Remove removes a policy by ID.
	Remove(id string) error

	// Get retrieves a policy by ID.
	Get(id string) (*Policy, error)

	// List returns all policies.
	List() ([]*Policy, error)

	// ListByTags returns policies matching any of the specified tags.
	ListByTags(tags ...string) ([]*Policy, error)

	// Clear removes all policies.
	Clear() error
}

// InMemoryPolicyStore provides an in-memory policy store.
type InMemoryPolicyStore struct {
	policies map[string]*Policy
	mu       sync.RWMutex
}

// NewInMemoryPolicyStore creates a new in-memory policy store.
func NewInMemoryPolicyStore() *InMemoryPolicyStore {
	return &InMemoryPolicyStore{
		policies: make(map[string]*Policy),
	}
}

// Add adds or updates a policy.
func (s *InMemoryPolicyStore) Add(policy *Policy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	if policy.ID == "" {
		return fmt.Errorf("policy ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[policy.ID] = policy
	return nil
}

// Remove removes a policy by ID.
func (s *InMemoryPolicyStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, id)
	return nil
}

// Get retrieves a policy by ID.
func (s *InMemoryPolicyStore) Get(id string) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	policy, ok := s.policies[id]
	if !ok {
		return nil, nil
	}
	return policy, nil
}

// List returns all policies.
func (s *InMemoryPolicyStore) List() ([]*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Policy, 0, len(s.policies))
	for _, p := range s.policies {
		result = append(result, p)
	}
	return result, nil
}

// ListByTags returns policies matching any of the specified tags.
func (s *InMemoryPolicyStore) ListByTags(tags ...string) ([]*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tagSet := make(map[string]bool)
	for _, t := range tags {
		tagSet[t] = true
	}

	var result []*Policy
	for _, p := range s.policies {
		for _, t := range p.Tags {
			if tagSet[t] {
				result = append(result, p)
				break
			}
		}
	}
	return result, nil
}

// Clear removes all policies.
func (s *InMemoryPolicyStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies = make(map[string]*Policy)
	return nil
}

// FilePolicyStore provides a file-based policy store.
type FilePolicyStore struct {
	dir   string
	cache *InMemoryPolicyStore
	mu    sync.RWMutex
}

// NewFilePolicyStore creates a new file-based policy store.
func NewFilePolicyStore(dir string) (*FilePolicyStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create policy directory: %w", err)
	}

	store := &FilePolicyStore{
		dir:   dir,
		cache: NewInMemoryPolicyStore(),
	}

	// Load existing policies
	if err := store.loadAll(); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *FilePolicyStore) policyPath(id string) string {
	return filepath.Join(s.dir, id+".json")
}

func (s *FilePolicyStore) loadAll() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("failed to read policy directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			continue
		}

		policy, err := ParsePolicy(data)
		if err != nil {
			continue
		}

		s.cache.Add(policy)
	}

	return nil
}

// Add adds or updates a policy.
func (s *FilePolicyStore) Add(policy *Policy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	if policy.ID == "" {
		return fmt.Errorf("policy ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	if err := os.WriteFile(s.policyPath(policy.ID), data, 0o644); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	return s.cache.Add(policy)
}

// Remove removes a policy by ID.
func (s *FilePolicyStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	os.Remove(s.policyPath(id))
	return s.cache.Remove(id)
}

// Get retrieves a policy by ID.
func (s *FilePolicyStore) Get(id string) (*Policy, error) {
	return s.cache.Get(id)
}

// List returns all policies.
func (s *FilePolicyStore) List() ([]*Policy, error) {
	return s.cache.List()
}

// ListByTags returns policies matching any of the specified tags.
func (s *FilePolicyStore) ListByTags(tags ...string) ([]*Policy, error) {
	return s.cache.ListByTags(tags...)
}

// Clear removes all policies.
func (s *FilePolicyStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, _ := os.ReadDir(s.dir)
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			os.Remove(filepath.Join(s.dir, entry.Name()))
		}
	}

	return s.cache.Clear()
}

// Reload reloads policies from disk.
func (s *FilePolicyStore) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache.Clear()
	return s.loadAll()
}

// PolicySet represents a collection of policies that can be evaluated together.
type PolicySet struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Policies    []*Policy `json:"policies"`
}

// NewPolicySet creates a new policy set.
func NewPolicySet(id, name string) *PolicySet {
	return &PolicySet{
		ID:       id,
		Name:     name,
		Policies: make([]*Policy, 0),
	}
}

// Add adds a policy to the set.
func (ps *PolicySet) Add(policy *Policy) *PolicySet {
	ps.Policies = append(ps.Policies, policy)
	return ps
}

// ToEvaluator creates an evaluator from this policy set.
func (ps *PolicySet) ToEvaluator(resolver EntityResolver) *Evaluator {
	e := NewEvaluator(resolver)
	e.AddPolicies(ps.Policies...)
	return e
}

// LoadPoliciesFromJSON loads policies from a JSON file.
func LoadPoliciesFromJSON(path string) ([]*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	return ParsePolicies(data)
}

// SavePoliciesToJSON saves policies to a JSON file.
func SavePoliciesToJSON(path string, policies []*Policy) error {
	data, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal policies: %w", err)
	}

	return os.WriteFile(path, data, 0o644)
}
