package cedar

import (
	"fmt"
	"sync"
)

// Entity represents an entity in the Cedar authorization model.
// Entities can be principals (users), actions, or resources.
type Entity struct {
	// Type is the entity type (e.g., "User", "Document", "Action").
	Type string `json:"type"`

	// ID is the unique identifier within the type.
	ID string `json:"id"`

	// Attributes are key-value pairs associated with the entity.
	Attributes map[string]any `json:"attributes,omitempty"`

	// Parents are the groups/roles this entity belongs to.
	Parents []*EntityRef `json:"parents,omitempty"`
}

// NewEntity creates a new entity with the given type and ID.
func NewEntity(entityType, id string) *Entity {
	return &Entity{
		Type:       entityType,
		ID:         id,
		Attributes: make(map[string]any),
		Parents:    make([]*EntityRef, 0),
	}
}

// Ref returns an EntityRef for this entity.
func (e *Entity) Ref() *EntityRef {
	return &EntityRef{Type: e.Type, ID: e.ID}
}

// String returns the Cedar-style string representation.
func (e *Entity) String() string {
	return fmt.Sprintf("%s::\"%s\"", e.Type, e.ID)
}

// SetAttribute sets an attribute on the entity.
func (e *Entity) SetAttribute(key string, value any) *Entity {
	if e.Attributes == nil {
		e.Attributes = make(map[string]any)
	}
	e.Attributes[key] = value
	return e
}

// GetAttribute gets an attribute from the entity.
func (e *Entity) GetAttribute(key string) (any, bool) {
	if e.Attributes == nil {
		return nil, false
	}
	v, ok := e.Attributes[key]
	return v, ok
}

// AddParent adds a parent group to the entity.
func (e *Entity) AddParent(parentType, parentID string) *Entity {
	e.Parents = append(e.Parents, &EntityRef{Type: parentType, ID: parentID})
	return e
}

// EntityResolver provides entity hierarchy resolution for group membership checks.
type EntityResolver interface {
	// GetEntity retrieves an entity by type and ID.
	GetEntity(entityType, id string) (*Entity, error)

	// GetParents returns all parent groups of an entity.
	GetParents(entity *Entity) ([]*EntityRef, error)

	// IsMemberOf checks if an entity is a direct or transitive member of a group.
	IsMemberOf(entity *Entity, group *EntityRef) bool
}

// EntityStore provides storage for entities.
type EntityStore interface {
	EntityResolver

	// Add adds an entity to the store.
	Add(entity *Entity) error

	// Remove removes an entity from the store.
	Remove(entityType, id string) error

	// List lists all entities of a given type.
	List(entityType string) ([]*Entity, error)
}

// InMemoryEntityStore provides a thread-safe in-memory entity store.
type InMemoryEntityStore struct {
	entities map[string]*Entity
	mu       sync.RWMutex
}

// NewInMemoryEntityStore creates a new in-memory entity store.
func NewInMemoryEntityStore() *InMemoryEntityStore {
	return &InMemoryEntityStore{
		entities: make(map[string]*Entity),
	}
}

func (s *InMemoryEntityStore) key(entityType, id string) string {
	return entityType + "::" + id
}

// Add adds an entity to the store.
func (s *InMemoryEntityStore) Add(entity *Entity) error {
	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entities[s.key(entity.Type, entity.ID)] = entity
	return nil
}

// Remove removes an entity from the store.
func (s *InMemoryEntityStore) Remove(entityType, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entities, s.key(entityType, id))
	return nil
}

// GetEntity retrieves an entity by type and ID.
func (s *InMemoryEntityStore) GetEntity(entityType, id string) (*Entity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entity, ok := s.entities[s.key(entityType, id)]
	if !ok {
		return nil, nil
	}
	return entity, nil
}

// GetParents returns all parent groups of an entity.
func (s *InMemoryEntityStore) GetParents(entity *Entity) ([]*EntityRef, error) {
	if entity == nil {
		return nil, nil
	}
	return entity.Parents, nil
}

// IsMemberOf checks if an entity is a direct or transitive member of a group.
func (s *InMemoryEntityStore) IsMemberOf(entity *Entity, group *EntityRef) bool {
	if entity == nil || group == nil {
		return false
	}

	// Check direct match
	if entity.Type == group.Type && entity.ID == group.ID {
		return true
	}

	// Check direct parents
	s.mu.RLock()
	defer s.mu.RUnlock()
	visited := make(map[string]bool)
	return s.isMemberOfRecursive(entity, group, visited)
}

// isMemberOfRecursive is internal - assumes lock is held
func (s *InMemoryEntityStore) isMemberOfRecursive(entity *Entity, target *EntityRef, visited map[string]bool) bool {
	key := s.key(entity.Type, entity.ID)
	if visited[key] {
		return false
	}
	visited[key] = true

	for _, parent := range entity.Parents {
		if parent.Type == target.Type && parent.ID == target.ID {
			return true
		}

		// Recursively check parent's parents
		parentEntity := s.entities[s.key(parent.Type, parent.ID)]
		if parentEntity != nil {
			if s.isMemberOfRecursive(parentEntity, target, visited) {
				return true
			}
		}
	}

	return false
}

// List lists all entities of a given type.
func (s *InMemoryEntityStore) List(entityType string) ([]*Entity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Entity
	for _, entity := range s.entities {
		if entityType == "" || entity.Type == entityType {
			result = append(result, entity)
		}
	}
	return result, nil
}

// Request represents an authorization request.
type Request struct {
	// Principal is the entity making the request.
	Principal *Entity `json:"principal"`

	// Action is the action being requested.
	Action *Entity `json:"action"`

	// Resource is the resource being accessed.
	Resource *Entity `json:"resource"`

	// Context provides additional context for evaluation.
	Context map[string]any `json:"context,omitempty"`
}

// NewRequest creates a new authorization request.
func NewRequest(principal, action, resource *Entity) *Request {
	return &Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   make(map[string]any),
	}
}

// WithContext sets context data on the request.
func (r *Request) WithContext(key string, value any) *Request {
	if r.Context == nil {
		r.Context = make(map[string]any)
	}
	r.Context[key] = value
	return r
}

// Response represents an authorization decision.
type Response struct {
	// Decision is the authorization decision (Allow or Deny).
	Decision Decision `json:"decision"`

	// Diagnostics provides details about policy evaluation.
	Diagnostics *Diagnostics `json:"diagnostics,omitempty"`
}

// Decision represents the authorization decision.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// IsAllowed returns true if the decision is Allow.
func (r *Response) IsAllowed() bool {
	return r.Decision == DecisionAllow
}

// Diagnostics provides details about policy evaluation.
type Diagnostics struct {
	// Reason provides human-readable explanation.
	Reason string `json:"reason,omitempty"`

	// DeterminingPolicies lists policy IDs that contributed to the decision.
	DeterminingPolicies []string `json:"determining_policies,omitempty"`

	// Errors contains any evaluation errors.
	Errors []string `json:"errors,omitempty"`
}
