// Package cedar provides a Cedar-inspired policy-based authorization system
// for fine-grained access control in PocketBase applications.
//
// Cedar is a policy language created by AWS for defining authorization policies.
// This implementation provides a Go-native, extensible policy engine that follows
// Cedar's core concepts while integrating seamlessly with PocketBase.
//
// Example policy:
//
//	permit (
//	    principal == User::"alice",
//	    action == Action::"read",
//	    resource == Document::"doc123"
//	);
package cedar

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Effect represents the policy decision effect.
type Effect string

const (
	EffectPermit Effect = "permit"
	EffectForbid Effect = "forbid"
)

// Policy represents a Cedar-style authorization policy.
type Policy struct {
	// ID is the unique identifier for this policy.
	ID string `json:"id"`

	// Effect determines whether this policy permits or forbids the action.
	Effect Effect `json:"effect"`

	// Description provides human-readable explanation of the policy.
	Description string `json:"description,omitempty"`

	// Principal defines who the policy applies to.
	// Can be a specific entity (User::"alice") or a pattern.
	Principal *EntityMatcher `json:"principal,omitempty"`

	// Action defines what action the policy applies to.
	// Can be a specific action (Action::"read") or a pattern.
	Action *EntityMatcher `json:"action,omitempty"`

	// Resource defines what resource the policy applies to.
	// Can be a specific resource (Document::"doc123") or a pattern.
	Resource *EntityMatcher `json:"resource,omitempty"`

	// Conditions are additional constraints that must be met.
	Conditions []Condition `json:"conditions,omitempty"`

	// Priority determines evaluation order (lower = higher priority).
	Priority int `json:"priority,omitempty"`

	// Tags allow grouping and filtering policies.
	Tags []string `json:"tags,omitempty"`
}

// EntityMatcher defines how to match entities in policies.
type EntityMatcher struct {
	// Type is the entity type (e.g., "User", "Document", "Action").
	Type string `json:"type"`

	// ID is the specific entity ID to match (empty means any).
	ID string `json:"id,omitempty"`

	// Pattern is a regex pattern for matching entity IDs.
	Pattern string `json:"pattern,omitempty"`

	// In matches if the entity is a member of the specified group.
	In *EntityRef `json:"in,omitempty"`

	// compiledPattern caches the compiled regex (thread-safe via sync.Once).
	compiledPattern *regexp.Regexp
	patternOnce     sync.Once
	patternErr      error
}

// EntityRef represents a reference to a specific entity.
type EntityRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// String returns the Cedar-style string representation.
func (e *EntityRef) String() string {
	return fmt.Sprintf("%s::\"%s\"", e.Type, e.ID)
}

// Condition represents a policy condition that must be evaluated.
type Condition struct {
	// Kind is the condition type: "when" or "unless".
	Kind ConditionKind `json:"kind"`

	// Expression is the condition expression to evaluate.
	Expression string `json:"expression"`

	// Attributes maps attribute names to expected values.
	// Used for simple attribute-based conditions.
	Attributes map[string]any `json:"attributes,omitempty"`
}

// ConditionKind represents the type of condition.
type ConditionKind string

const (
	ConditionWhen   ConditionKind = "when"
	ConditionUnless ConditionKind = "unless"
)

// Matches checks if the matcher matches the given entity.
// This method is thread-safe.
func (m *EntityMatcher) Matches(entity *Entity, resolver EntityResolver) bool {
	if m == nil {
		return true // nil matcher matches everything
	}

	if entity == nil {
		return false
	}

	// Check type match
	if m.Type != "" && m.Type != "*" && m.Type != entity.Type {
		return false
	}

	// Check specific ID match
	if m.ID != "" && m.ID != entity.ID {
		return false
	}

	// Check pattern match (thread-safe compilation)
	if m.Pattern != "" {
		m.patternOnce.Do(func() {
			m.compiledPattern, m.patternErr = regexp.Compile(m.Pattern)
		})
		if m.patternErr != nil || m.compiledPattern == nil {
			return false
		}
		if !m.compiledPattern.MatchString(entity.ID) {
			return false
		}
	}

	// Check group membership
	if m.In != nil && resolver != nil {
		if !resolver.IsMemberOf(entity, m.In) {
			return false
		}
	}

	return true
}

// PolicyBuilder provides a fluent interface for building policies.
type PolicyBuilder struct {
	policy *Policy
}

// NewPolicy creates a new PolicyBuilder.
func NewPolicy(id string) *PolicyBuilder {
	return &PolicyBuilder{
		policy: &Policy{
			ID:         id,
			Effect:     EffectPermit,
			Conditions: make([]Condition, 0),
			Tags:       make([]string, 0),
		},
	}
}

// Permit sets the policy effect to permit.
func (b *PolicyBuilder) Permit() *PolicyBuilder {
	b.policy.Effect = EffectPermit
	return b
}

// Forbid sets the policy effect to forbid.
func (b *PolicyBuilder) Forbid() *PolicyBuilder {
	b.policy.Effect = EffectForbid
	return b
}

// Description sets the policy description.
func (b *PolicyBuilder) Description(desc string) *PolicyBuilder {
	b.policy.Description = desc
	return b
}

// Principal sets the principal matcher.
func (b *PolicyBuilder) Principal(entityType string, entityID ...string) *PolicyBuilder {
	b.policy.Principal = &EntityMatcher{Type: entityType}
	if len(entityID) > 0 {
		b.policy.Principal.ID = entityID[0]
	}
	return b
}

// PrincipalPattern sets a pattern-based principal matcher.
func (b *PolicyBuilder) PrincipalPattern(entityType, pattern string) *PolicyBuilder {
	b.policy.Principal = &EntityMatcher{Type: entityType, Pattern: pattern}
	return b
}

// PrincipalIn sets the principal to match members of a group.
func (b *PolicyBuilder) PrincipalIn(groupType, groupID string) *PolicyBuilder {
	b.policy.Principal = &EntityMatcher{
		In: &EntityRef{Type: groupType, ID: groupID},
	}
	return b
}

// Action sets the action matcher.
func (b *PolicyBuilder) Action(actionType string, actionID ...string) *PolicyBuilder {
	b.policy.Action = &EntityMatcher{Type: actionType}
	if len(actionID) > 0 {
		b.policy.Action.ID = actionID[0]
	}
	return b
}

// ActionPattern sets a pattern-based action matcher.
func (b *PolicyBuilder) ActionPattern(actionType, pattern string) *PolicyBuilder {
	b.policy.Action = &EntityMatcher{Type: actionType, Pattern: pattern}
	return b
}

// Resource sets the resource matcher.
func (b *PolicyBuilder) Resource(resourceType string, resourceID ...string) *PolicyBuilder {
	b.policy.Resource = &EntityMatcher{Type: resourceType}
	if len(resourceID) > 0 {
		b.policy.Resource.ID = resourceID[0]
	}
	return b
}

// ResourcePattern sets a pattern-based resource matcher.
func (b *PolicyBuilder) ResourcePattern(resourceType, pattern string) *PolicyBuilder {
	b.policy.Resource = &EntityMatcher{Type: resourceType, Pattern: pattern}
	return b
}

// ResourceIn sets the resource to match members of a group.
func (b *PolicyBuilder) ResourceIn(groupType, groupID string) *PolicyBuilder {
	b.policy.Resource = &EntityMatcher{
		In: &EntityRef{Type: groupType, ID: groupID},
	}
	return b
}

// When adds a "when" condition.
func (b *PolicyBuilder) When(expression string) *PolicyBuilder {
	b.policy.Conditions = append(b.policy.Conditions, Condition{
		Kind:       ConditionWhen,
		Expression: expression,
	})
	return b
}

// WhenAttributes adds a "when" condition with attribute checks.
func (b *PolicyBuilder) WhenAttributes(attrs map[string]any) *PolicyBuilder {
	b.policy.Conditions = append(b.policy.Conditions, Condition{
		Kind:       ConditionWhen,
		Attributes: attrs,
	})
	return b
}

// Unless adds an "unless" condition.
func (b *PolicyBuilder) Unless(expression string) *PolicyBuilder {
	b.policy.Conditions = append(b.policy.Conditions, Condition{
		Kind:       ConditionUnless,
		Expression: expression,
	})
	return b
}

// Priority sets the policy priority.
func (b *PolicyBuilder) Priority(p int) *PolicyBuilder {
	b.policy.Priority = p
	return b
}

// Tags adds tags to the policy.
func (b *PolicyBuilder) Tags(tags ...string) *PolicyBuilder {
	b.policy.Tags = append(b.policy.Tags, tags...)
	return b
}

// Build returns the constructed policy.
func (b *PolicyBuilder) Build() *Policy {
	return b.policy
}

// ParsePolicy parses a policy from JSON.
func ParsePolicy(data []byte) (*Policy, error) {
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}
	return &policy, nil
}

// ParsePolicies parses multiple policies from JSON array.
func ParsePolicies(data []byte) ([]*Policy, error) {
	var policies []*Policy
	if err := json.Unmarshal(data, &policies); err != nil {
		return nil, fmt.Errorf("failed to parse policies: %w", err)
	}
	return policies, nil
}

// ParseCedarPolicy parses a policy from Cedar-like syntax.
// Supports basic Cedar syntax:
//
//	permit(principal == User::"alice", action == Action::"read", resource == Document::"*");
func ParseCedarPolicy(id, cedarSyntax string) (*Policy, error) {
	cedarSyntax = strings.TrimSpace(cedarSyntax)

	builder := NewPolicy(id)

	// Determine effect
	if strings.HasPrefix(cedarSyntax, "permit") {
		builder.Permit()
		cedarSyntax = strings.TrimPrefix(cedarSyntax, "permit")
	} else if strings.HasPrefix(cedarSyntax, "forbid") {
		builder.Forbid()
		cedarSyntax = strings.TrimPrefix(cedarSyntax, "forbid")
	} else {
		return nil, fmt.Errorf("policy must start with 'permit' or 'forbid'")
	}

	// Extract content between parentheses
	cedarSyntax = strings.TrimSpace(cedarSyntax)
	if !strings.HasPrefix(cedarSyntax, "(") {
		return nil, fmt.Errorf("expected '(' after effect")
	}

	// Find matching closing paren
	depth := 0
	endIdx := -1
	for i, c := range cedarSyntax {
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
			if depth == 0 {
				endIdx = i
				break
			}
		}
	}
	if endIdx == -1 {
		return nil, fmt.Errorf("unmatched parentheses")
	}

	content := cedarSyntax[1:endIdx]

	// Parse clauses (principal, action, resource)
	entityPattern := regexp.MustCompile(`(\w+)\s*==\s*(\w+)::\"([^\"]*)\"|(\w+)\s+in\s+(\w+)::\"([^\"]*)\"`)
	matches := entityPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if match[1] != "" {
			// Entity equality match
			clause := strings.ToLower(match[1])
			entityType := match[2]
			entityID := match[3]

			switch clause {
			case "principal":
				if entityID == "*" {
					builder.Principal(entityType)
				} else {
					builder.Principal(entityType, entityID)
				}
			case "action":
				if entityID == "*" {
					builder.Action(entityType)
				} else {
					builder.Action(entityType, entityID)
				}
			case "resource":
				if entityID == "*" {
					builder.Resource(entityType)
				} else {
					builder.Resource(entityType, entityID)
				}
			}
		} else if match[4] != "" {
			// Group membership match
			clause := strings.ToLower(match[4])
			groupType := match[5]
			groupID := match[6]

			switch clause {
			case "principal":
				builder.PrincipalIn(groupType, groupID)
			case "resource":
				builder.ResourceIn(groupType, groupID)
			}
		}
	}

	return builder.Build(), nil
}
