package cedar

import (
	"fmt"
	"sync"
	"testing"
)

func TestNewPolicy(t *testing.T) {
	t.Parallel()

	policy := NewPolicy("test-policy").
		Permit().
		Description("Test policy").
		Principal("User", "alice").
		Action("Action", "read").
		Resource("Document", "doc123").
		Build()

	if policy.ID != "test-policy" {
		t.Errorf("expected ID 'test-policy', got '%s'", policy.ID)
	}
	if policy.Effect != EffectPermit {
		t.Errorf("expected effect 'permit', got '%s'", policy.Effect)
	}
	if policy.Principal.Type != "User" || policy.Principal.ID != "alice" {
		t.Error("principal mismatch")
	}
	if policy.Action.Type != "Action" || policy.Action.ID != "read" {
		t.Error("action mismatch")
	}
	if policy.Resource.Type != "Document" || policy.Resource.ID != "doc123" {
		t.Error("resource mismatch")
	}
}

func TestEntityMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		matcher  *EntityMatcher
		entity   *Entity
		expected bool
	}{
		{
			name:     "nil matcher matches everything",
			matcher:  nil,
			entity:   NewEntity("User", "alice"),
			expected: true,
		},
		{
			name:     "exact type and ID match",
			matcher:  &EntityMatcher{Type: "User", ID: "alice"},
			entity:   NewEntity("User", "alice"),
			expected: true,
		},
		{
			name:     "type match only",
			matcher:  &EntityMatcher{Type: "User"},
			entity:   NewEntity("User", "bob"),
			expected: true,
		},
		{
			name:     "type mismatch",
			matcher:  &EntityMatcher{Type: "Admin"},
			entity:   NewEntity("User", "alice"),
			expected: false,
		},
		{
			name:     "ID mismatch",
			matcher:  &EntityMatcher{Type: "User", ID: "bob"},
			entity:   NewEntity("User", "alice"),
			expected: false,
		},
		{
			name:     "pattern match",
			matcher:  &EntityMatcher{Type: "User", Pattern: "^admin-.*"},
			entity:   NewEntity("User", "admin-alice"),
			expected: true,
		},
		{
			name:     "pattern no match",
			matcher:  &EntityMatcher{Type: "User", Pattern: "^admin-.*"},
			entity:   NewEntity("User", "alice"),
			expected: false,
		},
		{
			name:     "wildcard type",
			matcher:  &EntityMatcher{Type: "*"},
			entity:   NewEntity("User", "alice"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.matcher.Matches(tt.entity, nil)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestEvaluatorBasic(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	// Add a permit policy
	evaluator.AddPolicy(
		NewPolicy("allow-alice-read").
			Permit().
			Principal("User", "alice").
			Action("Action", "read").
			Resource("Document", "doc123").
			Build(),
	)

	tests := []struct {
		name      string
		principal *Entity
		action    *Entity
		resource  *Entity
		expected  Decision
	}{
		{
			name:      "matching request - allowed",
			principal: NewEntity("User", "alice"),
			action:    NewEntity("Action", "read"),
			resource:  NewEntity("Document", "doc123"),
			expected:  DecisionAllow,
		},
		{
			name:      "wrong principal - denied",
			principal: NewEntity("User", "bob"),
			action:    NewEntity("Action", "read"),
			resource:  NewEntity("Document", "doc123"),
			expected:  DecisionDeny,
		},
		{
			name:      "wrong action - denied",
			principal: NewEntity("User", "alice"),
			action:    NewEntity("Action", "write"),
			resource:  NewEntity("Document", "doc123"),
			expected:  DecisionDeny,
		},
		{
			name:      "wrong resource - denied",
			principal: NewEntity("User", "alice"),
			action:    NewEntity("Action", "read"),
			resource:  NewEntity("Document", "other"),
			expected:  DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := NewRequest(tt.principal, tt.action, tt.resource)
			response := evaluator.IsAuthorized(req)
			if response.Decision != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, response.Decision)
			}
		})
	}
}

func TestEvaluatorForbidTakesPrecedence(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	// Add a permit policy
	evaluator.AddPolicy(
		NewPolicy("allow-all").
			Permit().
			Build(),
	)

	// Add a forbid policy for specific user
	evaluator.AddPolicy(
		NewPolicy("forbid-bob").
			Forbid().
			Principal("User", "bob").
			Build(),
	)

	// Alice should be allowed
	req := NewRequest(
		NewEntity("User", "alice"),
		NewEntity("Action", "read"),
		NewEntity("Document", "doc"),
	)
	response := evaluator.IsAuthorized(req)
	if !response.IsAllowed() {
		t.Error("expected alice to be allowed")
	}

	// Bob should be denied (forbid takes precedence)
	req = NewRequest(
		NewEntity("User", "bob"),
		NewEntity("Action", "read"),
		NewEntity("Document", "doc"),
	)
	response = evaluator.IsAuthorized(req)
	if response.IsAllowed() {
		t.Error("expected bob to be denied")
	}
}

func TestEvaluatorConditions(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	// Policy with "when" condition
	evaluator.AddPolicy(
		NewPolicy("allow-verified").
			Permit().
			WhenAttributes(map[string]any{"principal.verified": true}).
			Build(),
	)

	// Verified user
	principal := NewEntity("User", "alice")
	principal.SetAttribute("verified", true)

	req := NewRequest(principal, NewEntity("Action", "read"), NewEntity("Doc", "1"))
	response := evaluator.IsAuthorized(req)
	if !response.IsAllowed() {
		t.Error("expected verified user to be allowed")
	}

	// Unverified user
	unverified := NewEntity("User", "bob")
	unverified.SetAttribute("verified", false)

	req = NewRequest(unverified, NewEntity("Action", "read"), NewEntity("Doc", "1"))
	response = evaluator.IsAuthorized(req)
	if response.IsAllowed() {
		t.Error("expected unverified user to be denied")
	}
}

func TestEvaluatorExpressionConditions(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	evaluator.AddPolicy(
		NewPolicy("allow-if-count-gt-5").
			Permit().
			When("context.count > 5").
			Build(),
	)

	tests := []struct {
		count    int
		expected bool
	}{
		{count: 10, expected: true},
		{count: 5, expected: false},
		{count: 3, expected: false},
	}

	for _, tt := range tests {
		req := NewRequest(
			NewEntity("User", "alice"),
			NewEntity("Action", "read"),
			NewEntity("Doc", "1"),
		)
		req.WithContext("count", tt.count)

		response := evaluator.IsAuthorized(req)
		if response.IsAllowed() != tt.expected {
			t.Errorf("count=%d: expected %v, got %v", tt.count, tt.expected, response.IsAllowed())
		}
	}
}

func TestEntityHierarchy(t *testing.T) {
	t.Parallel()

	store := NewInMemoryEntityStore()

	// Create role hierarchy
	adminRole := NewEntity("Role", "admin")
	editorRole := NewEntity("Role", "editor")
	viewerRole := NewEntity("Role", "viewer")

	// Editor inherits from viewer
	editorRole.AddParent("Role", "viewer")

	// Admin inherits from editor
	adminRole.AddParent("Role", "editor")

	store.Add(adminRole)
	store.Add(editorRole)
	store.Add(viewerRole)

	// Create user with admin role
	alice := NewEntity("User", "alice")
	alice.AddParent("Role", "admin")
	store.Add(alice)

	// Test membership
	if !store.IsMemberOf(alice, &EntityRef{Type: "Role", ID: "admin"}) {
		t.Error("alice should be member of admin")
	}
	if !store.IsMemberOf(alice, &EntityRef{Type: "Role", ID: "editor"}) {
		t.Error("alice should be member of editor (transitive)")
	}
	if !store.IsMemberOf(alice, &EntityRef{Type: "Role", ID: "viewer"}) {
		t.Error("alice should be member of viewer (transitive)")
	}
}

func TestParseCedarPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		syntax   string
		expected *Policy
		hasError bool
	}{
		{
			name:   "simple permit",
			syntax: `permit(principal == User::"alice", action == Action::"read", resource == Document::"doc1");`,
			expected: &Policy{
				ID:        "test",
				Effect:    EffectPermit,
				Principal: &EntityMatcher{Type: "User", ID: "alice"},
				Action:    &EntityMatcher{Type: "Action", ID: "read"},
				Resource:  &EntityMatcher{Type: "Document", ID: "doc1"},
			},
		},
		{
			name:   "forbid policy",
			syntax: `forbid(principal == User::"bob", action == Action::"delete", resource == Document::"*");`,
			expected: &Policy{
				ID:        "test",
				Effect:    EffectForbid,
				Principal: &EntityMatcher{Type: "User", ID: "bob"},
				Action:    &EntityMatcher{Type: "Action", ID: "delete"},
				Resource:  &EntityMatcher{Type: "Document"},
			},
		},
		{
			name:     "invalid - missing effect",
			syntax:   `(principal == User::"alice");`,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := ParseCedarPolicy("test", tt.syntax)

			if tt.hasError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if policy.Effect != tt.expected.Effect {
				t.Errorf("expected effect %v, got %v", tt.expected.Effect, policy.Effect)
			}
		})
	}
}

func TestPolicyStore(t *testing.T) {
	t.Parallel()

	store := NewInMemoryPolicyStore()

	policy1 := NewPolicy("policy-1").
		Permit().
		Tags("api", "read").
		Build()

	policy2 := NewPolicy("policy-2").
		Permit().
		Tags("api", "write").
		Build()

	// Add policies
	store.Add(policy1)
	store.Add(policy2)

	// List all
	all, _ := store.List()
	if len(all) != 2 {
		t.Errorf("expected 2 policies, got %d", len(all))
	}

	// Get by ID
	p, _ := store.Get("policy-1")
	if p == nil || p.ID != "policy-1" {
		t.Error("failed to get policy by ID")
	}

	// List by tags
	apiPolicies, _ := store.ListByTags("api")
	if len(apiPolicies) != 2 {
		t.Errorf("expected 2 api policies, got %d", len(apiPolicies))
	}

	readPolicies, _ := store.ListByTags("read")
	if len(readPolicies) != 1 {
		t.Errorf("expected 1 read policy, got %d", len(readPolicies))
	}

	// Remove
	store.Remove("policy-1")
	all, _ = store.List()
	if len(all) != 1 {
		t.Errorf("expected 1 policy after removal, got %d", len(all))
	}

	// Clear
	store.Clear()
	all, _ = store.List()
	if len(all) != 0 {
		t.Error("expected empty store after clear")
	}
}

func TestQuickEval(t *testing.T) {
	t.Parallel()

	policies := []*Policy{
		NewPolicy("allow-alice").
			Permit().
			Principal("User", "alice").
			Build(),
	}

	// Alice should be allowed
	allowed := QuickEval(
		policies,
		NewEntity("User", "alice"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)
	if !allowed {
		t.Error("expected alice to be allowed")
	}

	// Bob should be denied
	allowed = QuickEval(
		policies,
		NewEntity("User", "bob"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)
	if allowed {
		t.Error("expected bob to be denied")
	}
}

func TestParsePoliciesJSON(t *testing.T) {
	t.Parallel()

	jsonData := `[
		{
			"id": "policy-1",
			"effect": "permit",
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "read"}
		},
		{
			"id": "policy-2",
			"effect": "forbid",
			"principal": {"type": "User", "id": "bob"}
		}
	]`

	policies, err := ParsePolicies([]byte(jsonData))
	if err != nil {
		t.Fatalf("failed to parse policies: %v", err)
	}

	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}

	if policies[0].ID != "policy-1" || policies[0].Effect != EffectPermit {
		t.Error("policy-1 mismatch")
	}

	if policies[1].ID != "policy-2" || policies[1].Effect != EffectForbid {
		t.Error("policy-2 mismatch")
	}
}

func TestEvaluatorDiagnostics(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	evaluator.AddPolicy(
		NewPolicy("allow-alice").
			Permit().
			Principal("User", "alice").
			Build(),
	)

	req := NewRequest(
		NewEntity("User", "alice"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)

	response := evaluator.IsAuthorized(req)

	if response.Diagnostics == nil {
		t.Fatal("expected diagnostics")
	}

	if len(response.Diagnostics.DeterminingPolicies) != 1 {
		t.Errorf("expected 1 determining policy, got %d", len(response.Diagnostics.DeterminingPolicies))
	}

	if response.Diagnostics.DeterminingPolicies[0] != "allow-alice" {
		t.Errorf("expected 'allow-alice' in determining policies")
	}
}

func TestBooleanExpressions(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	evaluator.AddPolicy(
		NewPolicy("complex-condition").
			Permit().
			When("context.a == 1 && context.b == 2").
			Build(),
	)

	// Both conditions true
	req := NewRequest(
		NewEntity("User", "test"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)
	req.WithContext("a", 1).WithContext("b", 2)

	response := evaluator.IsAuthorized(req)
	if !response.IsAllowed() {
		t.Error("expected allowed when both conditions true")
	}

	// One condition false
	req2 := NewRequest(
		NewEntity("User", "test"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)
	req2.WithContext("a", 1).WithContext("b", 3)

	response2 := evaluator.IsAuthorized(req2)
	if response2.IsAllowed() {
		t.Error("expected denied when one condition false")
	}
}

func TestOrExpressions(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	evaluator.AddPolicy(
		NewPolicy("or-condition").
			Permit().
			When("context.role == 'admin' || context.role == 'editor'").
			Build(),
	)

	// Admin role
	req := NewRequest(
		NewEntity("User", "test"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)
	req.WithContext("role", "admin")

	if !evaluator.IsAuthorized(req).IsAllowed() {
		t.Error("expected allowed for admin")
	}

	// Editor role
	req2 := NewRequest(
		NewEntity("User", "test"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)
	req2.WithContext("role", "editor")

	if !evaluator.IsAuthorized(req2).IsAllowed() {
		t.Error("expected allowed for editor")
	}

	// Viewer role
	req3 := NewRequest(
		NewEntity("User", "test"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)
	req3.WithContext("role", "viewer")

	if evaluator.IsAuthorized(req3).IsAllowed() {
		t.Error("expected denied for viewer")
	}
}

func TestConcurrentPolicyEvaluation(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	// Add multiple policies
	for i := 0; i < 100; i++ {
		evaluator.AddPolicy(
			NewPolicy(fmt.Sprintf("policy-%d", i)).
				Permit().
				Principal("User", fmt.Sprintf("user-%d", i)).
				Build(),
		)
	}

	// Concurrent evaluations
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := NewRequest(
				NewEntity("User", fmt.Sprintf("user-%d", idx)),
				NewEntity("Action", "read"),
				NewEntity("Doc", "1"),
			)
			response := evaluator.IsAuthorized(req)
			if !response.IsAllowed() {
				t.Errorf("user-%d should be allowed", idx)
			}
		}(i)
	}
	wg.Wait()
}

func TestIPRangeCondition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ip       string
		cidr     string
		expected bool
	}{
		{"ip in range", "192.168.1.100", "192.168.1.0/24", true},
		{"ip not in range", "192.168.2.100", "192.168.1.0/24", false},
		{"exact ip", "10.0.0.1", "10.0.0.1/32", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{
				Context: map[string]any{"ip": tt.ip},
			}
			result, err := IPRangeCondition(
				fmt.Sprintf(`ip_in_range(context.ip, "%s")`, tt.cidr),
				req,
				nil,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestPolicyIndex(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	// Add policies for different resource types
	evaluator.AddPolicy(
		NewPolicy("doc-read").
			Permit().
			Resource("Document", "doc1").
			Build(),
	)
	evaluator.AddPolicy(
		NewPolicy("post-read").
			Permit().
			Resource("Post", "post1").
			Build(),
	)
	evaluator.AddPolicy(
		NewPolicy("wildcard").
			Permit().
			Principal("User", "admin").
			Build(),
	)

	// Test that index returns correct policies
	reqDoc := NewRequest(
		NewEntity("User", "test"),
		NewEntity("Action", "read"),
		NewEntity("Document", "doc1"),
	)
	respDoc := evaluator.IsAuthorized(reqDoc)
	if !respDoc.IsAllowed() {
		t.Error("expected doc request allowed")
	}

	reqPost := NewRequest(
		NewEntity("User", "test"),
		NewEntity("Action", "read"),
		NewEntity("Post", "post1"),
	)
	respPost := evaluator.IsAuthorized(reqPost)
	if !respPost.IsAllowed() {
		t.Error("expected post request allowed")
	}

	// Admin should be allowed for anything via wildcard
	reqAdmin := NewRequest(
		NewEntity("User", "admin"),
		NewEntity("Action", "delete"),
		NewEntity("Other", "x"),
	)
	respAdmin := evaluator.IsAuthorized(reqAdmin)
	if !respAdmin.IsAllowed() {
		t.Error("expected admin wildcard allowed")
	}
}

func TestNilRequestHandling(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)
	evaluator.AddPolicy(NewPolicy("test").Permit().Build())

	resp := evaluator.IsAuthorized(nil)
	if resp.IsAllowed() {
		t.Error("expected nil request to be denied")
	}
	if resp.Diagnostics.Reason != "request is nil" {
		t.Errorf("unexpected reason: %s", resp.Diagnostics.Reason)
	}
}

func TestUnlessCondition(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	evaluator.AddPolicy(
		NewPolicy("unless-blocked").
			Permit().
			Unless("context.blocked == true").
			Build(),
	)

	// Not blocked
	req := NewRequest(
		NewEntity("User", "test"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)
	req.WithContext("blocked", false)

	if !evaluator.IsAuthorized(req).IsAllowed() {
		t.Error("expected allowed when not blocked")
	}

	// Blocked
	req2 := NewRequest(
		NewEntity("User", "test"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)
	req2.WithContext("blocked", true)

	if evaluator.IsAuthorized(req2).IsAllowed() {
		t.Error("expected denied when blocked")
	}
}

func TestContainsOperator(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	evaluator.AddPolicy(
		NewPolicy("has-role").
			Permit().
			When("context.roles contains 'admin'").
			Build(),
	)

	// Has admin role
	req := NewRequest(
		NewEntity("User", "test"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)
	req.WithContext("roles", []string{"user", "admin"})

	if !evaluator.IsAuthorized(req).IsAllowed() {
		t.Error("expected allowed when has admin role")
	}

	// Does not have admin role
	req2 := NewRequest(
		NewEntity("User", "test"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)
	req2.WithContext("roles", []string{"user", "editor"})

	if evaluator.IsAuthorized(req2).IsAllowed() {
		t.Error("expected denied when no admin role")
	}
}

func TestPolicyRemoveAndReplace(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	// Add specific permit policy for alice
	evaluator.AddPolicy(
		NewPolicy("alice-permit").
			Permit().
			Principal("User", "alice").
			Build(),
	)

	reqAlice := NewRequest(
		NewEntity("User", "alice"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)

	reqBob := NewRequest(
		NewEntity("User", "bob"),
		NewEntity("Action", "read"),
		NewEntity("Doc", "1"),
	)

	// Alice should be allowed
	if !evaluator.IsAuthorized(reqAlice).IsAllowed() {
		t.Error("expected alice allowed initially")
	}

	// Bob should be denied (default deny)
	if evaluator.IsAuthorized(reqBob).IsAllowed() {
		t.Error("expected bob denied (no matching policy)")
	}

	// Replace with forbid for alice
	evaluator.AddPolicy(
		NewPolicy("alice-permit").
			Forbid().
			Principal("User", "alice").
			Build(),
	)

	// Alice should now be denied
	if evaluator.IsAuthorized(reqAlice).IsAllowed() {
		t.Error("expected alice denied after replacement with forbid")
	}

	// Remove policy
	evaluator.RemovePolicy("alice-permit")

	// Alice should be denied (default deny, no policies)
	if evaluator.IsAuthorized(reqAlice).IsAllowed() {
		t.Error("expected alice denied after removal (default deny)")
	}

	// Verify policy count
	policies := evaluator.ListPolicies()
	if len(policies) != 0 {
		t.Errorf("expected 0 policies after removal, got %d", len(policies))
	}
}
