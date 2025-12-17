// Package main demonstrates Cedar policy-based authorization in PocketBase.
//
// This example shows how to:
// - Define policies using the fluent builder API
// - Define policies using Cedar-like syntax
// - Define policies using JSON
// - Apply policies as middleware
// - Create custom entity resolvers for role-based access
// - Handle policy evaluation results
//
// Run: go run main.go serve
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/cedar"
	"github.com/pocketbase/pocketbase/tools/hook"
)

func main() {
	app := pocketbase.New()

	// ============================================================
	// EXAMPLE 1: Simple policies using the fluent builder API
	// ============================================================
	simpleEvaluator := cedar.NewEvaluator(nil)

	// Allow authenticated users to read posts
	simpleEvaluator.AddPolicy(
		cedar.NewPolicy("allow-read-posts").
			Permit().
			Description("Allow any authenticated user to read posts").
			Action("Action", "GET").
			Resource("Collection", "posts").
			Build(),
	)

	// Allow users to update their own posts (using condition)
	simpleEvaluator.AddPolicy(
		cedar.NewPolicy("allow-owner-update-posts").
			Permit().
			Description("Allow users to update their own posts").
			Action("Action", "PATCH").
			Resource("Collection", "posts").
			When("principal.id == resource.author").
			Build(),
	)

	// Forbid anonymous users from creating posts
	simpleEvaluator.AddPolicy(
		cedar.NewPolicy("deny-anonymous-create").
			Forbid().
			Description("Deny anonymous users from creating posts").
			Principal("User", "anonymous").
			Action("Action", "POST").
			Resource("Collection", "posts").
			Build(),
	)

	// ============================================================
	// EXAMPLE 2: Role-based access control with entity hierarchy
	// ============================================================
	entityStore := cedar.NewInMemoryEntityStore()

	// Define roles
	adminRole := cedar.NewEntity("Role", "admin")
	editorRole := cedar.NewEntity("Role", "editor")
	viewerRole := cedar.NewEntity("Role", "viewer")

	// Add roles to entity store
	entityStore.Add(adminRole)
	entityStore.Add(editorRole)
	entityStore.Add(viewerRole)

	// Create evaluator with entity resolver
	rbacEvaluator := cedar.NewEvaluator(entityStore)

	// Admins can do everything
	rbacEvaluator.AddPolicy(
		cedar.NewPolicy("admin-full-access").
			Permit().
			Description("Admins have full access").
			PrincipalIn("Role", "admin").
			Build(),
	)

	// Editors can read and update
	rbacEvaluator.AddPolicy(
		cedar.NewPolicy("editor-read-update").
			Permit().
			Description("Editors can read and update").
			PrincipalIn("Role", "editor").
			ActionPattern("Action", "^(GET|PATCH)$").
			Build(),
	)

	// Viewers can only read
	rbacEvaluator.AddPolicy(
		cedar.NewPolicy("viewer-read-only").
			Permit().
			Description("Viewers can only read").
			PrincipalIn("Role", "viewer").
			Action("Action", "GET").
			Build(),
	)

	// ============================================================
	// EXAMPLE 3: Policies from Cedar-like syntax
	// ============================================================
	syntaxEvaluator := cedar.NewEvaluator(nil)

	// Parse Cedar-like syntax
	publicReadPolicy, _ := cedar.ParseCedarPolicy(
		"public-read",
		`permit(principal == User::"*", action == Action::"GET", resource == Collection::"public_data");`,
	)
	syntaxEvaluator.AddPolicy(publicReadPolicy)

	// ============================================================
	// EXAMPLE 4: Policies from JSON
	// ============================================================
	jsonPolicies := `[
		{
			"id": "json-policy-1",
			"effect": "permit",
			"description": "Allow all users to access health endpoint",
			"action": {"type": "Action", "id": "GET"},
			"resource": {"type": "Path", "pattern": "^/api/health$"}
		},
		{
			"id": "json-policy-2",
			"effect": "forbid",
			"description": "Block access during maintenance",
			"conditions": [
				{
					"kind": "when",
					"attributes": {"context.maintenance": true}
				}
			]
		}
	]`

	jsonParsedPolicies, _ := cedar.ParsePolicies([]byte(jsonPolicies))
	jsonEvaluator := cedar.NewEvaluator(nil)
	jsonEvaluator.AddPolicies(jsonParsedPolicies...)

	// ============================================================
	// EXAMPLE 5: Custom condition evaluator
	// ============================================================
	customEvaluator := cedar.NewEvaluator(nil)

	// Register custom IP range condition
	customEvaluator.RegisterConditionEvaluator("ip_in_range", cedar.IPRangeCondition)

	// Register custom time range condition
	customEvaluator.RegisterConditionEvaluator("time_between", cedar.TimeRangeCondition)

	// Policy using custom condition
	customEvaluator.AddPolicy(
		cedar.NewPolicy("office-hours-only").
			Permit().
			Description("Allow access only during office hours").
			When(`time_between("09:00", "17:00")`).
			Build(),
	)

	// ============================================================
	// Register routes with Cedar middleware
	// ============================================================
	app.OnServe().Bind(&hook.Handler[*core.ServeEvent]{
		Func: func(e *core.ServeEvent) error {
			// Simple policy route - middleware is bound to route using .Bind()
			e.Router.GET("/api/posts", func(re *core.RequestEvent) error {
				return re.JSON(http.StatusOK, map[string]string{
					"message": "Posts retrieved successfully",
				})
			}).Bind(apis.RequireCedarPolicy(apis.CedarConfig{
				Evaluator: simpleEvaluator,
			}))

			// RBAC route with dynamic role assignment
			e.Router.GET("/api/admin/users", func(re *core.RequestEvent) error {
				return re.JSON(http.StatusOK, map[string]string{
					"message": "Admin users endpoint",
				})
			}).Bind(apis.RequireCedarPolicy(apis.CedarConfig{
				Evaluator:      rbacEvaluator,
				EntityResolver: entityStore,
				PrincipalFromRequest: func(re *core.RequestEvent) *cedar.Entity {
					if re.Auth == nil {
						return cedar.NewEntity("User", "anonymous")
					}

					principal := cedar.NewEntity("User", re.Auth.Id)

					// Assign role based on user data
					// In a real app, this would come from the user record
					role := re.Request.Header.Get("X-Role")
					if role != "" {
						principal.AddParent("Role", role)
						entityStore.Add(principal)
					}

					return principal
				},
			}))

			// Policy demo endpoint - shows how policies are evaluated
			e.Router.POST("/api/demo/evaluate", func(re *core.RequestEvent) error {
				var body struct {
					PrincipalType string         `json:"principalType"`
					PrincipalID   string         `json:"principalId"`
					ActionID      string         `json:"action"`
					ResourceType  string         `json:"resourceType"`
					ResourceID    string         `json:"resourceId"`
					Context       map[string]any `json:"context"`
				}

				if err := re.BindBody(&body); err != nil {
					return re.BadRequestError("Invalid request body", err)
				}

				// Create request
				principal := cedar.NewEntity(body.PrincipalType, body.PrincipalID)
				action := cedar.NewEntity("Action", body.ActionID)
				resource := cedar.NewEntity(body.ResourceType, body.ResourceID)

				req := cedar.NewRequest(principal, action, resource)
				for k, v := range body.Context {
					req.WithContext(k, v)
				}

				// Evaluate against simple evaluator
				response := simpleEvaluator.IsAuthorized(req)

				return re.JSON(http.StatusOK, map[string]any{
					"decision":    response.Decision,
					"allowed":     response.IsAllowed(),
					"diagnostics": response.Diagnostics,
				})
			})

			// List all policies endpoint
			e.Router.GET("/api/demo/policies", func(re *core.RequestEvent) error {
				policies := simpleEvaluator.ListPolicies()
				return re.JSON(http.StatusOK, policies)
			})

			return e.Next()
		},
		Priority: 999,
	})

	// ============================================================
	// Print example policies to console on startup
	// ============================================================
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		policies := simpleEvaluator.ListPolicies()
		policiesJSON, _ := json.MarshalIndent(policies, "", "  ")
		log.Printf("Loaded %d Cedar policies:\n%s\n", len(policies), string(policiesJSON))
		return e.Next()
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

// Example: Save policies to file for persistence
func savePoliciesExample(policies []*cedar.Policy) {
	dir := "./pb_policies"
	os.MkdirAll(dir, 0755)

	for _, p := range policies {
		data, _ := json.MarshalIndent(p, "", "  ")
		os.WriteFile(filepath.Join(dir, p.ID+".json"), data, 0644)
	}
}

// Example: Load policies from file
func loadPoliciesExample() []*cedar.Policy {
	store, err := cedar.NewFilePolicyStore("./pb_policies")
	if err != nil {
		log.Fatal(err)
	}

	policies, _ := store.List()
	return policies
}

// Example: Quick policy evaluation (one-liner)
func quickEvalExample() {
	policies := []*cedar.Policy{
		cedar.NewPolicy("allow-all").Permit().Build(),
	}

	allowed := cedar.QuickEval(
		policies,
		cedar.NewEntity("User", "alice"),
		cedar.NewEntity("Action", "read"),
		cedar.NewEntity("Document", "doc123"),
	)

	log.Printf("Quick eval result: %v", allowed)
}

