package apis

import (
	"fmt"
	"strings"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/cedar"
	"github.com/pocketbase/pocketbase/tools/hook"
)

const (
	DefaultCedarPolicyMiddlewareId       = "pbCedarPolicy"
	DefaultCedarPolicyMiddlewarePriority = DefaultLoadAuthTokenMiddlewarePriority + 10
)

// CedarConfig configures the Cedar policy middleware.
type CedarConfig struct {
	// Evaluator is the Cedar policy evaluator.
	Evaluator *cedar.Evaluator

	// EntityResolver resolves entity hierarchies.
	EntityResolver cedar.EntityResolver

	// ActionFromRequest extracts the action entity from the request.
	// Defaults to using HTTP method as action ID.
	ActionFromRequest func(e *core.RequestEvent) *cedar.Entity

	// ResourceFromRequest extracts the resource entity from the request.
	// Defaults to using URL path as resource ID.
	ResourceFromRequest func(e *core.RequestEvent) *cedar.Entity

	// PrincipalFromRequest extracts the principal entity from the request.
	// Defaults to using auth record as principal.
	PrincipalFromRequest func(e *core.RequestEvent) *cedar.Entity

	// ContextFromRequest extracts additional context from the request.
	ContextFromRequest func(e *core.RequestEvent) map[string]any

	// OnDeny is called when a request is denied.
	// Return a custom error or nil to use the default.
	OnDeny func(e *core.RequestEvent, response *cedar.Response) error

	// SkipFunc allows skipping policy evaluation for certain requests.
	SkipFunc func(e *core.RequestEvent) bool
}

// RequireCedarPolicy creates a middleware that enforces Cedar policies.
//
// Example usage:
//
//	evaluator := cedar.NewEvaluator(nil)
//	evaluator.AddPolicy(
//	    cedar.NewPolicy("allow-users-read").
//	        Permit().
//	        Principal("User", "").
//	        Action("Action", "GET").
//	        Resource("Collection", "posts").
//	        Build(),
//	)
//
//	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
//	    e.Router.GET("/api/posts", handler, apis.RequireCedarPolicy(apis.CedarConfig{
//	        Evaluator: evaluator,
//	    }))
//	    return e.Next()
//	})
func RequireCedarPolicy(config CedarConfig) *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Id:       DefaultCedarPolicyMiddlewareId,
		Priority: DefaultCedarPolicyMiddlewarePriority,
		Func:     cedarPolicyMiddleware(config),
	}
}

func cedarPolicyMiddleware(config CedarConfig) func(e *core.RequestEvent) error {
	// Set defaults
	if config.ActionFromRequest == nil {
		config.ActionFromRequest = defaultActionFromRequest
	}
	if config.ResourceFromRequest == nil {
		config.ResourceFromRequest = defaultResourceFromRequest
	}
	if config.PrincipalFromRequest == nil {
		config.PrincipalFromRequest = defaultPrincipalFromRequest
	}
	if config.ContextFromRequest == nil {
		config.ContextFromRequest = defaultContextFromRequest
	}

	return func(e *core.RequestEvent) error {
		// Check skip function
		if config.SkipFunc != nil && config.SkipFunc(e) {
			return e.Next()
		}

		// Superusers bypass policy checks
		if e.HasSuperuserAuth() {
			return e.Next()
		}

		if config.Evaluator == nil {
			return e.Next() // No evaluator configured, allow by default
		}

		// Build the authorization request
		principal := config.PrincipalFromRequest(e)
		action := config.ActionFromRequest(e)
		resource := config.ResourceFromRequest(e)

		req := cedar.NewRequest(principal, action, resource)

		// Add context
		if config.ContextFromRequest != nil {
			for k, v := range config.ContextFromRequest(e) {
				req.WithContext(k, v)
			}
		}

		// Set entity resolver if provided
		if config.EntityResolver != nil {
			config.Evaluator.SetEntityResolver(config.EntityResolver)
		}

		// Evaluate the policy
		response := config.Evaluator.IsAuthorized(req)

		if !response.IsAllowed() {
			if config.OnDeny != nil {
				if err := config.OnDeny(e, response); err != nil {
					return err
				}
			}

			reason := "Access denied by policy"
			if response.Diagnostics != nil && response.Diagnostics.Reason != "" {
				reason = response.Diagnostics.Reason
			}

			return e.ForbiddenError(reason, nil)
		}

		return e.Next()
	}
}

func defaultActionFromRequest(e *core.RequestEvent) *cedar.Entity {
	method := strings.ToUpper(e.Request.Method)
	return cedar.NewEntity("Action", method)
}

func defaultResourceFromRequest(e *core.RequestEvent) *cedar.Entity {
	path := e.Request.URL.Path

	// Extract collection name if it's a collection route
	// Pattern: /api/collections/{collection}/records
	if strings.HasPrefix(path, "/api/collections/") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/collections/"), "/")
		if len(parts) > 0 {
			resource := cedar.NewEntity("Collection", parts[0])
			// Add record ID if present
			if len(parts) > 2 && parts[1] == "records" {
				resource.SetAttribute("recordId", parts[2])
			}
			return resource
		}
	}

	// Default: use path as resource
	return cedar.NewEntity("Path", path)
}

func defaultPrincipalFromRequest(e *core.RequestEvent) *cedar.Entity {
	if e.Auth == nil {
		return cedar.NewEntity("User", "anonymous")
	}

	principal := cedar.NewEntity("User", e.Auth.Id)

	// Add collection as parent (for role-based matching)
	principal.AddParent("Collection", e.Auth.Collection().Name)

	// Add auth record attributes
	if e.Auth.Email() != "" {
		principal.SetAttribute("email", e.Auth.Email())
	}
	if e.Auth.Verified() {
		principal.SetAttribute("verified", true)
	}

	return principal
}

func defaultContextFromRequest(e *core.RequestEvent) map[string]any {
	ctx := make(map[string]any)

	ctx["method"] = e.Request.Method
	ctx["path"] = e.Request.URL.Path
	ctx["ip"] = e.RealIP()

	// Add query parameters
	for k, v := range e.Request.URL.Query() {
		if len(v) > 0 {
			ctx["query."+k] = v[0]
		}
	}

	return ctx
}

// CedarPolicyBuilder provides helpers for building common PocketBase policies.
type CedarPolicyBuilder struct{}

// NewCedarPolicyBuilder creates a new policy builder helper.
func NewCedarPolicyBuilder() *CedarPolicyBuilder {
	return &CedarPolicyBuilder{}
}

// AllowAuthenticatedUsers creates a policy that permits authenticated users.
func (b *CedarPolicyBuilder) AllowAuthenticatedUsers(actions ...string) []*cedar.Policy {
	policies := make([]*cedar.Policy, 0, len(actions))
	for _, action := range actions {
		p := cedar.NewPolicy(fmt.Sprintf("allow-authenticated-%s", action)).
			Permit().
			PrincipalIn("Collection", "users"). // Users collection
			Action("Action", action).
			Build()
		policies = append(policies, p)
	}
	return policies
}

// AllowCollection creates a policy that permits access to a specific collection.
func (b *CedarPolicyBuilder) AllowCollection(collection string, actions ...string) []*cedar.Policy {
	policies := make([]*cedar.Policy, 0, len(actions))
	for _, action := range actions {
		p := cedar.NewPolicy(fmt.Sprintf("allow-%s-%s", collection, action)).
			Permit().
			Action("Action", action).
			Resource("Collection", collection).
			Build()
		policies = append(policies, p)
	}
	return policies
}

// AllowOwner creates a policy that permits record owners.
func (b *CedarPolicyBuilder) AllowOwner(collection, ownerField string) *cedar.Policy {
	return cedar.NewPolicy(fmt.Sprintf("allow-owner-%s", collection)).
		Permit().
		Resource("Collection", collection).
		When(fmt.Sprintf("principal.id == resource.%s", ownerField)).
		Build()
}

// DenyAnonymous creates a policy that forbids anonymous access.
func (b *CedarPolicyBuilder) DenyAnonymous() *cedar.Policy {
	return cedar.NewPolicy("deny-anonymous").
		Forbid().
		Principal("User", "anonymous").
		Build()
}

// AllowVerifiedOnly creates a policy that permits only verified users.
func (b *CedarPolicyBuilder) AllowVerifiedOnly(actions ...string) []*cedar.Policy {
	policies := make([]*cedar.Policy, 0, len(actions))
	for _, action := range actions {
		p := cedar.NewPolicy(fmt.Sprintf("allow-verified-%s", action)).
			Permit().
			Action("Action", action).
			WhenAttributes(map[string]any{"principal.verified": true}).
			Build()
		policies = append(policies, p)
	}
	return policies
}

// PocketBaseCedarAdapter adapts PocketBase's existing rules to Cedar policies.
type PocketBaseCedarAdapter struct {
	app core.App
}

// NewPocketBaseCedarAdapter creates a new adapter.
func NewPocketBaseCedarAdapter(app core.App) *PocketBaseCedarAdapter {
	return &PocketBaseCedarAdapter{app: app}
}

// CollectionToPolicy converts a collection's access rules to Cedar policies.
func (a *PocketBaseCedarAdapter) CollectionToPolicy(collectionName string) ([]*cedar.Policy, error) {
	collection, err := a.app.FindCachedCollectionByNameOrId(collectionName)
	if err != nil {
		return nil, err
	}

	var policies []*cedar.Policy

	// View rule
	if collection.ViewRule != nil {
		p := cedar.NewPolicy(fmt.Sprintf("%s-view", collectionName)).
			Permit().
			Action("Action", "GET").
			Resource("Collection", collectionName).
			Tags("collection", collectionName, "action", "view").
			Build()
		if *collection.ViewRule != "" {
			p.Description = fmt.Sprintf("Original rule: %s", *collection.ViewRule)
		}
		policies = append(policies, p)
	}

	// Create rule
	if collection.CreateRule != nil {
		p := cedar.NewPolicy(fmt.Sprintf("%s-create", collectionName)).
			Permit().
			Action("Action", "POST").
			Resource("Collection", collectionName).
			Tags("collection", collectionName, "action", "create").
			Build()
		if *collection.CreateRule != "" {
			p.Description = fmt.Sprintf("Original rule: %s", *collection.CreateRule)
		}
		policies = append(policies, p)
	}

	// Update rule
	if collection.UpdateRule != nil {
		p := cedar.NewPolicy(fmt.Sprintf("%s-update", collectionName)).
			Permit().
			Action("Action", "PATCH").
			Resource("Collection", collectionName).
			Tags("collection", collectionName, "action", "update").
			Build()
		if *collection.UpdateRule != "" {
			p.Description = fmt.Sprintf("Original rule: %s", *collection.UpdateRule)
		}
		policies = append(policies, p)
	}

	// Delete rule
	if collection.DeleteRule != nil {
		p := cedar.NewPolicy(fmt.Sprintf("%s-delete", collectionName)).
			Permit().
			Action("Action", "DELETE").
			Resource("Collection", collectionName).
			Tags("collection", collectionName, "action", "delete").
			Build()
		if *collection.DeleteRule != "" {
			p.Description = fmt.Sprintf("Original rule: %s", *collection.DeleteRule)
		}
		policies = append(policies, p)
	}

	return policies, nil
}

