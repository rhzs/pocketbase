package cedar

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Evaluator evaluates Cedar policies against authorization requests.
type Evaluator struct {
	policies       []*Policy
	entityResolver EntityResolver
	mu             sync.RWMutex

	// policyIndex provides O(1) lookup by resource type for scalability.
	policyIndex map[string][]*Policy

	// conditionEvaluators allows extending condition evaluation.
	conditionEvaluators map[string]ConditionEvaluator
}

// ConditionEvaluator is a function that evaluates a condition expression.
type ConditionEvaluator func(expr string, req *Request, resolver EntityResolver) (bool, error)

// NewEvaluator creates a new policy evaluator.
func NewEvaluator(resolver EntityResolver) *Evaluator {
	e := &Evaluator{
		policies:            make([]*Policy, 0),
		entityResolver:      resolver,
		policyIndex:         make(map[string][]*Policy),
		conditionEvaluators: make(map[string]ConditionEvaluator),
	}
	// Register built-in condition evaluators
	e.conditionEvaluators["ip_in_range"] = IPRangeCondition
	e.conditionEvaluators["time_between"] = TimeRangeCondition
	return e
}

// SetEntityResolver sets the entity resolver.
func (e *Evaluator) SetEntityResolver(resolver EntityResolver) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.entityResolver = resolver
}

// AddPolicy adds a policy to the evaluator.
func (e *Evaluator) AddPolicy(policy *Policy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	if policy.ID == "" {
		return fmt.Errorf("policy ID cannot be empty")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Check for duplicate ID
	for i, p := range e.policies {
		if p.ID == policy.ID {
			// Replace existing
			e.policies[i] = policy
			e.sortPolicies()
			return nil
		}
	}

	e.policies = append(e.policies, policy)
	e.sortPolicies()
	return nil
}

// AddPolicies adds multiple policies to the evaluator.
func (e *Evaluator) AddPolicies(policies ...*Policy) error {
	for _, p := range policies {
		if err := e.AddPolicy(p); err != nil {
			return err
		}
	}
	return nil
}

// RemovePolicy removes a policy by ID.
func (e *Evaluator) RemovePolicy(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, p := range e.policies {
		if p.ID == id {
			e.policies = append(e.policies[:i], e.policies[i+1:]...)
			break
		}
	}
}

// GetPolicy returns a policy by ID.
func (e *Evaluator) GetPolicy(id string) *Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, p := range e.policies {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// ListPolicies returns all policies.
func (e *Evaluator) ListPolicies() []*Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Policy, len(e.policies))
	copy(result, e.policies)
	return result
}

// ClearPolicies removes all policies.
func (e *Evaluator) ClearPolicies() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies = make([]*Policy, 0)
}

// RegisterConditionEvaluator registers a custom condition evaluator.
func (e *Evaluator) RegisterConditionEvaluator(name string, evaluator ConditionEvaluator) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conditionEvaluators[name] = evaluator
}

func (e *Evaluator) sortPolicies() {
	sort.SliceStable(e.policies, func(i, j int) bool {
		return e.policies[i].Priority < e.policies[j].Priority
	})
	e.rebuildIndex()
}

func (e *Evaluator) rebuildIndex() {
	e.policyIndex = make(map[string][]*Policy)
	for _, p := range e.policies {
		key := "*" // default bucket for policies without specific resource
		if p.Resource != nil && p.Resource.Type != "" && p.Resource.Type != "*" {
			key = p.Resource.Type
		}
		e.policyIndex[key] = append(e.policyIndex[key], p)
	}
}

// getRelevantPolicies returns policies relevant to the request using the index.
func (e *Evaluator) getRelevantPolicies(req *Request) []*Policy {
	if req.Resource == nil || req.Resource.Type == "" {
		return e.policies
	}

	// Get policies matching the specific resource type + wildcard policies
	resourceType := req.Resource.Type
	relevant := make([]*Policy, 0, len(e.policies))

	if typed, ok := e.policyIndex[resourceType]; ok {
		relevant = append(relevant, typed...)
	}
	if wildcard, ok := e.policyIndex["*"]; ok {
		relevant = append(relevant, wildcard...)
	}

	// If index is empty or no matches, fall back to all policies
	if len(relevant) == 0 {
		return e.policies
	}

	return relevant
}

// IsAuthorized evaluates the request against all policies and returns the decision.
// Default-deny: if no permit policy matches, the request is denied.
func (e *Evaluator) IsAuthorized(req *Request) *Response {
	e.mu.RLock()
	defer e.mu.RUnlock()

	response := &Response{
		Decision: DecisionDeny,
		Diagnostics: &Diagnostics{
			DeterminingPolicies: make([]string, 0),
			Errors:              make([]string, 0),
		},
	}

	if req == nil {
		response.Diagnostics.Reason = "request is nil"
		return response
	}

	var permitPolicies []string
	var forbidPolicies []string

	// Get relevant policies using index for better scalability
	policiesToEval := e.getRelevantPolicies(req)

	for _, policy := range policiesToEval {
		matches, err := e.evaluatePolicy(policy, req)
		if err != nil {
			response.Diagnostics.Errors = append(response.Diagnostics.Errors,
				fmt.Sprintf("policy %s: %v", policy.ID, err))
			continue
		}

		if matches {
			switch policy.Effect {
			case EffectPermit:
				permitPolicies = append(permitPolicies, policy.ID)
			case EffectForbid:
				forbidPolicies = append(forbidPolicies, policy.ID)
			}
		}
	}

	// Forbid takes precedence over permit
	if len(forbidPolicies) > 0 {
		response.Decision = DecisionDeny
		response.Diagnostics.DeterminingPolicies = forbidPolicies
		response.Diagnostics.Reason = "explicitly forbidden by policy"
		return response
	}

	// If any permit policy matched, allow
	if len(permitPolicies) > 0 {
		response.Decision = DecisionAllow
		response.Diagnostics.DeterminingPolicies = permitPolicies
		response.Diagnostics.Reason = "permitted by policy"
		return response
	}

	response.Diagnostics.Reason = "no matching permit policy found (default deny)"
	return response
}

// evaluatePolicy evaluates a single policy against a request.
func (e *Evaluator) evaluatePolicy(policy *Policy, req *Request) (bool, error) {
	// Check principal match
	if !policy.Principal.Matches(req.Principal, e.entityResolver) {
		return false, nil
	}

	// Check action match
	if !policy.Action.Matches(req.Action, e.entityResolver) {
		return false, nil
	}

	// Check resource match
	if !policy.Resource.Matches(req.Resource, e.entityResolver) {
		return false, nil
	}

	// Evaluate conditions
	for _, cond := range policy.Conditions {
		condResult, err := e.evaluateCondition(cond, req)
		if err != nil {
			return false, err
		}

		switch cond.Kind {
		case ConditionWhen:
			if !condResult {
				return false, nil
			}
		case ConditionUnless:
			if condResult {
				return false, nil
			}
		}
	}

	return true, nil
}

// evaluateCondition evaluates a condition.
func (e *Evaluator) evaluateCondition(cond Condition, req *Request) (bool, error) {
	// First, check attribute-based conditions
	if len(cond.Attributes) > 0 {
		return e.evaluateAttributeCondition(cond.Attributes, req)
	}

	// Then, check expression-based conditions
	if cond.Expression != "" {
		return e.evaluateExpression(cond.Expression, req)
	}

	// Empty condition always passes
	return true, nil
}

// evaluateAttributeCondition evaluates attribute-based conditions.
func (e *Evaluator) evaluateAttributeCondition(attrs map[string]any, req *Request) (bool, error) {
	for key, expected := range attrs {
		actual, found := e.resolveAttribute(key, req)
		if !found {
			return false, nil
		}
		if !compareValues(actual, expected) {
			return false, nil
		}
	}
	return true, nil
}

// resolveAttribute resolves an attribute path from the request.
func (e *Evaluator) resolveAttribute(path string, req *Request) (any, bool) {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) == 0 {
		return nil, false
	}

	var entity *Entity
	switch parts[0] {
	case "principal":
		entity = req.Principal
	case "action":
		entity = req.Action
	case "resource":
		entity = req.Resource
	case "context":
		if len(parts) > 1 && req.Context != nil {
			v, ok := req.Context[parts[1]]
			return v, ok
		}
		return nil, false
	default:
		// Check context directly
		if req.Context != nil {
			v, ok := req.Context[path]
			return v, ok
		}
		return nil, false
	}

	if entity == nil {
		return nil, false
	}

	if len(parts) == 1 {
		return entity, true
	}

	// Resolve sub-path
	subPath := parts[1]
	if subPath == "type" {
		return entity.Type, true
	}
	if subPath == "id" {
		return entity.ID, true
	}

	// Check attributes
	if entity.Attributes != nil {
		v, ok := entity.Attributes[subPath]
		return v, ok
	}

	return nil, false
}

// evaluateExpression evaluates a condition expression.
func (e *Evaluator) evaluateExpression(expr string, req *Request) (bool, error) {
	expr = strings.TrimSpace(expr)

	// Check for registered custom evaluators
	for name, evaluator := range e.conditionEvaluators {
		if strings.HasPrefix(expr, name+"(") {
			return evaluator(expr, req, e.entityResolver)
		}
	}

	// Built-in expression evaluation
	return e.evaluateBuiltinExpression(expr, req)
}

// evaluateBuiltinExpression handles built-in expression patterns.
func (e *Evaluator) evaluateBuiltinExpression(expr string, req *Request) (bool, error) {
	expr = strings.TrimSpace(expr)

	// Handle boolean operators (lowest precedence, evaluated first for splitting)
	if idx := strings.Index(expr, " && "); idx != -1 {
		left, err := e.evaluateBuiltinExpression(expr[:idx], req)
		if err != nil {
			return false, err
		}
		if !left {
			return false, nil // short-circuit
		}
		return e.evaluateBuiltinExpression(expr[idx+4:], req)
	}

	if idx := strings.Index(expr, " || "); idx != -1 {
		left, err := e.evaluateBuiltinExpression(expr[:idx], req)
		if err != nil {
			return false, err
		}
		if left {
			return true, nil // short-circuit
		}
		return e.evaluateBuiltinExpression(expr[idx+4:], req)
	}

	// Handle NOT operator
	if strings.HasPrefix(expr, "!") {
		result, err := e.evaluateBuiltinExpression(expr[1:], req)
		if err != nil {
			return false, err
		}
		return !result, nil
	}

	// Handle parentheses
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		return e.evaluateBuiltinExpression(expr[1:len(expr)-1], req)
	}

	// Handle comparison operators (order matters: >= before >, <= before <)
	operators := []string{"==", "!=", ">=", "<=", ">", "<", " contains ", " in "}

	for _, op := range operators {
		if idx := strings.Index(expr, op); idx != -1 {
			left := strings.TrimSpace(expr[:idx])
			right := strings.TrimSpace(expr[idx+len(op):])

			leftVal, leftFound := e.resolveExpressionValue(left, req)
			rightVal, rightFound := e.resolveExpressionValue(right, req)

			if !leftFound || !rightFound {
				return false, nil
			}

			return e.applyOperator(leftVal, strings.TrimSpace(op), rightVal)
		}
	}

	// Handle boolean expressions
	if expr == "true" {
		return true, nil
	}
	if expr == "false" {
		return false, nil
	}

	// Try to resolve as a truthy value
	val, found := e.resolveExpressionValue(expr, req)
	if !found {
		return false, nil
	}

	return isTruthy(val), nil
}

// resolveExpressionValue resolves a value from an expression.
func (e *Evaluator) resolveExpressionValue(expr string, req *Request) (any, bool) {
	expr = strings.TrimSpace(expr)

	// String literal
	if (strings.HasPrefix(expr, `"`) && strings.HasSuffix(expr, `"`)) ||
		(strings.HasPrefix(expr, `'`) && strings.HasSuffix(expr, `'`)) {
		return expr[1 : len(expr)-1], true
	}

	// Numeric literal
	if i, err := strconv.ParseInt(expr, 10, 64); err == nil {
		return i, true
	}
	if f, err := strconv.ParseFloat(expr, 64); err == nil {
		return f, true
	}

	// Boolean literal
	if expr == "true" {
		return true, true
	}
	if expr == "false" {
		return false, true
	}

	// Attribute path
	return e.resolveAttribute(expr, req)
}

// applyOperator applies an operator to two values.
func (e *Evaluator) applyOperator(left any, op string, right any) (bool, error) {
	switch op {
	case "==":
		return compareValues(left, right), nil
	case "!=":
		return !compareValues(left, right), nil
	case ">", "<", ">=", "<=":
		return compareNumeric(left, op, right)
	case "contains":
		return containsValue(left, right), nil
	case "in":
		return containsValue(right, left), nil
	}
	return false, fmt.Errorf("unknown operator: %s", op)
}

// compareValues compares two values for equality.
func compareValues(a, b any) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// compareNumeric compares two numeric values.
func compareNumeric(a any, op string, b any) (bool, error) {
	aFloat, aOk := toFloat64(a)
	bFloat, bOk := toFloat64(b)

	if !aOk || !bOk {
		return false, nil
	}

	switch op {
	case ">":
		return aFloat > bFloat, nil
	case "<":
		return aFloat < bFloat, nil
	case ">=":
		return aFloat >= bFloat, nil
	case "<=":
		return aFloat <= bFloat, nil
	}
	return false, nil
}

func toFloat64(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case int32:
		return float64(val), true
	case string:
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

// containsValue checks if a collection contains a value.
func containsValue(collection, value any) bool {
	switch c := collection.(type) {
	case []any:
		for _, item := range c {
			if compareValues(item, value) {
				return true
			}
		}
	case []string:
		for _, item := range c {
			if compareValues(item, value) {
				return true
			}
		}
	case string:
		if s, ok := value.(string); ok {
			return strings.Contains(c, s)
		}
	}
	return false
}

// isTruthy returns true if the value is "truthy".
func isTruthy(v any) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val != ""
	case int, int64, int32, float64, float32:
		return val != 0
	case []any:
		return len(val) > 0
	}
	return true
}

// EvaluatorOption is a functional option for configuring the evaluator.
type EvaluatorOption func(*Evaluator)

// WithEntityResolver sets the entity resolver.
func WithEntityResolver(resolver EntityResolver) EvaluatorOption {
	return func(e *Evaluator) {
		e.entityResolver = resolver
	}
}

// WithPolicies adds policies to the evaluator.
func WithPolicies(policies ...*Policy) EvaluatorOption {
	return func(e *Evaluator) {
		for _, p := range policies {
			e.AddPolicy(p)
		}
	}
}

// WithConditionEvaluator registers a custom condition evaluator.
func WithConditionEvaluator(name string, evaluator ConditionEvaluator) EvaluatorOption {
	return func(e *Evaluator) {
		e.conditionEvaluators[name] = evaluator
	}
}

// NewEvaluatorWithOptions creates a new evaluator with options.
func NewEvaluatorWithOptions(opts ...EvaluatorOption) *Evaluator {
	e := NewEvaluator(nil)
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// QuickEval provides a quick evaluation without creating an evaluator.
// Useful for simple, one-off authorization checks.
func QuickEval(policies []*Policy, principal, action, resource *Entity) bool {
	e := NewEvaluator(nil)
	e.AddPolicies(policies...)
	req := NewRequest(principal, action, resource)
	return e.IsAuthorized(req).IsAllowed()
}

// IPRangeCondition is a built-in condition evaluator for IP range checks.
// Usage: ip_in_range(context.ip, "192.168.1.0/24")
func IPRangeCondition(expr string, req *Request, resolver EntityResolver) (bool, error) {
	pattern := regexp.MustCompile(`ip_in_range\(([^,]+),\s*"([^"]+)"\)`)
	matches := pattern.FindStringSubmatch(expr)
	if len(matches) != 3 {
		return false, fmt.Errorf("invalid ip_in_range expression: %s", expr)
	}

	ipPath := strings.TrimSpace(matches[1])
	cidr := matches[2]

	if req.Context == nil {
		return false, nil
	}

	// Resolve IP from context path
	var ipStr string
	if strings.HasPrefix(ipPath, "context.") {
		key := strings.TrimPrefix(ipPath, "context.")
		if v, ok := req.Context[key]; ok {
			ipStr, _ = v.(string)
		}
	} else if v, ok := req.Context[ipPath]; ok {
		ipStr, _ = v.(string)
	}

	if ipStr == "" {
		return false, nil
	}

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false, nil
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR: %s", cidr)
	}

	return prefix.Contains(ip), nil
}

// TimeRangeCondition is a built-in condition evaluator for time-based checks.
// Usage: time_between("09:00", "17:00")
// Optionally accepts a third parameter for timezone: time_between("09:00", "17:00", "America/New_York")
func TimeRangeCondition(expr string, req *Request, resolver EntityResolver) (bool, error) {
	pattern := regexp.MustCompile(`time_between\("([^"]+)",\s*"([^"]+)"(?:,\s*"([^"]+)")?\)`)
	matches := pattern.FindStringSubmatch(expr)
	if len(matches) < 3 {
		return false, fmt.Errorf("invalid time_between expression: %s", expr)
	}

	startStr := matches[1]
	endStr := matches[2]

	loc := time.Local
	if len(matches) > 3 && matches[3] != "" {
		var err error
		loc, err = time.LoadLocation(matches[3])
		if err != nil {
			return false, fmt.Errorf("invalid timezone: %s", matches[3])
		}
	}

	now := time.Now().In(loc)
	today := now.Format("2006-01-02")

	startTime, err := time.ParseInLocation("2006-01-02 15:04", today+" "+startStr, loc)
	if err != nil {
		return false, fmt.Errorf("invalid start time: %s", startStr)
	}

	endTime, err := time.ParseInLocation("2006-01-02 15:04", today+" "+endStr, loc)
	if err != nil {
		return false, fmt.Errorf("invalid end time: %s", endStr)
	}

	return !now.Before(startTime) && !now.After(endTime), nil
}
