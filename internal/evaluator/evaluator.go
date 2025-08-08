package evaluator

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Rule defines a single authorization rule loaded from YAML.
type Rule struct {
	ID          string            `yaml:"id"`
	Description string            `yaml:"description,omitempty"`
	Roles       []string          `yaml:"roles,omitempty"`
	Actions     []string          `yaml:"actions"`
	Resources   []string          `yaml:"resources"`
	Conditions  map[string]string `yaml:"conditions,omitempty"`
	Effect      string            `yaml:"effect"` // "allow" or "deny"
	Advice      string            `yaml:"advice,omitempty"`
}

// Evaluator loads policies and evaluates verifiable credentials against them.
type Evaluator struct {
	rules []Rule
}

// New reads all YAML policy files from dir and constructs an Evaluator.
func New(dir string) (*Evaluator, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var rs []Rule
		if err := yaml.Unmarshal(b, &rs); err != nil {
			return nil, err
		}
		rules = append(rules, rs...)
	}
	return &Evaluator{rules: rules}, nil
}

// Context provides fields used during evaluation.
type Context struct {
	Action      string
	Resource    string
	Environment map[string]string
}

// Result is returned from Evaluate.
type Result struct {
	Allowed bool
	Advice  string
}

// Evaluate returns the decision for the given VC and context.
func (e *Evaluator) Evaluate(vc map[string]any, ctx Context) Result {
	roles, attrs := extractFacts(vc)
	facts := map[string]string{}
	for k, v := range attrs {
		facts[k] = v
	}
	for k, v := range ctx.Environment {
		facts[k] = v
	}
	for _, r := range e.rules {
		if !match(r.Actions, ctx.Action) || !match(r.Resources, ctx.Resource) {
			continue
		}
		if len(r.Roles) > 0 && !hasAny(r.Roles, roles) {
			continue
		}
		if len(r.Conditions) > 0 && !conditionsMatch(r.Conditions, facts) {
			continue
		}
		if r.Effect == "allow" {
			return Result{Allowed: true}
		}
		return Result{Allowed: false, Advice: r.Advice}
	}
	return Result{Allowed: false}
}

func match(list []string, v string) bool {
	for _, item := range list {
		if item == "*" || item == v {
			return true
		}
	}
	return false
}

func hasAny(req, have []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, r := range have {
		set[r] = struct{}{}
	}
	for _, r := range req {
		if _, ok := set[r]; ok {
			return true
		}
	}
	return false
}

func conditionsMatch(conds, facts map[string]string) bool {
	for k, v := range conds {
		if facts[k] != v {
			return false
		}
	}
	return true
}

// extractFacts retrieves roles and attributes from a VC-like structure.
func extractFacts(vc map[string]any) ([]string, map[string]string) {
	cs, _ := vc["credentialSubject"].(map[string]any)
	var roles []string
	attrs := map[string]string{}
	if cs != nil {
		if r, ok := cs["roles"].([]any); ok {
			for _, v := range r {
				roles = append(roles, fmt.Sprint(v))
			}
		}
		for k, v := range cs {
			if k == "roles" {
				continue
			}
			attrs[k] = fmt.Sprint(v)
		}
	}
	return roles, attrs
}
