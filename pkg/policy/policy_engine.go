package policy

// PolicyEngine evaluates policies to determine access decisions.
//
// The engine performs simple matching on resource and action attributes. Policies
// may optionally scope themselves to specific roles via the `Subjects` field.
// Evaluation stops at the first matching policy and returns a structured
// decision describing the result.
type PolicyEngine struct {
	store *PolicyStore
}

// NewPolicyEngine creates a new PolicyEngine instance.
func NewPolicyEngine(store *PolicyStore) *PolicyEngine {
	return &PolicyEngine{store: store}
}

// Evaluate determines whether the given subject is allowed to perform the
// specified action on the resource. It returns a Decision describing the
// outcome and does not log sensitive data.
func (pe *PolicyEngine) Evaluate(subject, resource, action string, env map[string]string) Decision {
	ctx := map[string]string{
		"subject":  subject,
		"resource": resource,
		"action":   action,
	}

	trace := []string{}

	user, exists := pe.store.Users[subject]
	if !exists {
		trace = append(trace, "user not found")
		return Decision{Allow: false, Reason: "user not found", Context: ctx, Trace: trace}
	}

	for _, roleName := range user.Roles {
		role, exists := pe.store.Roles[roleName]
		if !exists {
			continue
		}

		for _, policyID := range role.Policies {
			policy, exists := pe.store.Policies[policyID]
			if !exists {
				continue
			}
			// Ensure the policy applies to the current role
			if len(policy.Subjects) > 0 {
				allowed := false
				for _, subj := range policy.Subjects {
					if subj.Role == roleName {
						allowed = true
						break
					}
				}
				if !allowed {
					trace = append(trace, "policy "+policy.ID+" skipped: subject mismatch")
					continue
				}
			}

			matched := false
			for _, polResource := range policy.Resource {
				for _, polAction := range policy.Action {
					if (polResource == "*" || polResource == resource) &&
						(polAction == "*" || polAction == action) {
						matched = true
						if ok := evaluateConditions(policy.Conditions, env); !ok {
							trace = append(trace, "policy "+policy.ID+" failed: conditions not satisfied")
							return Decision{Allow: false, PolicyID: policy.ID, Reason: "conditions not satisfied", Context: ctx, Trace: trace}
						}
						switch policy.Effect {
						case "allow":
							trace = append(trace, "policy "+policy.ID+" matched: allow")
							return Decision{Allow: true, PolicyID: policy.ID, Reason: "allowed by policy", Context: ctx, Trace: trace}
						case "deny":
							trace = append(trace, "policy "+policy.ID+" matched: deny")
							return Decision{Allow: false, PolicyID: policy.ID, Reason: "denied by policy", Context: ctx, Trace: trace}
						}
					}
				}
			}
			if !matched {
				trace = append(trace, "policy "+policy.ID+" did not match")
			}
		}
	}

	trace = append(trace, "no matching policy")
	return Decision{Allow: false, Reason: "no matching policy", Context: ctx, Trace: trace}
}
