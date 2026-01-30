package analyzer

import (
	"fmt"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func DetectWildcardOveruse(p *model.Policy) []model.Finding {
	var findings []model.Finding

	for i, s := range p.Statement {
		wildcardAction := containsWildcard(s.Action)
		wildcardResource := containsWildcard(s.Resource)

		if wildcardAction && wildcardResource {
			findings = append(findings, model.Finding{
				Severity:    model.SeverityHigh,
				Title:       "Full wildcard statement",
				Explanation: "Both Action and Resource are wildcards. This grants unrestricted access.",
				Evidence:    fmt.Sprintf("Statement %d has Action=* and Resource=*", i),
				StmtIndices: []int{i},
			})
		} else if wildcardAction {
			findings = append(findings, model.Finding{
				Severity:    model.SeverityMedium,
				Title:       "Wildcard action",
				Explanation: "Action is a wildcard. This grants all actions on the specified resources.",
				Evidence:    fmt.Sprintf("Statement %d has Action=*", i),
				StmtIndices: []int{i},
			})
		} else if wildcardResource {
			findings = append(findings, model.Finding{
				Severity:    model.SeverityMedium,
				Title:       "Wildcard resource",
				Explanation: "Resource is a wildcard. The specified actions apply to all resources.",
				Evidence:    fmt.Sprintf("Statement %d has Resource=*", i),
				StmtIndices: []int{i},
			})
		}
	}

	return findings
}

func containsWildcard(ss model.StringOrSlice) bool {
	for _, s := range ss {
		if s == "*" {
			return true
		}
	}
	return false
}
