package analyzer

import (
	"fmt"
	"reflect"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func DetectMergeCandidates(p *model.Policy) []model.Finding {
	var findings []model.Finding

	for i := 0; i < len(p.Statement); i++ {
		for j := i + 1; j < len(p.Statement); j++ {
			a := p.Statement[i]
			b := p.Statement[j]

			if a.Effect != b.Effect {
				continue
			}
			if !reflect.DeepEqual(a.Condition, b.Condition) {
				continue
			}
			if !reflect.DeepEqual(a.Principal, b.Principal) {
				continue
			}

			if reflect.DeepEqual(a.Resource, b.Resource) && !reflect.DeepEqual(a.Action, b.Action) {
				findings = append(findings, model.Finding{
					Severity:    model.SeverityLow,
					Title:       "Merge candidates (same resources)",
					Explanation: "These statements share the same Effect, Resources, Conditions and Principal. Their Actions can be merged into one statement.",
					Evidence:    fmt.Sprintf("Statements %d and %d can merge Actions", i, j),
					StmtIndices: []int{i, j},
				})
			}

			if reflect.DeepEqual(a.Action, b.Action) && !reflect.DeepEqual(a.Resource, b.Resource) {
				findings = append(findings, model.Finding{
					Severity:    model.SeverityLow,
					Title:       "Merge candidates (same actions)",
					Explanation: "These statements share the same Effect, Actions, Conditions and Principal. Their Resources can be merged into one statement.",
					Evidence:    fmt.Sprintf("Statements %d and %d can merge Resources", i, j),
					StmtIndices: []int{i, j},
				})
			}
		}
	}
	return findings
}
