package analyzer

import (
	"fmt"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func DetectDenyAllowOverlap(p *model.Policy) []model.Finding {
	var findings []model.Finding

	type actionSource struct {
		action string
		index  int
	}

	var allows []actionSource
	var denies []actionSource

	for i, s := range p.Statement {
		for _, a := range s.Action {
			if s.Effect == "Allow" {
				allows = append(allows, actionSource{action: a, index: i})
			} else if s.Effect == "Deny" {
				denies = append(denies, actionSource{action: a, index: i})
			}
		}
	}

	seen := make(map[[2]int]bool)
	for _, d := range denies {
		for _, a := range allows {
			if d.action == a.action {
				pair := [2]int{a.index, d.index}
				if seen[pair] {
					continue
				}
				seen[pair] = true

				findings = append(findings, model.Finding{
					Severity:    model.SeverityHigh,
					Title:       "Deny/Allow overlap",
					Explanation: fmt.Sprintf("Action %q is both allowed and denied. The Deny will take precedence, but this may indicate a misconfiguration.", d.action),
					Evidence:    fmt.Sprintf("Action %q in Allow statement %d and Deny statement %d", d.action, a.index, d.index),
					StmtIndices: []int{a.index, d.index},
				})
			}
		}
	}

	return findings
}
