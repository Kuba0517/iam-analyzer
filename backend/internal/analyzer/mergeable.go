package analyzer

import (
	"fmt"

	"github.com/Kuba0517/iam-analyzer/internal/graph"
	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func DetectMergeCandidates(p *model.Policy) []model.Finding {
	return detectMergeCandidatesFromGraph(graph.Build(p))
}

func detectMergeCandidatesFromGraph(g *graph.Graph) []model.Finding {
	var findings []model.Finding

	for _, e := range g.EdgesOfType(graph.MergeableAction) {
		findings = append(findings, model.Finding{
			Severity:    model.SeverityLow,
			Title:       "Merge candidates (same resources)",
			Explanation: "These statements share the same Effect, Resources, Conditions and Principal. Their Actions can be merged into one statement.",
			Evidence:    fmt.Sprintf("Statements %d and %d can merge Actions", e.From, e.To),
			StmtIndices: []int{e.From, e.To},
		})
	}

	for _, e := range g.EdgesOfType(graph.MergeableResource) {
		findings = append(findings, model.Finding{
			Severity:    model.SeverityLow,
			Title:       "Merge candidates (same actions)",
			Explanation: "These statements share the same Effect, Actions, Conditions and Principal. Their Resources can be merged into one statement.",
			Evidence:    fmt.Sprintf("Statements %d and %d can merge Resources", e.From, e.To),
			StmtIndices: []int{e.From, e.To},
		})
	}
	return findings
}
