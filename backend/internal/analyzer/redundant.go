package analyzer

import (
	"fmt"

	"github.com/Kuba0517/iam-analyzer/internal/graph"
	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func DetectRedundant(p *model.Policy) []model.Finding {
	return detectRedundantFromGraph(graph.Build(p))
}

func detectRedundantFromGraph(g *graph.Graph) []model.Finding {
	var findings []model.Finding
	for _, e := range g.EdgesOfType(graph.Redundant) {
		findings = append(findings, model.Finding{
			Severity:    model.SeverityMedium,
			Title:       "Redundant statements",
			Explanation: "Two statements are identical and one can be removed.",
			Evidence:    fmt.Sprintf("Statements %d and %d are identical", e.From, e.To),
			StmtIndices: []int{e.From, e.To},
		})
	}
	return findings
}
