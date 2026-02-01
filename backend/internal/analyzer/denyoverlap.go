package analyzer

import (
	"fmt"

	"github.com/Kuba0517/iam-analyzer/internal/graph"
	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func DetectDenyAllowOverlap(p *model.Policy) []model.Finding {
	return detectDenyAllowOverlapFromGraph(graph.Build(p), p)
}

func detectDenyAllowOverlapFromGraph(g *graph.Graph, p *model.Policy) []model.Finding {
	var findings []model.Finding

	for _, e := range g.EdgesOfType(graph.DenyAllowOverlap) {
		allowIdx, denyIdx := e.From, e.To
		if p.Statement[allowIdx].Effect != "Allow" {
			allowIdx, denyIdx = denyIdx, allowIdx
		}

		for _, action := range e.Meta.OverlappingActions {
			findings = append(findings, model.Finding{
				Severity:    model.SeverityHigh,
				Title:       "Deny/Allow overlap",
				Explanation: fmt.Sprintf("Action %q is both allowed and denied. The Deny will take precedence, but this may indicate a misconfiguration.", action),
				Evidence:    fmt.Sprintf("Action %q in Allow statement %d and Deny statement %d", action, allowIdx, denyIdx),
				StmtIndices: []int{allowIdx, denyIdx},
			})
		}
	}

	return findings
}
