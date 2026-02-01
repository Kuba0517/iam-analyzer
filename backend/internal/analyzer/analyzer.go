package analyzer

import (
	"sort"

	"github.com/Kuba0517/iam-analyzer/internal/graph"
	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func Analyze(p *model.Policy) []model.Finding {
	g := graph.Build(p)

	var findings []model.Finding
	findings = append(findings, detectRedundantFromGraph(g)...)
	findings = append(findings, detectMergeCandidatesFromGraph(g)...)
	findings = append(findings, DetectWildcardOveruse(p)...)
	findings = append(findings, DetectNegativeElements(p)...)
	findings = append(findings, detectDenyAllowOverlapFromGraph(g, p)...)

	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})

	return findings
}

func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	default:
		return 0
	}
}
