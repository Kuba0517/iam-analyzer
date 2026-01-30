package analyzer

import (
	"sort"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

type Detector func(p *model.Policy) []model.Finding

func Analyze(p *model.Policy) []model.Finding {
	detectors := []Detector{
		DetectRedundant,
		DetectMergeCandidates,
		DetectWildcardOveruse,
		DetectNegativeElements,
		DetectDenyAllowOverlap,
	}

	var findings []model.Finding
	for _, d := range detectors {
		findings = append(findings, d(p)...)
	}

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
