package analyzer

import (
	"fmt"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func DetectNegativeElements(p *model.Policy) []model.Finding {
	var findings []model.Finding

	for i, s := range p.Statement {
		if len(s.NotAction) > 0 {
			findings = append(findings, model.Finding{
				Severity:    model.SeverityMedium,
				Title:       "Usage of NotAction",
				Explanation: "NotAction inverts the action match. This is error-prone and can unintentionally grant broad permissions.",
				Evidence:    fmt.Sprintf("Statement %d uses NotAction", i),
				StmtIndices: []int{i},
			})
		}
		if len(s.NotResource) > 0 {
			findings = append(findings, model.Finding{
				Severity:    model.SeverityMedium,
				Title:       "Usage of NotResource",
				Explanation: "NotResource inverts the resource match. This is error-prone and can unintentionally expose resources.",
				Evidence:    fmt.Sprintf("Statement %d uses NotResource", i),
				StmtIndices: []int{i},
			})
		}
	}

	return findings
}
