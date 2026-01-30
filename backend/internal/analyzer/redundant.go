package analyzer

import (
	"fmt"
	"reflect"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func DetectRedundant(p *model.Policy) []model.Finding {
	var findings []model.Finding

	for i := 0; i < len(p.Statement); i++ {
		for j := i + 1; j < len(p.Statement); j++ {
			if reflect.DeepEqual(p.Statement[i], p.Statement[j]) {
				findings = append(findings, model.Finding{
					Severity:    model.SeverityMedium,
					Title:       "Redundant statements",
					Explanation: "Two statements are identical and one can be removed.",
					Evidence:    fmt.Sprintf("Statements %d and %d are identical", i, j),
					StmtIndices: []int{i, j},
				})
			}
		}
	}
	return findings
}
