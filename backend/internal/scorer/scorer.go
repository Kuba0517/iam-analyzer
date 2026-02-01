package scorer

import (
	"fmt"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func Score(p *model.Policy) model.ScoreResult {
	factors := []model.ScoreBreakdown{
		statementCount(p),
		wildcardActionPct(p),
		wildcardResourcePct(p),
		negativeStatements(p),
		denyAllowOverlap(p),
	}

	total := 0
	for _, f := range factors {
		total += f.Score
	}
	if total > 100 {
		total = 100
	}

	return model.ScoreResult{
		Score:     total,
		Rank:      rankFromScore(total),
		Breakdown: factors,
	}
}

func rankFromScore(score int) string {
	switch {
	case score <= 20:
		return "A"
	case score <= 40:
		return "B"
	case score <= 60:
		return "C"
	case score <= 80:
		return "D"
	default:
		return "F"
	}
}

func statementCount(p *model.Policy) model.ScoreBreakdown {
	n := len(p.Statement)
	var pts int
	switch {
	case n <= 5:
		pts = 0
	case n <= 10:
		pts = 5
	case n <= 20:
		pts = 10
	case n <= 50:
		pts = 15
	default:
		pts = 20
	}

	return model.ScoreBreakdown{
		Label: "Statement count",
		Value: fmt.Sprintf("%d statements", n),
		Score: pts,
	}
}

func wildcardActionPct(p *model.Policy) model.ScoreBreakdown {
	total := len(p.Statement)
	if total == 0 {
		return model.ScoreBreakdown{Label: "Wildcard actions", Value: "0%", Score: 0}
	}

	count := 0
	for _, s := range p.Statement {
		for _, a := range s.Action {
			if a == "*" {
				count++
				break
			}
		}
	}

	pct := count * 100 / total
	return model.ScoreBreakdown{
		Label: "Wildcard actions",
		Value: fmt.Sprintf("%d%% (%d/%d statements)", pct, count, total),
		Score: pctToScore(pct),
	}
}

func wildcardResourcePct(p *model.Policy) model.ScoreBreakdown {
	total := len(p.Statement)
	if total == 0 {
		return model.ScoreBreakdown{Label: "Wildcard resources", Value: "0%", Score: 0}
	}

	count := 0
	for _, s := range p.Statement {
		for _, r := range s.Resource {
			if r == "*" {
				count++
				break
			}
		}
	}

	pct := count * 100 / total
	return model.ScoreBreakdown{
		Label: "Wildcard resources",
		Value: fmt.Sprintf("%d%% (%d/%d statements)", pct, count, total),
		Score: pctToScore(pct),
	}
}

func pctToScore(pct int) int {
	switch {
	case pct == 0:
		return 0
	case pct < 10:
		return 5
	case pct < 25:
		return 10
	case pct < 50:
		return 15
	default:
		return 20
	}
}

func negativeStatements(p *model.Policy) model.ScoreBreakdown {
	count := 0
	for _, s := range p.Statement {
		if len(s.NotAction) > 0 {
			count++
		}
		if len(s.NotResource) > 0 {
			count++
		}
	}

	pts := count * 5
	if pts > 20 {
		pts = 20
	}

	return model.ScoreBreakdown{
		Label: "Negative statements (NotAction/NotResource)",
		Value: fmt.Sprintf("%d occurrences", count),
		Score: pts,
	}
}

func denyAllowOverlap(p *model.Policy) model.ScoreBreakdown {
	allowActions := make(map[string]bool)
	for _, s := range p.Statement {
		if s.Effect == "Allow" {
			for _, a := range s.Action {
				allowActions[a] = true
			}
		}
	}

	overlapCount := 0
	for _, s := range p.Statement {
		if s.Effect == "Deny" {
			for _, a := range s.Action {
				if allowActions[a] {
					overlapCount++
				}
			}
		}
	}

	pts := overlapCount * 5
	if pts > 20 {
		pts = 20
	}

	return model.ScoreBreakdown{
		Label: "Deny/Allow overlap",
		Value: fmt.Sprintf("%d overlapping actions", overlapCount),
		Score: pts,
	}
}
