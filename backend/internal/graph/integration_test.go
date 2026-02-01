package graph_test

import (
	"testing"

	"github.com/Kuba0517/iam-analyzer/internal/analyzer"
	"github.com/Kuba0517/iam-analyzer/internal/model"
	"github.com/Kuba0517/iam-analyzer/internal/normalizer"
	"github.com/Kuba0517/iam-analyzer/internal/parser"
	"github.com/Kuba0517/iam-analyzer/internal/scorer"
	"github.com/Kuba0517/iam-analyzer/internal/simplifier"
)

func TestFullPipeline_OverprivilegedPolicy(t *testing.T) {
	raw := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": "*", "Resource": "*"},
			{"Effect": "Allow", "Action": "*", "Resource": "*"},
			{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"},
			{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::bucket/*"},
			{"Effect": "Deny",  "Action": "s3:GetObject", "Resource": "*"},
			{"Effect": "Allow", "NotAction": "s3:DeleteObject", "Resource": "*"}
		]
	}`)

	policy, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	normalized := normalizer.Normalize(policy)
	findings := analyzer.Analyze(normalized)
	score := scorer.Score(normalized)
	patches := simplifier.Suggest(normalized)

	if len(findings) == 0 {
		t.Fatal("expected findings for overprivileged policy")
	}

	findingTitles := make(map[string]bool)
	for _, f := range findings {
		findingTitles[f.Title] = true
	}

	expected := []string{
		"Redundant statements",
		"Merge candidates (same resources)",
		"Full wildcard statement",
		"Deny/Allow overlap",
		"Usage of NotAction",
	}
	for _, title := range expected {
		if !findingTitles[title] {
			t.Errorf("missing expected finding: %q", title)
		}
	}

	for i := 1; i < len(findings); i++ {
		if severityRank(findings[i].Severity) > severityRank(findings[i-1].Severity) {
			t.Errorf("findings not sorted: %s before %s", findings[i-1].Severity, findings[i].Severity)
		}
	}

	if score.Score == 0 {
		t.Error("expected non-zero score for overprivileged policy")
	}

	if len(patches) < 2 {
		t.Errorf("expected at least 2 patches, got %d", len(patches))
	}
}

func TestFullPipeline_MinimalPolicy(t *testing.T) {
	raw := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}
		]
	}`)

	policy, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	normalized := normalizer.Normalize(policy)
	findings := analyzer.Analyze(normalized)
	score := scorer.Score(normalized)
	patches := simplifier.Suggest(normalized)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for minimal policy, got %d", len(findings))
	}
	if score.Score != 0 {
		t.Errorf("expected score 0 for minimal policy, got %d", score.Score)
	}
	if len(patches) != 0 {
		t.Errorf("expected 0 patches for minimal policy, got %d", len(patches))
	}
}

func TestFullPipeline_ApplyPatches(t *testing.T) {
	raw := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"},
			{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"},
			{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::bucket/*"}
		]
	}`)

	policy, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	normalized := normalizer.Normalize(policy)
	patches := simplifier.Suggest(normalized)

	if len(patches) == 0 {
		t.Fatal("expected patches for policy with redundant+mergeable statements")
	}

	ids := []string{patches[0].ID}
	simplified := simplifier.Apply(normalized, patches, ids)

	if len(simplified.Statement) >= len(normalized.Statement) {
		t.Errorf("expected fewer statements after applying patch, got %d (was %d)",
			len(simplified.Statement), len(normalized.Statement))
	}

	findingsBefore := len(analyzer.Analyze(normalized))
	findingsAfter := len(analyzer.Analyze(simplified))
	if findingsAfter >= findingsBefore {
		t.Errorf("expected fewer findings after simplification: before=%d, after=%d",
			findingsBefore, findingsAfter)
	}
}

func TestFullPipeline_WildcardOverlapDetection(t *testing.T) {
	raw := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
			{"Effect": "Deny",  "Action": "s3:DeleteObject", "Resource": "*"}
		]
	}`)

	policy, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	normalized := normalizer.Normalize(policy)
	findings := analyzer.Analyze(normalized)

	hasOverlap := false
	for _, f := range findings {
		if f.Title == "Deny/Allow overlap" {
			hasOverlap = true
			break
		}
	}
	if !hasOverlap {
		t.Error("expected Deny/Allow overlap finding for s3:* vs s3:DeleteObject")
	}
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
