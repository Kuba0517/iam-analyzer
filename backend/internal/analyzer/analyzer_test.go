package analyzer_test

import (
	"testing"

	"github.com/Kuba0517/iam-analyzer/internal/analyzer"
	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func TestAnalyze_ReturnsFindings(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"*"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	findings := analyzer.Analyze(p)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for wildcard policy")
	}
}

func TestAnalyze_SortsBySeverity(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::other"}},
			{Effect: "Deny", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	findings := analyzer.Analyze(p)
	for i := 1; i < len(findings); i++ {
		if severityRank(findings[i].Severity) > severityRank(findings[i-1].Severity) {
			t.Errorf("findings not sorted by severity: %s before %s", findings[i-1].Severity, findings[i].Severity)
		}
	}
}

func TestDetectRedundant(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	findings := analyzer.DetectRedundant(p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityMedium {
		t.Errorf("expected medium severity, got %s", findings[0].Severity)
	}
}

func TestDetectRedundant_NoDuplicates(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:PutObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	findings := analyzer.DetectRedundant(p)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestDetectMergeCandidates_SameResources(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket/*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:PutObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket/*"}},
		},
	}

	findings := analyzer.DetectMergeCandidates(p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 merge candidate, got %d", len(findings))
	}
	if findings[0].Title != "Merge candidates (same resources)" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

func TestDetectMergeCandidates_SameActions(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket-a/*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket-b/*"}},
		},
	}

	findings := analyzer.DetectMergeCandidates(p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 merge candidate, got %d", len(findings))
	}
	if findings[0].Title != "Merge candidates (same actions)" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

func TestDetectMergeCandidates_DifferentEffect(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Deny", Action: model.StringOrSlice{"s3:PutObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	findings := analyzer.DetectMergeCandidates(p)
	if len(findings) != 0 {
		t.Fatalf("expected 0 merge candidates for different effects, got %d", len(findings))
	}
}

func TestDetectWildcardOveruse_BothWildcard(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"*"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	findings := analyzer.DetectWildcardOveruse(p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityHigh {
		t.Errorf("expected high severity, got %s", findings[0].Severity)
	}
}

func TestDetectWildcardOveruse_ActionOnly(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"*"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket/*"}},
		},
	}

	findings := analyzer.DetectWildcardOveruse(p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityMedium {
		t.Errorf("expected medium severity, got %s", findings[0].Severity)
	}
}

func TestDetectWildcardOveruse_NoWildcard(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket/*"}},
		},
	}

	findings := analyzer.DetectWildcardOveruse(p)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestDetectNegativeElements_NotAction(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", NotAction: model.StringOrSlice{"s3:DeleteObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	findings := analyzer.DetectNegativeElements(p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Title != "Usage of NotAction" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

func TestDetectNegativeElements_NotResource(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, NotResource: model.StringOrSlice{"arn:aws:s3:::secret"}},
		},
	}

	findings := analyzer.DetectNegativeElements(p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Title != "Usage of NotResource" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

func TestDetectNegativeElements_Both(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", NotAction: model.StringOrSlice{"s3:DeleteObject"}, NotResource: model.StringOrSlice{"arn:aws:s3:::secret"}},
		},
	}

	findings := analyzer.DetectNegativeElements(p)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestDetectNegativeElements_None(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	findings := analyzer.DetectNegativeElements(p)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestDetectDenyAllowOverlap(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject", "s3:PutObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Deny", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	findings := analyzer.DetectDenyAllowOverlap(p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityHigh {
		t.Errorf("expected high severity, got %s", findings[0].Severity)
	}
}

func TestDetectDenyAllowOverlap_NoOverlap(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Deny", Action: model.StringOrSlice{"s3:DeleteObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	findings := analyzer.DetectDenyAllowOverlap(p)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestDetectDenyAllowOverlap_NoDuplicateFindings(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject", "s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Deny", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	findings := analyzer.DetectDenyAllowOverlap(p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (no duplicates), got %d", len(findings))
	}
}

// helper to mirror the unexported severityRank in analyzer.go
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
