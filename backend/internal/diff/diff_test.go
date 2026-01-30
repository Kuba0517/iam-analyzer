package diff_test

import (
	"strings"
	"testing"

	"github.com/Kuba0517/iam-analyzer/internal/diff"
	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func TestUnified_IdenticalPolicies(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	result, err := diff.Unified("original", p, "copy", p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(result, "-") && strings.Contains(result, "+") {
		// Check for actual diff lines, not the header
		lines := strings.Split(result, "\n")
		for _, line := range lines[2:] { // skip --- and +++ headers
			if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "+") {
				t.Error("expected no diff for identical policies")
				break
			}
		}
	}
}

func TestUnified_DifferentActions(t *testing.T) {
	p1 := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}
	p2 := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:PutObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	result, err := diff.Unified("original", p1, "modified", p2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "-") || !strings.Contains(result, "+") {
		t.Error("expected diff to contain additions and removals")
	}
	if !strings.Contains(result, "s3:GetObject") {
		t.Error("expected diff to reference s3:GetObject")
	}
	if !strings.Contains(result, "s3:PutObject") {
		t.Error("expected diff to reference s3:PutObject")
	}
}

func TestUnified_Headers(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	result, err := diff.Unified("original", p, "normalized", p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(result, "--- original\n+++ normalized\n") {
		t.Errorf("expected unified diff headers, got:\n%s", result)
	}
}

func TestUnified_AddedStatement(t *testing.T) {
	p1 := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}
	p2 := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Deny", Action: model.StringOrSlice{"s3:DeleteObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	result, err := diff.Unified("before", p1, "after", p2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasAddition := false
	lines := strings.Split(result, "\n")
	for _, line := range lines[2:] {
		if strings.HasPrefix(line, "+") {
			hasAddition = true
			break
		}
	}
	if !hasAddition {
		t.Error("expected diff to show added lines for the new statement")
	}
}

func TestUnified_RemovedStatement(t *testing.T) {
	p1 := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Deny", Action: model.StringOrSlice{"s3:DeleteObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}
	p2 := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	result, err := diff.Unified("before", p1, "after", p2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasRemoval := false
	lines := strings.Split(result, "\n")
	for _, line := range lines[2:] {
		if strings.HasPrefix(line, "-") {
			hasRemoval = true
			break
		}
	}
	if !hasRemoval {
		t.Error("expected diff to show removed lines for the deleted statement")
	}
}
