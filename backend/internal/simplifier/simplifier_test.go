package simplifier_test

import (
	"testing"

	"github.com/Kuba0517/iam-analyzer/internal/model"
	"github.com/Kuba0517/iam-analyzer/internal/simplifier"
)

func TestSuggest_RedundantStatements(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	patches := simplifier.Suggest(p)
	if len(patches) == 0 {
		t.Fatal("expected at least one patch for redundant statements")
	}

	found := false
	for _, patch := range patches {
		if patch.ID == "dedup-0" {
			found = true
		}
	}
	if !found {
		t.Error("expected a dedup patch")
	}
}

func TestSuggest_MergeActions(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket/*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:PutObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket/*"}},
		},
	}

	patches := simplifier.Suggest(p)
	if len(patches) == 0 {
		t.Fatal("expected at least one merge patch")
	}

	found := false
	for _, patch := range patches {
		if patch.ID == "merge-0" {
			found = true
		}
	}
	if !found {
		t.Error("expected a merge patch")
	}
}

func TestSuggest_MergeResources(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket-a/*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket-b/*"}},
		},
	}

	patches := simplifier.Suggest(p)
	if len(patches) == 0 {
		t.Fatal("expected at least one merge patch")
	}
}

func TestSuggest_NothingToSuggest(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket/*"}},
		},
	}

	patches := simplifier.Suggest(p)
	if len(patches) != 0 {
		t.Fatalf("expected 0 patches, got %d", len(patches))
	}
}

func TestApply_RemoveRedundant(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	patches := simplifier.Suggest(p)
	result := simplifier.Apply(p, patches, []string{"dedup-0"})

	if len(result.Statement) != 1 {
		t.Fatalf("expected 1 statement after dedup, got %d", len(result.Statement))
	}
}

func TestApply_MergeActions(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket/*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:PutObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket/*"}},
		},
	}

	patches := simplifier.Suggest(p)
	result := simplifier.Apply(p, patches, []string{"merge-0"})

	if len(result.Statement) != 1 {
		t.Fatalf("expected 1 statement after merge, got %d", len(result.Statement))
	}
	if len(result.Statement[0].Action) != 2 {
		t.Fatalf("expected 2 actions after merge, got %d", len(result.Statement[0].Action))
	}
}

func TestApply_DoesNotMutateOriginal(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	patches := simplifier.Suggest(p)
	simplifier.Apply(p, patches, []string{"dedup-0"})

	if len(p.Statement) != 2 {
		t.Fatalf("original was mutated: expected 2 statements, got %d", len(p.Statement))
	}
}

func TestApply_NoSelectedPatches(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	patches := simplifier.Suggest(p)
	result := simplifier.Apply(p, patches, []string{})

	if len(result.Statement) != 2 {
		t.Fatalf("expected 2 statements when no patches selected, got %d", len(result.Statement))
	}
}
