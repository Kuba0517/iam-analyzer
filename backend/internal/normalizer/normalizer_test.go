package normalizer_test

import (
	"testing"

	"github.com/Kuba0517/iam-analyzer/internal/model"
	"github.com/Kuba0517/iam-analyzer/internal/normalizer"
)

func TestNormalize_DeduplicatesActions(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{
				Effect:   "Allow",
				Action:   model.StringOrSlice{"s3:GetObject", "s3:GetObject", "s3:PutObject"},
				Resource: model.StringOrSlice{"*"},
			},
		},
	}

	n := normalizer.Normalize(p)
	actions := n.Statement[0].Action
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions after dedup, got %d: %v", len(actions), actions)
	}
	if actions[0] != "s3:GetObject" || actions[1] != "s3:PutObject" {
		t.Errorf("expected [s3:GetObject, s3:PutObject], got %v", actions)
	}
}

func TestNormalize_SortsStatements(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Deny", Action: model.StringOrSlice{"s3:DeleteObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"ec2:StartInstances"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	n := normalizer.Normalize(p)

	if n.Statement[0].Effect != "Allow" || n.Statement[0].Action[0] != "ec2:StartInstances" {
		t.Errorf("expected first statement Allow/ec2:StartInstances, got %s/%s", n.Statement[0].Effect, n.Statement[0].Action[0])
	}
	if n.Statement[1].Effect != "Allow" || n.Statement[1].Action[0] != "s3:GetObject" {
		t.Errorf("expected second statement Allow/s3:GetObject, got %s/%s", n.Statement[1].Effect, n.Statement[1].Action[0])
	}
	if n.Statement[2].Effect != "Deny" {
		t.Errorf("expected third statement Deny, got %s", n.Statement[2].Effect)
	}
}

func TestNormalize_DoesNotMutateOriginal(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{
				Effect:   "Allow",
				Action:   model.StringOrSlice{"b", "a", "a"},
				Resource: model.StringOrSlice{"*"},
			},
		},
	}

	originalAction := make([]string, len(p.Statement[0].Action))
	copy(originalAction, p.Statement[0].Action)

	normalizer.Normalize(p)

	for i, a := range p.Statement[0].Action {
		if a != originalAction[i] {
			t.Fatalf("original was mutated: expected %v, got %v", originalAction, p.Statement[0].Action)
		}
	}
}
