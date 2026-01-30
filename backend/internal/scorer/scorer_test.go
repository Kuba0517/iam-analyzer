package scorer_test

import (
	"testing"

	"github.com/Kuba0517/iam-analyzer/internal/model"
	"github.com/Kuba0517/iam-analyzer/internal/scorer"
)

func TestScore_SimplePolicy(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket/*"}},
		},
	}

	result := scorer.Score(p)
	if result.Score != 0 {
		t.Errorf("expected score 0 for simple policy, got %d", result.Score)
	}
	if result.Rank != "A" {
		t.Errorf("expected rank A, got %s", result.Rank)
	}
}

func TestScore_WildcardPolicy(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"*"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	result := scorer.Score(p)
	if result.Score == 0 {
		t.Error("expected non-zero score for wildcard policy")
	}
}

func TestScore_DenyAllowOverlap(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject", "s3:PutObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Deny", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	result := scorer.Score(p)
	found := false
	for _, b := range result.Breakdown {
		if b.Label == "Deny/Allow overlap" && b.Score > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected Deny/Allow overlap to have a score > 0")
	}
}

func TestScore_NegativeStatements(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", NotAction: model.StringOrSlice{"s3:DeleteObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"ec2:*"}, NotResource: model.StringOrSlice{"arn:aws:ec2:::secret"}},
		},
	}

	result := scorer.Score(p)
	found := false
	for _, b := range result.Breakdown {
		if b.Label == "Negative statements (NotAction/NotResource)" && b.Score > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected negative elements to have a score > 0")
	}
}

func TestScore_ManyStatements(t *testing.T) {
	stmts := make([]model.Statement, 25)
	for i := range stmts {
		stmts[i] = model.Statement{
			Effect:   "Allow",
			Action:   model.StringOrSlice{"s3:GetObject"},
			Resource: model.StringOrSlice{"*"},
		}
	}

	p := &model.Policy{Version: "2012-10-17", Statement: stmts}
	result := scorer.Score(p)

	found := false
	for _, b := range result.Breakdown {
		if b.Label == "Statement count" && b.Score == 15 {
			found = true
		}
	}
	if !found {
		t.Error("expected statement count score of 15 for 25 statements")
	}
}
