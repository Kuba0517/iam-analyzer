package graph

import (
	"testing"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func TestSerialize_Nodes(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"arn:aws:s3:::bucket/*"}},
			{Effect: "Deny", Action: model.StringOrSlice{"s3:DeleteObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	g := Build(p)
	data := Serialize(g, p)

	if len(data.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(data.Nodes))
	}

	if data.Nodes[0].Effect != "Allow" {
		t.Errorf("expected node 0 effect Allow, got %s", data.Nodes[0].Effect)
	}
	if data.Nodes[0].Label != "S0: Allow s3:GetObject on arn:aws:s3:::bucket/*" {
		t.Errorf("unexpected label: %s", data.Nodes[0].Label)
	}
	if data.Nodes[1].Effect != "Deny" {
		t.Errorf("expected node 1 effect Deny, got %s", data.Nodes[1].Effect)
	}
}

func TestSerialize_Edges(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	g := Build(p)
	data := Serialize(g, p)

	if len(data.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(data.Edges))
	}
	if data.Edges[0].Type != "Redundant" {
		t.Errorf("expected Redundant edge, got %s", data.Edges[0].Type)
	}
	if data.Edges[0].Label != "Duplicate" {
		t.Errorf("expected label 'Duplicate', got %s", data.Edges[0].Label)
	}
}

func TestSerialize_MultipleActions(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	g := Build(p)
	data := Serialize(g, p)

	if data.Nodes[0].Label != "S0: Allow s3:GetObject +2 on *" {
		t.Errorf("unexpected label: %s", data.Nodes[0].Label)
	}
}

func TestSerialize_DenyAllowOverlapEdge(t *testing.T) {
	p := &model.Policy{
		Version: "2012-10-17",
		Statement: []model.Statement{
			{Effect: "Allow", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
			{Effect: "Deny", Action: model.StringOrSlice{"s3:GetObject"}, Resource: model.StringOrSlice{"*"}},
		},
	}

	g := Build(p)
	data := Serialize(g, p)

	hasOverlap := false
	for _, e := range data.Edges {
		if e.Type == "DenyAllowOverlap" {
			hasOverlap = true
			if e.Label != "Overlap: s3:GetObject" {
				t.Errorf("unexpected overlap label: %s", e.Label)
			}
		}
	}
	if !hasOverlap {
		t.Error("expected DenyAllowOverlap edge")
	}
}
