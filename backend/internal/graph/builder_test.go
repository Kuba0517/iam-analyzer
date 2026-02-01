package graph

import (
	"testing"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func policyWith(stmts ...model.Statement) *model.Policy {
	return &model.Policy{
		Version:   "2012-10-17",
		Statement: stmts,
	}
}

func stmt(effect string, actions, resources []string) model.Statement {
	return model.Statement{
		Effect:   effect,
		Action:   actions,
		Resource: resources,
	}
}

func TestBuild_RedundantStatements(t *testing.T) {
	p := policyWith(
		stmt("Allow", []string{"s3:GetObject"}, []string{"*"}),
		stmt("Allow", []string{"s3:GetObject"}, []string{"*"}),
	)

	g := Build(p)

	if g.NodeCount() != 2 {
		t.Fatalf("expected 2 nodes, got %d", g.NodeCount())
	}

	edges := g.EdgesOfType(Redundant)
	if len(edges) != 1 {
		t.Fatalf("expected 1 Redundant edge, got %d", len(edges))
	}
	if edges[0].From != 0 || edges[0].To != 1 {
		t.Errorf("expected edge 0→1, got %d→%d", edges[0].From, edges[0].To)
	}
}

func TestBuild_MergeableActions(t *testing.T) {
	p := policyWith(
		stmt("Allow", []string{"s3:GetObject"}, []string{"*"}),
		stmt("Allow", []string{"s3:PutObject"}, []string{"*"}),
	)

	g := Build(p)

	edges := g.EdgesOfType(MergeableAction)
	if len(edges) != 1 {
		t.Fatalf("expected 1 MergeableAction edge, got %d", len(edges))
	}
}

func TestBuild_MergeableResources(t *testing.T) {
	p := policyWith(
		stmt("Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket-a/*"}),
		stmt("Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket-b/*"}),
	)

	g := Build(p)

	edges := g.EdgesOfType(MergeableResource)
	if len(edges) != 1 {
		t.Fatalf("expected 1 MergeableResource edge, got %d", len(edges))
	}
}

func TestBuild_DenyAllowOverlap(t *testing.T) {
	p := policyWith(
		stmt("Allow", []string{"s3:GetObject"}, []string{"*"}),
		stmt("Deny", []string{"s3:GetObject"}, []string{"*"}),
	)

	g := Build(p)

	edges := g.EdgesOfType(DenyAllowOverlap)
	if len(edges) != 1 {
		t.Fatalf("expected 1 DenyAllowOverlap edge, got %d", len(edges))
	}
	if len(edges[0].Meta.OverlappingActions) != 1 {
		t.Fatalf("expected 1 overlapping action, got %d", len(edges[0].Meta.OverlappingActions))
	}
	if edges[0].Meta.OverlappingActions[0] != "s3:GetObject" {
		t.Errorf("expected overlapping action 's3:GetObject', got %q", edges[0].Meta.OverlappingActions[0])
	}
}

func TestBuild_DenyAllowOverlap_Wildcard(t *testing.T) {
	p := policyWith(
		stmt("Allow", []string{"s3:*"}, []string{"*"}),
		stmt("Deny", []string{"s3:GetObject"}, []string{"*"}),
	)

	g := Build(p)

	edges := g.EdgesOfType(DenyAllowOverlap)
	if len(edges) != 1 {
		t.Fatalf("expected 1 DenyAllowOverlap edge, got %d", len(edges))
	}
}

func TestBuild_NoEdges(t *testing.T) {
	p := policyWith(
		stmt("Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket-a/*"}),
		stmt("Deny", []string{"ec2:DescribeInstances"}, []string{"*"}),
	)

	g := Build(p)

	if g.EdgeCount() != 0 {
		t.Errorf("expected 0 edges, got %d", g.EdgeCount())
	}
}

func TestBuild_DifferentEffects_NotMergeable(t *testing.T) {
	p := policyWith(
		stmt("Allow", []string{"s3:GetObject"}, []string{"*"}),
		stmt("Deny", []string{"s3:PutObject"}, []string{"*"}),
	)

	g := Build(p)

	if len(g.EdgesOfType(MergeableAction)) != 0 {
		t.Error("should not merge statements with different effects")
	}
}

func TestBuild_RedundantSkipsMerge(t *testing.T) {
	p := policyWith(
		stmt("Allow", []string{"s3:GetObject"}, []string{"*"}),
		stmt("Allow", []string{"s3:GetObject"}, []string{"*"}),
	)

	g := Build(p)

	if len(g.EdgesOfType(MergeableAction)) != 0 {
		t.Error("redundant statements should not also be marked as mergeable")
	}
	if len(g.EdgesOfType(MergeableResource)) != 0 {
		t.Error("redundant statements should not also be marked as mergeable")
	}
}
