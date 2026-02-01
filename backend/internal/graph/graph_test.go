package graph

import (
	"testing"
)

func TestNewGraph(t *testing.T) {
	g := New()
	if g.NodeCount() != 0 {
		t.Errorf("expected 0 nodes, got %d", g.NodeCount())
	}
	if g.EdgeCount() != 0 {
		t.Errorf("expected 0 edges, got %d", g.EdgeCount())
	}
}

func TestAddNode(t *testing.T) {
	g := New()
	g.AddNode(Node{Index: 0, Fingerprint: "abc"})
	g.AddNode(Node{Index: 1, Fingerprint: "def"})

	if g.NodeCount() != 2 {
		t.Errorf("expected 2 nodes, got %d", g.NodeCount())
	}

	nodes := g.Nodes()
	if nodes[0].Fingerprint != "abc" {
		t.Errorf("expected fingerprint 'abc', got '%s'", nodes[0].Fingerprint)
	}
}

func TestAddEdge(t *testing.T) {
	g := New()
	g.AddNode(Node{Index: 0, Fingerprint: "a"})
	g.AddNode(Node{Index: 1, Fingerprint: "b"})
	g.AddEdge(Edge{From: 0, To: 1, Type: Redundant})

	if g.EdgeCount() != 1 {
		t.Errorf("expected 1 edge, got %d", g.EdgeCount())
	}

	edges := g.Edges()
	if edges[0].Type != Redundant {
		t.Errorf("expected Redundant edge, got %v", edges[0].Type)
	}
}

func TestEdgesOfType(t *testing.T) {
	g := New()
	g.AddNode(Node{Index: 0})
	g.AddNode(Node{Index: 1})
	g.AddNode(Node{Index: 2})
	g.AddEdge(Edge{From: 0, To: 1, Type: Redundant})
	g.AddEdge(Edge{From: 1, To: 2, Type: MergeableAction})
	g.AddEdge(Edge{From: 0, To: 2, Type: Redundant})

	redundant := g.EdgesOfType(Redundant)
	if len(redundant) != 2 {
		t.Errorf("expected 2 Redundant edges, got %d", len(redundant))
	}

	mergeable := g.EdgesOfType(MergeableAction)
	if len(mergeable) != 1 {
		t.Errorf("expected 1 MergeableAction edge, got %d", len(mergeable))
	}

	overlap := g.EdgesOfType(DenyAllowOverlap)
	if len(overlap) != 0 {
		t.Errorf("expected 0 DenyAllowOverlap edges, got %d", len(overlap))
	}
}

func TestEdgesFrom(t *testing.T) {
	g := New()
	g.AddNode(Node{Index: 0})
	g.AddNode(Node{Index: 1})
	g.AddNode(Node{Index: 2})
	g.AddEdge(Edge{From: 0, To: 1, Type: Redundant})
	g.AddEdge(Edge{From: 0, To: 2, Type: MergeableAction})
	g.AddEdge(Edge{From: 1, To: 2, Type: MergeableResource})

	edges := g.EdgesFrom(0)
	if len(edges) != 2 {
		t.Errorf("expected 2 edges from node 0, got %d", len(edges))
	}

	edges = g.EdgesFrom(1)
	if len(edges) != 1 {
		t.Errorf("expected 1 edge from node 1, got %d", len(edges))
	}
}

func TestEdgesInvolving(t *testing.T) {
	g := New()
	g.AddNode(Node{Index: 0})
	g.AddNode(Node{Index: 1})
	g.AddNode(Node{Index: 2})
	g.AddEdge(Edge{From: 0, To: 1, Type: Redundant})
	g.AddEdge(Edge{From: 1, To: 2, Type: MergeableAction})

	// Node 1 is involved in both edges.
	edges := g.EdgesInvolving(1)
	if len(edges) != 2 {
		t.Errorf("expected 2 edges involving node 1, got %d", len(edges))
	}

	// Node 0 is only involved in one edge.
	edges = g.EdgesInvolving(0)
	if len(edges) != 1 {
		t.Errorf("expected 1 edge involving node 0, got %d", len(edges))
	}
}

func TestNeighbors(t *testing.T) {
	g := New()
	g.AddNode(Node{Index: 0})
	g.AddNode(Node{Index: 1})
	g.AddNode(Node{Index: 2})
	g.AddEdge(Edge{From: 0, To: 1, Type: Redundant})
	g.AddEdge(Edge{From: 0, To: 2, Type: MergeableAction})

	neighbors := g.Neighbors(0)
	if len(neighbors) != 2 {
		t.Errorf("expected 2 neighbors for node 0, got %d", len(neighbors))
	}

	neighbors = g.Neighbors(1)
	if len(neighbors) != 1 {
		t.Errorf("expected 1 neighbor for node 1, got %d", len(neighbors))
	}
}

func TestHasEdge(t *testing.T) {
	g := New()
	g.AddNode(Node{Index: 0})
	g.AddNode(Node{Index: 1})
	g.AddEdge(Edge{From: 0, To: 1, Type: Redundant})

	if !g.HasEdge(0, 1, Redundant) {
		t.Error("expected edge from 0 to 1 of type Redundant")
	}

	// Should work in reverse direction too (undirected).
	if !g.HasEdge(1, 0, Redundant) {
		t.Error("expected edge from 1 to 0 of type Redundant (reverse)")
	}

	if g.HasEdge(0, 1, MergeableAction) {
		t.Error("did not expect edge of type MergeableAction")
	}
}

func TestEdgeTypeString(t *testing.T) {
	tests := []struct {
		et   EdgeType
		want string
	}{
		{Redundant, "Redundant"},
		{MergeableAction, "MergeableAction"},
		{MergeableResource, "MergeableResource"},
		{DenyAllowOverlap, "DenyAllowOverlap"},
		{EdgeType(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.et.String(); got != tt.want {
			t.Errorf("EdgeType(%d).String() = %s, want %s", tt.et, got, tt.want)
		}
	}
}
