package graph

type Graph struct {
	nodes     []Node
	edges     []Edge
	adjacency map[int][]int
}

func New() *Graph {
	return &Graph{
		nodes:     make([]Node, 0),
		edges:     make([]Edge, 0),
		adjacency: make(map[int][]int),
	}
}

func (g *Graph) AddNode(n Node) {
	g.nodes = append(g.nodes, n)
	if _, ok := g.adjacency[n.Index]; !ok {
		g.adjacency[n.Index] = make([]int, 0)
	}
}

func (g *Graph) AddEdge(e Edge) {
	edgeIdx := len(g.edges)
	g.edges = append(g.edges, e)
	g.adjacency[e.From] = append(g.adjacency[e.From], edgeIdx)
	// Also add reverse lookup for undirected relationships.
	g.adjacency[e.To] = append(g.adjacency[e.To], edgeIdx)
}

func (g *Graph) Nodes() []Node {
	return g.nodes
}

func (g *Graph) Edges() []Edge {
	return g.edges
}

func (g *Graph) EdgesOfType(t EdgeType) []Edge {
	result := make([]Edge, 0)
	for _, e := range g.edges {
		if e.Type == t {
			result = append(result, e)
		}
	}
	return result
}

func (g *Graph) EdgesFrom(nodeIdx int) []Edge {
	result := make([]Edge, 0)
	for _, edgeIdx := range g.adjacency[nodeIdx] {
		e := g.edges[edgeIdx]
		if e.From == nodeIdx {
			result = append(result, e)
		}
	}
	return result
}

func (g *Graph) EdgesInvolving(nodeIdx int) []Edge {
	result := make([]Edge, 0)
	seen := make(map[int]bool)
	for _, edgeIdx := range g.adjacency[nodeIdx] {
		if !seen[edgeIdx] {
			result = append(result, g.edges[edgeIdx])
			seen[edgeIdx] = true
		}
	}
	return result
}

func (g *Graph) Neighbors(nodeIdx int) []int {
	neighbors := make(map[int]bool)
	for _, edgeIdx := range g.adjacency[nodeIdx] {
		e := g.edges[edgeIdx]
		if e.From == nodeIdx {
			neighbors[e.To] = true
		} else {
			neighbors[e.From] = true
		}
	}
	result := make([]int, 0, len(neighbors))
	for idx := range neighbors {
		result = append(result, idx)
	}
	return result
}

func (g *Graph) NodeCount() int {
	return len(g.nodes)
}

func (g *Graph) EdgeCount() int {
	return len(g.edges)
}

func (g *Graph) HasEdge(from, to int, t EdgeType) bool {
	for _, edgeIdx := range g.adjacency[from] {
		e := g.edges[edgeIdx]
		if e.Type == t && ((e.From == from && e.To == to) || (e.From == to && e.To == from)) {
			return true
		}
	}
	return false
}
