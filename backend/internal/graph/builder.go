package graph

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func Build(p *model.Policy) *Graph {
	g := New()

	for i, s := range p.Statement {
		g.AddNode(Node{
			Index:       i,
			Fingerprint: fingerprint(s),
		})
	}

	for i := 0; i < len(p.Statement); i++ {
		for j := i + 1; j < len(p.Statement); j++ {
			addRelationshipEdges(g, p, i, j)
		}
	}

	addDenyAllowEdges(g, p)

	return g
}

func addRelationshipEdges(g *Graph, p *model.Policy, i, j int) {
	a := p.Statement[i]
	b := p.Statement[j]

	if g.Nodes()[i].Fingerprint == g.Nodes()[j].Fingerprint {
		g.AddEdge(Edge{From: i, To: j, Type: Redundant})
		return
	}

	if a.Effect != b.Effect {
		return
	}
	if !reflect.DeepEqual(a.Condition, b.Condition) {
		return
	}
	if !reflect.DeepEqual(a.Principal, b.Principal) {
		return
	}

	if reflect.DeepEqual(a.Resource, b.Resource) && !reflect.DeepEqual(a.Action, b.Action) {
		g.AddEdge(Edge{From: i, To: j, Type: MergeableAction})
	}

	if reflect.DeepEqual(a.Action, b.Action) && !reflect.DeepEqual(a.Resource, b.Resource) {
		g.AddEdge(Edge{From: i, To: j, Type: MergeableResource})
	}
}

func addDenyAllowEdges(g *Graph, p *model.Policy) {
	type actionSource struct {
		action string
		index  int
	}

	var allows, denies []actionSource
	for i, s := range p.Statement {
		for _, a := range s.Action {
			if s.Effect == "Allow" {
				allows = append(allows, actionSource{action: a, index: i})
			} else if s.Effect == "Deny" {
				denies = append(denies, actionSource{action: a, index: i})
			}
		}
	}

	seen := make(map[[2]int]bool)
	for _, d := range denies {
		for _, a := range allows {
			if !Overlaps(d.action, a.action) {
				continue
			}
			pair := [2]int{a.index, d.index}
			if seen[pair] {
				continue
			}
			seen[pair] = true

			overlapping := collectOverlappingActions(p.Statement[a.index], p.Statement[d.index])
			g.AddEdge(Edge{
				From: a.index,
				To:   d.index,
				Type: DenyAllowOverlap,
				Meta: EdgeMeta{OverlappingActions: overlapping},
			})
		}
	}
}

func collectOverlappingActions(allow, deny model.Statement) []string {
	var result []string
	seen := make(map[string]bool)
	for _, a := range allow.Action {
		for _, d := range deny.Action {
			if Overlaps(a, d) {
				key := a + "|" + d
				if !seen[key] {
					seen[key] = true
					if hasWildcard(a) && !hasWildcard(d) {
						result = append(result, d)
					} else {
						result = append(result, a)
					}
				}
			}
		}
	}
	return result
}

func fingerprint(s model.Statement) string {
	data, _ := json.Marshal(s)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash[:8])
}
