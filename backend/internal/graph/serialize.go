package graph

import (
	"fmt"
	"strings"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func Serialize(g *Graph, p *model.Policy) model.GraphData {
	nodes := make([]model.GraphNode, 0, len(p.Statement))
	for i, s := range p.Statement {
		nodes = append(nodes, model.GraphNode{
			Index:  i,
			Label:  statementLabel(i, s),
			Effect: s.Effect,
		})
	}

	edges := make([]model.GraphEdge, 0, len(g.Edges()))
	for _, e := range g.Edges() {
		edges = append(edges, model.GraphEdge{
			From:  e.From,
			To:    e.To,
			Type:  e.Type.String(),
			Label: edgeLabel(e),
		})
	}

	return model.GraphData{Nodes: nodes, Edges: edges}
}

func statementLabel(idx int, s model.Statement) string {
	actions := s.Action
	if len(actions) == 0 {
		actions = s.NotAction
	}

	actionStr := "*"
	if len(actions) > 0 {
		actionStr = actions[0]
		if len(actions) > 1 {
			actionStr = fmt.Sprintf("%s +%d", actions[0], len(actions)-1)
		}
	}

	resources := s.Resource
	if len(resources) == 0 {
		resources = s.NotResource
	}

	resourceStr := "*"
	if len(resources) > 0 {
		resourceStr = resources[0]
		if len(resources) > 1 {
			resourceStr = fmt.Sprintf("%s +%d", resources[0], len(resources)-1)
		}
	}

	return fmt.Sprintf("S%d: %s %s on %s", idx, s.Effect, actionStr, resourceStr)
}

func edgeLabel(e Edge) string {
	switch e.Type {
	case Redundant:
		return "Duplicate"
	case MergeableAction:
		return "Merge actions"
	case MergeableResource:
		return "Merge resources"
	case DenyAllowOverlap:
		if len(e.Meta.OverlappingActions) > 0 {
			return fmt.Sprintf("Overlap: %s", strings.Join(e.Meta.OverlappingActions, ", "))
		}
		return "Deny/Allow overlap"
	default:
		return ""
	}
}
