package simplifier

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/Kuba0517/iam-analyzer/internal/graph"
	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func Suggest(p *model.Policy) []model.Patch {
	g := graph.Build(p)

	var patches []model.Patch
	patches = append(patches, removeRedundant(p, g)...)
	patches = append(patches, mergeStatements(p, g)...)
	return patches
}

func Apply(p *model.Policy, patches []model.Patch, selectedIDs []string) *model.Policy {
	selected := make(map[string]bool, len(selectedIDs))
	for _, id := range selectedIDs {
		selected[id] = true
	}

	result := deepCopyPolicy(p)
	for _, patch := range patches {
		if selected[patch.ID] {
			result = patch.Apply(result)
		}
	}

	return result
}

func removeRedundant(p *model.Policy, g *graph.Graph) []model.Patch {
	var patches []model.Patch

	for i, e := range g.EdgesOfType(graph.Redundant) {
		removeIdx := e.To
		id := fmt.Sprintf("dedup-%d", i)

		patches = append(patches, model.Patch{
			ID:          id,
			Title:       fmt.Sprintf("Remove redundant statement %d", removeIdx),
			Impact:      "Removes 1 duplicate statement",
			DiffPreview: removeDiffPreview(p, removeIdx),
			Apply: func(policy *model.Policy) *model.Policy {
				cp := deepCopyPolicy(policy)
				cp.Statement = slices.Delete(cp.Statement, removeIdx, removeIdx+1)
				return cp
			},
		})
	}

	return patches
}

func mergeStatements(p *model.Policy, g *graph.Graph) []model.Patch {
	var patches []model.Patch
	counter := 0

	for _, e := range g.EdgesOfType(graph.MergeableAction) {
		mergeI, mergeJ := e.From, e.To
		id := fmt.Sprintf("merge-%d", counter)
		counter++

		patches = append(patches, model.Patch{
			ID:          id,
			Title:       fmt.Sprintf("Merge actions of statements %d and %d", mergeI, mergeJ),
			Impact:      "Combines 2 statements into 1 by merging Actions",
			DiffPreview: mergeDiffPreview(p, mergeI, mergeJ, "actions"),
			Apply: func(policy *model.Policy) *model.Policy {
				cp := deepCopyPolicy(policy)
				merged := unionStrings(cp.Statement[mergeI].Action, cp.Statement[mergeJ].Action)
				cp.Statement[mergeI].Action = merged
				cp.Statement = slices.Delete(cp.Statement, mergeJ, mergeJ+1)
				return cp
			},
		})
	}

	for _, e := range g.EdgesOfType(graph.MergeableResource) {
		mergeI, mergeJ := e.From, e.To
		id := fmt.Sprintf("merge-%d", counter)
		counter++

		patches = append(patches, model.Patch{
			ID:          id,
			Title:       fmt.Sprintf("Merge resources of statements %d and %d", mergeI, mergeJ),
			Impact:      "Combines 2 statements into 1 by merging Resources",
			DiffPreview: mergeDiffPreview(p, mergeI, mergeJ, "resources"),
			Apply: func(policy *model.Policy) *model.Policy {
				cp := deepCopyPolicy(policy)
				merged := unionStrings(cp.Statement[mergeI].Resource, cp.Statement[mergeJ].Resource)
				cp.Statement[mergeI].Resource = merged
				cp.Statement = slices.Delete(cp.Statement, mergeJ, mergeJ+1)
				return cp
			},
		})
	}

	return patches
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var result []string
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	slices.Sort(result)
	return result
}

func deepCopyPolicy(p *model.Policy) *model.Policy {
	data, _ := json.Marshal(p)
	var cp model.Policy
	json.Unmarshal(data, &cp)
	return &cp
}

func removeDiffPreview(p *model.Policy, idx int) string {
	data, _ := json.MarshalIndent(p.Statement[idx], "", "  ")
	return fmt.Sprintf("- Statement %d:\n- %s", idx, string(data))
}

func mergeDiffPreview(p *model.Policy, i, j int, field string) string {
	return fmt.Sprintf("Merge %s from statement %d into statement %d, remove statement %d", field, j, i, j)
}
