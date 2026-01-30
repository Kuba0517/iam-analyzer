package normalizer

import (
	"slices"
	"sort"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func Normalize(p *model.Policy) *model.Policy {
	normalized := &model.Policy{
		Version: p.Version,
		Id:      p.Id,
	}

	stmts := make([]model.Statement, len(p.Statement))
	for i, s := range p.Statement {
		stmts[i] = deepCopyStatement(s)
	}

	sortStatements(stmts)
	normalized.Statement = stmts

	return normalized
}

func deepCopyStatement(s model.Statement) model.Statement {
	return model.Statement{
		Sid:          s.Sid,
		Effect:       s.Effect,
		Principal:    deepCopyPrincipal(s.Principal),
		NotPrincipal: deepCopyPrincipal(s.NotPrincipal),
		Action:       dedupSorted(s.Action),
		NotAction:    dedupSorted(s.NotAction),
		Resource:     dedupSorted(s.Resource),
		NotResource:  dedupSorted(s.NotResource),
		Condition:    deepCopyCondition(s.Condition),
	}
}

func deepCopyPrincipal(p *model.Principal) *model.Principal {
	if p == nil {
		return nil
	}

	cp := &model.Principal{
		Wildcard: p.Wildcard,
	}

	if p.Members != nil {
		cp.Members = make(map[string][]string, len(p.Members))
		keys := make([]string, 0, len(p.Members))
		for k := range p.Members {
			keys = append(keys, k)
		}
		slices.Sort(keys)

		for _, k := range keys {
			cp.Members[k] = dedupSorted(p.Members[k])
		}
	}

	return cp
}

func deepCopyCondition(c model.Condition) model.Condition {
	if c == nil {
		return nil
	}

	cp := make(model.Condition, len(c))
	for op, kvs := range c {
		cpKvs := make(map[string]model.StringOrSlice, len(kvs))
		for k, v := range kvs {
			cpKvs[k] = dedupSorted(v)
		}
		cp[op] = cpKvs
	}

	return cp
}

func dedupSorted(ss []string) []string {
	if ss == nil {
		return nil
	}

	cp := make([]string, len(ss))
	copy(cp, ss)
	slices.Sort(cp)

	result := make([]string, 0, len(cp))
	for i, s := range cp {
		if i == 0 || s != cp[i-1] {
			result = append(result, s)
		}
	}

	return result
}

func sortStatements(stmts []model.Statement) {
	sort.SliceStable(stmts, func(i, j int) bool {
		if stmts[i].Effect != stmts[j].Effect {
			return stmts[i].Effect < stmts[j].Effect
		}

		aFirst := firstAction(stmts[i])
		bFirst := firstAction(stmts[j])
		return aFirst < bFirst
	})
}

func firstAction(s model.Statement) string {
	if len(s.Action) > 0 {
		return s.Action[0]
	}
	if len(s.NotAction) > 0 {
		return s.NotAction[0]
	}
	return ""
}
