package diff

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

type DiffOp int

const (
	DiffEqual DiffOp = iota
	DiffAdd
	DiffRemove
)

type DiffLine struct {
	Op   DiffOp
	Text string
}

func Unified(label1 string, p1 *model.Policy, label2 string, p2 *model.Policy) (string, error) {
	b1, err := json.MarshalIndent(p1, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal %s: %w", label1, err)
	}

	b2, err := json.MarshalIndent(p2, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal %s: %w", label2, err)
	}

	lines1 := strings.Split(string(b1), "\n")
	lines2 := strings.Split(string(b2), "\n")

	dl := diffLines(lines1, lines2)

	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n", label1)
	fmt.Fprintf(&sb, "+++ %s\n", label2)

	for _, d := range dl {
		switch d.Op {
		case DiffEqual:
			fmt.Fprintf(&sb, " %s\n", d.Text)
		case DiffRemove:
			fmt.Fprintf(&sb, "-%s\n", d.Text)
		case DiffAdd:
			fmt.Fprintf(&sb, "+%s\n", d.Text)
		}
	}

	return sb.String(), nil
}

func diffLines(a, b []string) []DiffLine {
	n := len(a)
	m := len(b)

	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				lcs[i][j] = lcs[i][j-1] + 1
			} else if lcs[i-1][j] > lcs[i][j-1] {
				lcs[i][j] = lcs[i-1][j]
			} else {
				lcs[i][j] = lcs[i][j-1]
			}
		}
	}

	var result []DiffLine
	i, j := n, m
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && a[i-1] == b[j-1] {
			result = append(result, DiffLine{Op: DiffEqual, Text: a[i-1]})
			i--
			j--
		} else if j > 0 && (i == 0 || lcs[i][j-1] > lcs[i-1][j]) {
			result = append(result, DiffLine{Op: DiffAdd, Text: b[j-1]})
			j--
		} else {
			result = append(result, DiffLine{Op: DiffRemove, Text: a[i-1]})
			i--
		}
	}

	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}

	return result
}
