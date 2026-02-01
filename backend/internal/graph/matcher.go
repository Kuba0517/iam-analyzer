package graph

import "strings"

func Match(pattern, value string) bool {
	return matchDP(strings.ToLower(pattern), strings.ToLower(value))
}

func matchDP(pattern, value string) bool {
	p, v := len(pattern), len(value)

	dp := make([][]bool, p+1)
	for i := range dp {
		dp[i] = make([]bool, v+1)
	}
	dp[0][0] = true

	for i := 1; i <= p; i++ {
		if pattern[i-1] == '*' {
			dp[i][0] = dp[i-1][0]
		}
	}

	for i := 1; i <= p; i++ {
		for j := 1; j <= v; j++ {
			switch pattern[i-1] {
			case '*':
				dp[i][j] = dp[i-1][j] || dp[i][j-1]
			case '?':
				dp[i][j] = dp[i-1][j-1]
			default:
				dp[i][j] = dp[i-1][j-1] && pattern[i-1] == value[j-1]
			}
		}
	}

	return dp[p][v]
}

func Overlaps(a, b string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)

	if a == "*" || b == "*" {
		return true
	}

	if !hasWildcard(a) {
		return Match(b, a)
	}
	if !hasWildcard(b) {
		return Match(a, b)
	}

	prefixA := literalPrefix(a)
	prefixB := literalPrefix(b)
	if prefixA != "" && prefixB != "" {
		if !strings.HasPrefix(prefixA, prefixB) && !strings.HasPrefix(prefixB, prefixA) {
			return false
		}
	}

	return true
}

func hasWildcard(s string) bool {
	return strings.ContainsAny(s, "*?")
}

func literalPrefix(pattern string) string {
	for i, c := range pattern {
		if c == '*' || c == '?' {
			return pattern[:i]
		}
	}
	return pattern
}
