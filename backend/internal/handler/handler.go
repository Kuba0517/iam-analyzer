package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Kuba0517/iam-analyzer/internal/analyzer"
	"github.com/Kuba0517/iam-analyzer/internal/diff"
	"github.com/Kuba0517/iam-analyzer/internal/model"
	"github.com/Kuba0517/iam-analyzer/internal/normalizer"
	"github.com/Kuba0517/iam-analyzer/internal/parser"
	"github.com/Kuba0517/iam-analyzer/internal/scorer"
	"github.com/Kuba0517/iam-analyzer/internal/simplifier"
)

func Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func Analyze(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, parser.MaxInputBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	defer r.Body.Close()

	policy, err := parser.Parse(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	normalized := normalizer.Normalize(policy)
	score := scorer.Score(normalized)
	findings := analyzer.Analyze(normalized)
	suggestions := simplifier.Suggest(normalized)

	for i := range suggestions {
		result := suggestions[i].Apply(normalized)
		preview, err := diff.Unified("normalized", normalized, "simplified", result)
		if err == nil {
			suggestions[i].DiffPreview = preview
		}
	}

	resp := model.AnalyzeResponse{
		Original:    policy,
		Normalized:  normalized,
		Score:       score,
		Findings:    findings,
		Suggestions: suggestions,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func Apply(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, parser.MaxInputBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	defer r.Body.Close()

	var req model.ApplyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Policy == nil {
		writeError(w, http.StatusBadRequest, "missing policy")
		return
	}

	normalized := normalizer.Normalize(req.Policy)
	suggestions := simplifier.Suggest(normalized)
	simplified := simplifier.Apply(normalized, suggestions, req.PatchIDs)

	score := scorer.Score(simplified)
	findings := analyzer.Analyze(simplified)

	resp := model.ApplyResponse{
		Simplified: simplified,
		Score:      score,
		Findings:   findings,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
