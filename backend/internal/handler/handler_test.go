package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kuba0517/iam-analyzer/internal/handler"
	"github.com/Kuba0517/iam-analyzer/internal/model"
)

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	handler.Healthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Errorf("expected status ok, got %s", body["status"])
	}
}

func TestAnalyze_HappyPath(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "*"
			}
		]
	}`

	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(policy))
	w := httptest.NewRecorder()

	handler.Analyze(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp model.AnalyzeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Original == nil {
		t.Error("expected original policy in response")
	}
	if resp.Normalized == nil {
		t.Error("expected normalized policy in response")
	}
	if resp.Score.Rank == "" {
		t.Error("expected score rank in response")
	}
}

func TestAnalyze_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(`{not json`))
	w := httptest.NewRecorder()

	handler.Analyze(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] == "" {
		t.Error("expected error message in response")
	}
}

func TestAnalyze_MissingVersion(t *testing.T) {
	policy := `{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}`
	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(policy))
	w := httptest.NewRecorder()

	handler.Analyze(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAnalyze_WithFindings(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*"
			}
		]
	}`

	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(policy))
	w := httptest.NewRecorder()

	handler.Analyze(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp model.AnalyzeResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if len(resp.Findings) == 0 {
		t.Error("expected findings for wildcard policy")
	}
}

func TestApply_HappyPath(t *testing.T) {
	body := `{
		"policy": {
			"Version": "2012-10-17",
			"Statement": [
				{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]},
				{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]}
			]
		},
		"patchIds": ["dedup-0"]
	}`

	req := httptest.NewRequest(http.MethodPost, "/apply", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.Apply(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp model.ApplyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Simplified == nil {
		t.Error("expected simplified policy in response")
	}
	if len(resp.Simplified.Statement) != 1 {
		t.Errorf("expected 1 statement after dedup, got %d", len(resp.Simplified.Statement))
	}
}

func TestApply_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/apply", strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	handler.Apply(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestApply_MissingPolicy(t *testing.T) {
	body := `{"patchIds": ["dedup-0"]}`
	req := httptest.NewRequest(http.MethodPost, "/apply", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.Apply(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
