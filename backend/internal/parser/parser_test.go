package parser_test

import (
	"strings"
	"testing"

	"github.com/Kuba0517/iam-analyzer/internal/parser"
)

func TestParse_ValidPolicy(t *testing.T) {
	raw := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket/*"
			}
		]
	}`)

	p, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Version != "2012-10-17" {
		t.Errorf("expected version 2012-10-17, got %s", p.Version)
	}
	if len(p.Statement) != 1 {
		t.Errorf("expected 1 statement, got %d", len(p.Statement))
	}
	if len(p.Statement[0].Action) != 1 || p.Statement[0].Action[0] != "s3:GetObject" {
		t.Errorf("expected Action [s3:GetObject], got %v", p.Statement[0].Action)
	}
}

func TestParse_TooLarge(t *testing.T) {
	raw := []byte(strings.Repeat("x", parser.MaxInputBytes+1))
	_, err := parser.Parse(raw)
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := parser.Parse([]byte(`{not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParse_MissingVersion(t *testing.T) {
	raw := []byte(`{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}`)
	_, err := parser.Parse(raw)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
}

func TestParse_MissingStatement(t *testing.T) {
	raw := []byte(`{"Version": "2012-10-17"}`)
	_, err := parser.Parse(raw)
	if err == nil {
		t.Fatal("expected error for missing statement")
	}
}

func TestParse_InvalidEffect(t *testing.T) {
	raw := []byte(`{"Version": "2012-10-17", "Statement": [{"Effect": "Maybe", "Action": "s3:GetObject", "Resource": "*"}]}`)
	_, err := parser.Parse(raw)
	if err == nil {
		t.Fatal("expected error for invalid effect")
	}
}

func TestParse_SingletonAction(t *testing.T) {
	raw := []byte(`{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}`)
	p, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Statement[0].Action) != 1 {
		t.Errorf("expected singleton action wrapped in slice, got %v", p.Statement[0].Action)
	}
}
