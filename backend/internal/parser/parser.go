package parser

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Kuba0517/iam-analyzer/internal/model"
)

const MaxInputBytes = 1 << 20 // 1 MB

var (
	ErrInputTooLarge    = errors.New("input exceeds 1MB limit")
	ErrInvalidJSON      = errors.New("invalid JSON")
	ErrMissingVersion   = errors.New("missing Version field")
	ErrMissingStatement = errors.New("missing or empty Statement array")
	ErrInvalidEffect    = errors.New("statement Effect must be Allow or Deny")
)

func Parse(raw []byte) (*model.Policy, error) {
	if len(raw) > MaxInputBytes {
		return nil, ErrInputTooLarge
	}

	var policy model.Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	if policy.Version == "" {
		return nil, ErrMissingVersion
	}

	// Current version of policy language and legacy one
	if policy.Version != "2012-10-17" && policy.Version != "2008-10-17" {
		return nil, fmt.Errorf("unsupported version: %q", policy.Version)
	}

	if len(policy.Statement) == 0 {
		return nil, ErrMissingStatement
	}

	for i, stmt := range policy.Statement {
		if stmt.Effect != "Allow" && stmt.Effect != "Deny" {
			return nil, fmt.Errorf("%w: statement %d has Effect %q", ErrInvalidEffect, i, stmt.Effect)
		}

		if len(stmt.Action) == 0 && len(stmt.NotAction) == 0 {
			return nil, fmt.Errorf("statement %d must have Action or NotAction", i)
		}

		if len(stmt.Resource) == 0 && len(stmt.NotResource) == 0 && stmt.Principal == nil {
			return nil, fmt.Errorf("statement %d must have Resource, NotResource or Principal", i)
		}
	}
	return &policy, nil
}
