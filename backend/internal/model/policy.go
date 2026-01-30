package model

import (
	"encoding/json"
	"fmt"
)

type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch v := raw.(type) {
	case string:
		*s = []string{v}
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			str, ok := item.(string)
			if !ok {
				return fmt.Errorf("expected string in array, got %T", item)
			}
			result = append(result, str)
		}
		*s = result

	default:
		return fmt.Errorf("expected string or array, got %T", raw)
	}
	return nil
}

func (s StringOrSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(s))
}

type Principal struct {
	Wildcard bool
	Members  map[string][]string
}

func (p *Principal) UnmarshalJSON(data []byte) error {
	var raw interface{}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch v := raw.(type) {
	case string:
		if v == "*" {
			p.Wildcard = true
			return nil
		}
		return fmt.Errorf("unexpected principal string: %q", v)

	case map[string]interface{}:
		p.Members = make(map[string][]string)
		for key, val := range v {
			switch tv := val.(type) {
			case string:
				p.Members[key] = []string{tv}
			case []interface{}:
				strs := make([]string, 0, len(tv))
				for _, item := range tv {
					str, ok := item.(string)
					if !ok {
						return fmt.Errorf("expected string in principal array, got %T", item)
					}
					strs = append(strs, str)
				}
				p.Members[key] = strs
			default:
				return fmt.Errorf("unexpected principal value type: %T", val)
			}
		}
	default:
		return fmt.Errorf("expected string or array, got %T", raw)
	}
	return nil
}

func (p Principal) MarshalJSON() ([]byte, error) {
	if p.Wildcard {
		return json.Marshal("*")
	}
	return json.Marshal(p.Members)
}

type Condition map[string]map[string]StringOrSlice

type Statement struct {
	Sid          string        `json:"Sid,omitempty"`
	Effect       string        `json:"Effect"`
	Principal    *Principal    `json:"Principal,omitempty"`
	NotPrincipal *Principal    `json:"NotPrincipal,omitempty"`
	Action       StringOrSlice `json:"Action,omitempty"`
	NotAction    StringOrSlice `json:"NotAction,omitempty"`
	Resource     StringOrSlice `json:"Resource,omitempty"`
	NotResource  StringOrSlice `json:"NotResource,omitempty"`
	Condition    Condition     `json:"Condition,omitempty"`
}

type Policy struct {
	Version   string      `json:"Version"`
	Id        string      `json:"Id,omitempty"`
	Statement []Statement `json:"Statement"`
}
