package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
)

//go:embed rules/regexes.json
var defaultRules []byte

type SecretFinding struct {
	Name    string   `json:"name"`
	Value   string   `json:"value"`
	Type    string   `json:"type,omitempty"`
	Sources []string `json:"sources"`
}

type rule struct {
	name  string
	re    *regexp.Regexp
	group int
}

func loadRules(path string) ([]rule, error) {
	data := defaultRules
	if path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("invalid pattern JSON: %w", err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("pattern file must contain at least one named rule")
	}
	var rules []rule
	for name, raw := range values {
		var single string
		var patterns []string
		if err := json.Unmarshal(raw, &single); err == nil {
			patterns = []string{single}
		} else if err := json.Unmarshal(raw, &patterns); err != nil {
			return nil, fmt.Errorf("rule %q must be a string or string array", name)
		}
		if len(patterns) == 0 {
			return nil, fmt.Errorf("rule %q has no patterns", name)
		}
		for _, pattern := range patterns {
			if pattern == "" {
				return nil, fmt.Errorf("rule %q has an empty pattern", name)
			}
			re, err := regexp.Compile("(?m)" + pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %q is not valid Go/RE2 syntax: %w", name, err)
			}
			group := re.SubexpIndex("match")
			if group < 0 {
				group = 0
			}
			rules = append(rules, rule{name, re, group})
		}
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].name < rules[j].name })
	return rules, nil
}

func findSecrets(views [][]byte, rules []rule) []SecretFinding {
	if len(rules) == 0 {
		return nil
	}
	seen := make(map[[2]string]bool)
	var results []SecretFinding
	for _, view := range views {
		// Binary string terminators delimit lines for anchored APKLeaks rules.
		text := bytes.ReplaceAll(view, []byte{0}, []byte{'\n'})
		for _, rule := range rules {
			for _, index := range rule.re.FindAllSubmatchIndex(text, -1) {
				start, end := index[2*rule.group], index[2*rule.group+1]
				if start < 0 || start == end {
					continue
				}
				value := string(text[start:end])
				// Preserve the upstream JWT letter/digit checks without lookahead.
				if rule.name == "JSON_Web_Token" && !hasLetterAndDigit(value) {
					continue
				}
				key := [2]string{rule.name, value}
				if !seen[key] {
					seen[key] = true
					results = append(results, SecretFinding{Name: rule.name, Value: value})
				}
			}
		}
	}
	for _, finding := range findNamedCredentials(views) {
		key := [2]string{finding.Name, finding.Value}
		if !seen[key] {
			seen[key] = true
			results = append(results, finding)
		}
	}
	return results
}

func hasLetterAndDigit(value string) bool {
	var letter, digit bool
	for _, c := range value {
		letter = letter || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		digit = digit || c >= '0' && c <= '9'
	}
	return letter && digit
}
