package main

import (
	"bytes"
	"encoding/json"
	"html"
	"regexp"
	"strconv"
	"strings"
)

var (
	credentialXML        = regexp.MustCompile(`(?is)<string\b[^>]*\bname\s*=\s*["']([A-Za-z_$][A-Za-z0-9_$.-]*)["'][^>]*>([^<]*|<!\[CDATA\[.*?\]\]>)</string\s*>`)
	credentialAssignment = regexp.MustCompile(`(?m)["']?\b([A-Za-z_$][A-Za-z0-9_$.-]*)["']?\s*[:=]\s*("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*')`)
	credentialSmali      = regexp.MustCompile(`(?m)^\s*\.field[^\r\n]*?\s([A-Za-z_$][A-Za-z0-9_$.-]*):Ljava/lang/String;\s*=\s*("(?:\\.|[^"\\\r\n])*")`)
	credentialUnquoted   = regexp.MustCompile(`(?m)^[\t ]*([A-Za-z_$][A-Za-z0-9_$.-]*)[\t ]*[:=][\t ]*([^\s"'\x60#][^\r\n]*)`)
)

func normalizedName(name string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(name))
}

func sensitiveName(name string) bool {
	name = normalizedName(name)
	for _, marker := range []string{"apikey", "secret", "salt", "token", "password", "passwd", "privatekey", "publickey", "clientid"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func credentialType(name string) string {
	name = normalizedName(name)
	switch {
	case strings.Contains(name, "clientid"):
		return "Client identifier (often public)"
	case strings.Contains(name, "clienttoken"):
		return "SDK client token candidate"
	case strings.Contains(name, "privatekey"):
		return "Private key candidate"
	case strings.Contains(name, "publickey"):
		return "Public key candidate"
	case strings.Contains(name, "secret"):
		return "Application secret candidate"
	case strings.Contains(name, "apikey"):
		return "API key candidate"
	case strings.Contains(name, "token"):
		return "API/access token candidate"
	case strings.Contains(name, "salt"):
		return "Salt / key material candidate (verify usage)"
	case strings.Contains(name, "password") || strings.Contains(name, "passwd"):
		return "Password candidate"
	default:
		return "Pattern match (unverified)"
	}
}

func decodeLiteral(raw string) (string, error) {
	var decoded string
	if raw[0] == '"' {
		if err := json.Unmarshal([]byte(raw), &decoded); err == nil {
			return decoded, nil
		}
		return strconv.Unquote(raw)
	}
	var text strings.Builder
	for content := raw[1 : len(raw)-1]; content != ""; {
		if len(content) >= 2 && content[0] == '\\' && (content[1] == '/' || content[1] == '"') {
			text.WriteByte(content[1])
			content = content[2:]
			continue
		}
		r, _, rest, err := strconv.UnquoteChar(content, '\'')
		if err != nil {
			return "", err
		}
		text.WriteRune(r)
		content = rest
	}
	return text.String(), nil
}

func findNamedCredentials(views [][]byte) []SecretFinding {
	seen := make(map[[2]string]bool)
	var findings []SecretFinding
	add := func(name, value string) {
		if !sensitiveName(name) || value == "" || strings.HasPrefix(value, "@string/") || strings.HasPrefix(value, "${") {
			return
		}
		switch strings.ToLower(value) {
		case "null", "undefined", "true", "false":
			return
		}
		key := [2]string{name, value}
		if !seen[key] {
			seen[key] = true
			findings = append(findings, SecretFinding{Name: name, Value: value, Type: credentialType(name)})
		}
	}
	for _, view := range views {
		if bytes.Contains(view, []byte("<string")) {
			for _, match := range credentialXML.FindAllSubmatch(view, -1) {
				value := strings.TrimSpace(string(match[2]))
				if strings.HasPrefix(value, "<![CDATA[") {
					value = strings.TrimSuffix(strings.TrimPrefix(value, "<![CDATA["), "]]>")
				} else {
					value = html.UnescapeString(value)
				}
				add(string(match[1]), value)
			}
		}
		for _, pattern := range []*regexp.Regexp{credentialAssignment, credentialSmali} {
			for _, match := range pattern.FindAllSubmatch(view, -1) {
				if !sensitiveName(string(match[1])) {
					continue
				}
				value, err := decodeLiteral(string(match[2]))
				if err == nil {
					add(string(match[1]), value)
				}
			}
		}
		for _, match := range credentialUnquoted.FindAllSubmatch(view, -1) {
			add(string(match[1]), strings.TrimSpace(string(match[2])))
		}
	}
	return findings
}
