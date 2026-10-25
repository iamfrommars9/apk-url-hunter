package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundledRulesAndCaptures(t *testing.T) {
	rules, err := loadRules("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) < 50 {
		t.Fatal("bundled rules missing")
	}
	google := "AIza" + strings.Repeat("A", 35)
	input := []byte("\x00https://demo:pass@example.invalid\x00mailto:demo@example.invalid\x00abc1.def.ghi\x00abc.def.ghi\x00" + google)
	got := findSecrets(textViews(input), rules)
	values := make(map[string][]string)
	for _, match := range got {
		values[match.Name] = append(values[match.Name], match.Value)
	}
	for name, want := range map[string]string{
		"Basic_Auth_Credentials": "demo:pass@example.invalid",
		"Mailto":                 "demo@example.invalid",
		"JSON_Web_Token":         "abc1.def.ghi",
		"Google_API_Key":         google,
	} {
		if len(values[name]) != 1 || values[name][0] != want {
			t.Errorf("%s: got %q, want %q", name, values[name], want)
		}
	}
}

func TestCustomRulesAndFindingSources(t *testing.T) {
	dir := t.TempDir()
	pattern := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(pattern, []byte(`{"Demo":["fixture-secret","other-marker"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules(pattern)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fixture.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	for _, name := range []string{"classes.dex", "assets/config"} {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("fixture-secret fixture-secret")); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, findings, entries, err := scan(path, rules)
	if err != nil {
		t.Fatal(err)
	}
	if entries != 2 || len(findings) != 1 || findings[0].Value != "fixture-secret" || len(findings[0].Sources) != 2 {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	for _, invalid := range []string{`{}`, `{"x":[]}`, `{"x":""}`, `{"x":5}`, `{"x":"(?<=unsupported)x"}`, `not JSON`} {
		if err := os.WriteFile(pattern, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRules(pattern); err == nil {
			t.Errorf("accepted invalid rules: %s", invalid)
		}
	}
}

func TestDecompressionLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	_, err = z.CreateRaw(&zip.FileHeader{Name: "oversized", Method: zip.Store, UncompressedSize64: maxEntry + 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := scan(path, nil); err == nil {
		t.Fatal("accepted oversized entry")
	}
}
