package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func invoke(args ...string) error {
	oldArgs, oldFlags := os.Args, flag.CommandLine
	defer func() { os.Args, flag.CommandLine = oldArgs, oldFlags }()
	os.Args = append([]string{"apk-url-hunter"}, args...)
	flag.CommandLine = flag.NewFlagSet("apk-url-hunter", flag.ExitOnError)
	return run()
}

func TestDirectoryCLI(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("https://example.invalid/test fixture-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "results.json")
	if err := invoke("-d", root, "--urls-only", "--json", "-o", output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.APK != "" || report.Directory != filepath.Base(root) || report.Entries != 1 || len(report.URLs) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if err := invoke("-d", root, "--urls-only", "--json", "-o", output); err == nil {
		t.Fatal("overwrote output")
	}
	after, err := os.ReadFile(output)
	if err != nil || string(after) != string(data) {
		t.Fatal("existing output changed")
	}
	patterns := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(patterns, []byte(`{"Fixture":"fixture-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	textOutput := filepath.Join(t.TempDir(), "findings.txt")
	if err := invoke("-d", root, "-p", patterns, "-o", textOutput); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(textOutput)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), "[Fixture]") || !strings.Contains(string(text), "app.js") {
		t.Fatal("missing custom findings or relative sources")
	}
}

func TestCLIInputValidationAndCleanup(t *testing.T) {
	if err := invoke(); err == nil {
		t.Fatal("accepted no input")
	}
	if err := invoke("-f", "app.apk", "-d", "app"); err == nil {
		t.Fatal("accepted both input modes")
	}
	output := filepath.Join(t.TempDir(), "failed.json")
	if err := invoke("-d", filepath.Join(t.TempDir(), "missing"), "--urls-only", "-o", output); err == nil {
		t.Fatal("accepted nonexistent input")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("failed scan left output: %v", err)
	}
}
