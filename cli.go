package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Report struct {
	APK       string          `json:"apk,omitempty"`
	Directory string          `json:"directory,omitempty"`
	Entries   int             `json:"entries"`
	Seconds   float64         `json:"seconds"`
	URLs      []Finding       `json:"urls"`
	Findings  []SecretFinding `json:"findings"`
}

func run() error {
	file := flag.String("f", "", "APK file to scan")
	directory := flag.String("d", "", "already-decompiled app directory to scan recursively")
	out := flag.String("o", "", "new output file (existing files are never overwritten)")
	patterns := flag.String("p", "", "custom rules JSON (Go/RE2 regular expressions)")
	urlsOnly := flag.Bool("urls-only", false, "extract URLs only, without secret rules")
	asJSON := flag.Bool("json", false, "write JSON with source filenames")
	flag.Parse()
	if (*file == "") == (*directory == "") || flag.NArg() != 0 {
		return errors.New("usage: apk-url-hunter (-f FILE.apk | -d DIRECTORY) [-o OUTPUT] [--json] [--urls-only] [-p RULES.json]")
	}
	if *urlsOnly && *patterns != "" {
		return errors.New("-p cannot be combined with --urls-only")
	}
	var rules []rule
	if !*urlsOnly {
		var err error
		rules, err = loadRules(*patterns)
		if err != nil {
			return err
		}
	}
	if *out == "" {
		*out = "apk-url-hunter-results.txt"
		if *asJSON {
			*out = "apk-url-hunter-results.json"
		}
	}
	output, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		output.Close()
		if !complete {
			os.Remove(*out)
		}
	}()
	start := time.Now()
	var urls []Finding
	var findings []SecretFinding
	var entries int
	if *directory != "" {
		urls, findings, entries, err = scanDirectory(*directory, *out, rules)
	} else {
		urls, findings, entries, err = scan(*file, rules)
	}
	if err != nil {
		return err
	}
	if findings == nil {
		findings = []SecretFinding{}
	}
	report := Report{Entries: entries, Seconds: time.Since(start).Seconds(), URLs: urls, Findings: findings}
	if *directory != "" {
		report.Directory = filepath.Base(filepath.Clean(*directory))
	} else {
		report.APK = filepath.Base(*file)
	}
	var data []byte
	if *asJSON {
		data, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
	} else {
		var text strings.Builder
		text.WriteString("[URLs]\n")
		for _, url := range urls {
			fmt.Fprintf(&text, "%s\n  sources: %s\n", url.URL, strings.Join(url.Sources, ", "))
		}
		for _, finding := range findings {
			fmt.Fprintf(&text, "\n[%s]\n%s\n  type: %s\n  sources: %s\n", finding.Name, finding.Value, finding.Type, strings.Join(finding.Sources, ", "))
		}
		data = []byte(text.String())
	}
	if _, err := output.Write(data); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	complete = true
	fmt.Printf("Scanned %d entries: %d URLs, %d pattern findings in %s\nSaved: %s\n", entries, len(urls), len(findings), time.Duration(report.Seconds*float64(time.Second)).Round(time.Millisecond), *out)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
