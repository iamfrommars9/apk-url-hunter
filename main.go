package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

const maxEntry = 128 << 20
const maxTotal = 1 << 30

var urlPattern = regexp.MustCompile(`(?i)\b(?:https?|wss?)://[a-z0-9\[\]][a-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*|\bwww\.[a-z0-9][a-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*`)

type Finding struct {
	URL     string   `json:"url"`
	Sources []string `json:"sources"`
}

// shortcut: literal strings only; use a decompiler for URLs assembled at runtime.
func textViews(data []byte) [][]byte {
	data = bytes.ReplaceAll(data, []byte(`\/`), []byte(`/`))
	views := [][]byte{data}
	// Android resource strings can store ASCII characters in UTF-16LE or BE.
	for i := 0; i+1 < len(data); {
		start, offset := i, -1
		if data[i] >= 32 && data[i] <= 126 && data[i+1] == 0 {
			offset = 0
		} else if data[i] == 0 && data[i+1] >= 32 && data[i+1] <= 126 {
			offset = 1
		}
		if offset < 0 {
			i++
			continue
		}
		for i+1 < len(data) && data[i+offset] >= 32 && data[i+offset] <= 126 && data[i+1-offset] == 0 {
			i += 2
		}
		if i-start >= 16 {
			text := make([]byte, (i-start)/2)
			for n := range text {
				text[n] = data[start+offset+2*n]
			}
			views = append(views, text)
		}
	}
	return views
}

func extract(data []byte) []string {
	return extractURLs(textViews(data))
}

func extractURLs(views [][]byte) []string {
	seen := make(map[string]bool)
	for _, view := range views {
		for _, match := range urlPattern.FindAll(view, -1) {
			u := strings.TrimRight(string(match), ".,;)")
			seen[u] = true
		}
	}
	urls := make([]string, 0, len(seen))
	for u := range seen {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	return urls
}

func scan(path string, rules []rule) ([]Finding, []SecretFinding, int, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, 0, err
	}
	defer archive.Close()
	var total uint64
	var files []*zip.File
	for _, f := range archive.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.UncompressedSize64 > maxEntry || f.UncompressedSize64 > maxTotal-total {
			return nil, nil, 0, fmt.Errorf("APK exceeds decompression limit (128 MiB per entry, 1 GiB total): %s", f.Name)
		}
		total += f.UncompressedSize64
		files = append(files, f)
	}
	jobs := make(chan *zip.File)
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := make(map[string]map[string]bool)
	secrets := make(map[[2]string]map[string]bool)
	var failures []error
	for n := 0; n < min(runtime.GOMAXPROCS(0), 8); n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				urls, matches, err := scanEntry(f, rules)
				mu.Lock()
				if err != nil {
					failures = append(failures, fmt.Errorf("%s: %w", f.Name, err))
				}
				for _, u := range urls {
					if found[u] == nil {
						found[u] = make(map[string]bool)
					}
					found[u][f.Name] = true
				}
				for _, match := range matches {
					key := [2]string{match.Name, match.Value}
					if secrets[key] == nil {
						secrets[key] = make(map[string]bool)
					}
					secrets[key][f.Name] = true
				}
				mu.Unlock()
			}
		}()
	}
	for _, f := range files {
		jobs <- f
	}
	close(jobs)
	wg.Wait()
	if len(failures) > 0 {
		return nil, nil, len(files), errors.Join(failures...)
	}
	results := make([]Finding, 0, len(found))
	for url, paths := range found {
		sources := make([]string, 0, len(paths))
		for path := range paths {
			sources = append(sources, path)
		}
		sort.Strings(sources)
		results = append(results, Finding{url, sources})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].URL < results[j].URL })
	secretResults := make([]SecretFinding, 0, len(secrets))
	for key, paths := range secrets {
		sources := make([]string, 0, len(paths))
		for path := range paths {
			sources = append(sources, path)
		}
		sort.Strings(sources)
		secretResults = append(secretResults, SecretFinding{key[0], key[1], sources})
	}
	sort.Slice(secretResults, func(i, j int) bool {
		if secretResults[i].Name == secretResults[j].Name {
			return secretResults[i].Value < secretResults[j].Value
		}
		return secretResults[i].Name < secretResults[j].Name
	})
	return results, secretResults, len(files), nil
}

func scanEntry(f *zip.File, rules []rule) ([]string, []SecretFinding, error) {
	r, err := f.Open()
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, maxEntry+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxEntry {
		return nil, nil, errors.New("entry exceeds decompression limit")
	}
	views := textViews(data)
	return extractURLs(views), findSecrets(views, rules), nil
}
