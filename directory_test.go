package main

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
)

func TestDirectoryMatchesArchive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "decompiled app")
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"classes.dex":        "https://example.invalid/api\x00fixture-secret",
		"assets/config.json": `{"url":"https:\/\/example.invalid/api","marker":"fixture-secret"}`,
	}
	archivePath := filepath.Join(t.TempDir(), "fixture.apk")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		entry, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	rules := []rule{{name: "Fixture", re: regexp.MustCompile("fixture-secret")}}
	wantURLs, wantFindings, wantCount, err := scan(archivePath, rules)
	if err != nil {
		t.Fatal(err)
	}
	gotURLs, gotFindings, gotCount, err := scanDirectory(root, "", rules)
	if err != nil {
		t.Fatal(err)
	}
	if gotCount != wantCount || !reflect.DeepEqual(gotURLs, wantURLs) || !reflect.DeepEqual(gotFindings, wantFindings) {
		t.Fatalf("folder differs from archive: URLs=%v findings=%v count=%d", gotURLs, gotFindings, gotCount)
	}
}

func TestDirectoryExcludesOutputAndAcceptsEmpty(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "output.json")
	if err := os.WriteFile(output, []byte("https://excluded.invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	urls, findings, count, err := scanDirectory(root, output, nil)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || len(urls) != 0 || len(findings) != 0 {
		t.Fatal("scanned its own output")
	}
	if _, _, _, err := scanDirectory(output, "", nil); err == nil {
		t.Fatal("accepted file as directory")
	}
	if _, _, _, err := scanDirectory(filepath.Join(root, "missing"), "", nil); err == nil {
		t.Fatal("accepted missing directory")
	}
}

func TestDirectoryDoesNotFollowSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	secret := filepath.Join(outside, "outside.txt")
	if err := os.WriteFile(secret, []byte("https://outside.invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "linked.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked-dir")); err != nil {
		t.Fatal(err)
	}
	urls, _, count, err := scanDirectory(root, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || len(urls) != 0 {
		t.Fatal("followed a symlink outside the input")
	}
	if _, _, _, err := scanDirectory(filepath.Join(root, "linked-dir"), "", nil); err == nil {
		t.Fatal("accepted symlink root")
	}
}

func TestSharedReadFailureAndSizeLimits(t *testing.T) {
	sentinel := errors.New("fixture read failure")
	failing := inputFile{"unreadable", 0, func() (io.ReadCloser, error) { return nil, sentinel }}
	if _, _, _, err := scanFiles([]inputFile{failing}, nil); !errors.Is(err, sentinel) {
		t.Fatalf("lost read error: %v", err)
	}
	oversized := inputFile{"oversized", maxEntry + 1, nil}
	if _, _, _, err := scanFiles([]inputFile{oversized}, nil); err == nil {
		t.Fatal("accepted oversized file")
	}
	var tooMany []inputFile
	for i := 0; i < 9; i++ {
		tooMany = append(tooMany, inputFile{"large", maxEntry, nil})
	}
	if _, _, _, err := scanFiles(tooMany, nil); err == nil {
		t.Fatal("accepted input above total size limit")
	}
}
