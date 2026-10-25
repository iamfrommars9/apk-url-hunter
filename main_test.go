package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestExtract(t *testing.T) {
	data := []byte("https://example.invalid/a?q=1\x00https:\\/\\/example.invalid/a?q=1\nws://socket.invalid/live\n")
	for _, c := range []byte("https://utf16.invalid/path") {
		data = append(data, c, 0)
	}
	data = append(data, 0, 0)
	for _, c := range []byte("https://bigendian.invalid/path") {
		data = append(data, 0, c)
	}
	want := []string{"https://bigendian.invalid/path", "https://example.invalid/a?q=1", "https://utf16.invalid/path", "ws://socket.invalid/live"}
	if got := extract(data); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestScanSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	for _, name := range []string{"classes.dex", "assets/config.json"} {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("https://example.invalid/test")); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	got, _, count, err := scan(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Finding{{"https://example.invalid/test", []string{"assets/config.json", "classes.dex"}}}
	if count != 2 || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v (%d entries)", got, count)
	}
	if err := os.WriteFile(path, []byte("not a ZIP"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := scan(path, nil); err == nil {
		t.Fatal("accepted invalid APK")
	}
}
