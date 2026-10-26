package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNamedCredentialExamples(t *testing.T) {
	names := []string{
		"city_locator_secret_key", "clientID", "facebook_client_token", "geo_api_key",
		"google_api_key", "google_crash_reporting_api_key", "fingerprint_salt_key",
		"loyalty_secret_key", "salt_key", "salt_search_api_token", "slots_list_api_key", "truecaller_salt_key",
	}
	var xml strings.Builder
	xml.WriteString("<resources>\n")
	want := make(map[string]string)
	for i, name := range names {
		value := fmt.Sprintf("demo-only-%02d-@()^$[]", i)
		want[name] = value
		fmt.Fprintf(&xml, "<string name=\"%s\">%s</string>\n", name, value)
	}
	xml.WriteString("</resources>")
	got := findNamedCredentials(textViews([]byte(xml.String())))
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d", len(got), len(want))
	}
	for _, finding := range got {
		if want[finding.Name] != finding.Value || finding.Type == "" {
			t.Errorf("unexpected finding: %+v", finding)
		}
	}
}

func TestCredentialTextFormatsAndEscapes(t *testing.T) {
	tests := []struct{ text, name, value string }{
		{`{"clientID":"demo-client"}`, "clientID", "demo-client"},
		{`{"api_key":"demo\"quoted\\value\u0041"}`, "api_key", "demo\"quoted\\valueA"},
		{`const salt_search_api_token = 'demo(i)^$[x]#';`, "salt_search_api_token", "demo(i)^$[x]#"},
		{`var apiKey = 'demo\'quote\"double\/slash';`, "apiKey", "demo'quote\"double/slash"},
		{`public static final String LOYALTY_SECRET_KEY = "demo-java";`, "LOYALTY_SECRET_KEY", "demo-java"},
		{`.field public static final slots_list_api_key:Ljava/lang/String; = "demo-smali"`, "slots_list_api_key", "demo-smali"},
		{"SALT_KEY=demo@value[]#\n", "SALT_KEY", "demo@value[]#"},
		{"api_key: demo-yaml\n", "api_key", "demo-yaml"},
		{`<string translatable="false" name="api_key">demo&amp;value&quot;x&quot;</string>`, "api_key", "demo&value\"x\""},
		{`<string name='salt_key'><![CDATA[demo&amp;literal<>]]></string>`, "salt_key", "demo&amp;literal<>"},
	}
	for _, test := range tests {
		t.Run(test.name+"/"+test.value, func(t *testing.T) {
			got := findNamedCredentials(textViews([]byte(test.text)))
			if len(got) != 1 || got[0].Name != test.name || got[0].Value != test.value {
				t.Fatalf("got %+v", got)
			}
		})
	}
	var utf16 []byte
	for _, c := range []byte(`api_key="demo-utf16"`) {
		utf16 = append(utf16, c, 0)
	}
	if got := findNamedCredentials(textViews(utf16)); len(got) != 1 || got[0].Value != "demo-utf16" {
		t.Fatalf("UTF16: %+v", got)
	}
}

func TestCredentialNoiseAndTypes(t *testing.T) {
	text := `<string name="app_name">Demo</string><string name="api_key">@string/other</string>
{"api_key":"","clientID":"${CLIENT_ID}","ordinary":"demo"}
api_key=null
secret=false
salt_key=true
token=undefined
`
	if got := findNamedCredentials(textViews([]byte(text))); len(got) != 0 {
		t.Fatalf("unexpected noise: %+v", got)
	}
	if !strings.Contains(credentialType("clientID"), "often public") {
		t.Fatal("client ID incorrectly described as a secret")
	}
	if !strings.Contains(credentialType("salt_search_api_token"), "token") {
		t.Fatal("token misclassified as salt")
	}
	if !strings.Contains(credentialType("truecaller_salt_key"), "Salt") {
		t.Fatal("salt classification missing")
	}
}

func TestNamedCredentialsInAPKAndFolder(t *testing.T) {
	root := t.TempDir()
	content := `<resources><string name="loyalty_secret_key">demo-shared</string><string name="city_locator_secret_key">demo-shared</string></resources>`
	archivePath := filepath.Join(t.TempDir(), "fixture.apk")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	for _, path := range []string{"strings.xml", "assets/config.xml"} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		w, err := z.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules("")
	if err != nil {
		t.Fatal(err)
	}
	_, archiveFindings, _, err := scan(archivePath, rules)
	if err != nil {
		t.Fatal(err)
	}
	_, folderFindings, _, err := scanDirectory(root, "", rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(archiveFindings) != 2 || !reflect.DeepEqual(archiveFindings, folderFindings) {
		t.Fatalf("unexpected findings: %+v / %+v", archiveFindings, folderFindings)
	}
	for _, finding := range archiveFindings {
		if len(finding.Sources) != 2 || finding.Type == "" {
			t.Fatalf("missing sources/type: %+v", finding)
		}
	}
	if _, findings, _, err := scan(archivePath, nil); err != nil || len(findings) != 0 {
		t.Fatalf("URL-only mode returned credentials: %+v %v", findings, err)
	}
}
