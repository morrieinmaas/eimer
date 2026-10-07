package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func archiveWith(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body []byte
	}{{"README.md", []byte("readme")}, {name, content}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fakeGitHub serves the release API and the download layout for version 1.2.3.
func fakeGitHub(t *testing.T, binary []byte, tamper bool) (*httptest.Server, Options) {
	t.Helper()
	archive := archiveWith(t, "eimer", binary)
	sum := sha256.Sum256(archive)
	digest := hex.EncodeToString(sum[:])
	if tamper {
		digest = "deadbeef" + digest[8:]
	}
	name := "eimer_1.2.3_testos_testarch.tar.gz"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/latest":
			fmt.Fprint(w, `{"tag_name":"v1.2.3"}`)
		case "/download/v1.2.3/" + name:
			_, _ = w.Write(archive)
		case "/download/v1.2.3/checksums.txt":
			fmt.Fprintf(w, "%s  %s\n%s  eimer_1.2.3_other_arch.tar.gz\n", digest, name, digest)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, Options{APIURL: srv.URL + "/api/latest", BaseURL: srv.URL + "/download", HTTP: srv.Client(), OS: "testos", Arch: "testarch"}
}

func TestCheck(t *testing.T) {
	_, o := fakeGitHub(t, []byte("bin"), false)
	o.Current = "v1.0.0"
	rel, err := Check(context.Background(), o)
	if err != nil || rel.Latest != "1.2.3" || rel.Current != "1.0.0" || !rel.Newer {
		t.Fatalf("%+v %v", rel, err)
	}
	o.Current = "1.2.3"
	if rel, _ := Check(context.Background(), o); rel.Newer {
		t.Fatalf("same version reported newer: %+v", rel)
	}
}

func TestApplyReplacesTheExecutable(t *testing.T) {
	_, o := fakeGitHub(t, []byte("#!/bin/sh\necho new\n"), false)
	exe := filepath.Join(t.TempDir(), "eimer")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	o.Current, o.Exe = "0.1.0", exe
	got, err := Apply(context.Background(), o)
	if err != nil || got != "1.2.3" {
		t.Fatalf("%q %v", got, err)
	}
	data, err := os.ReadFile(exe)
	if err != nil || !strings.Contains(string(data), "echo new") {
		t.Fatalf("binary not replaced: %q %v", data, err)
	}
	info, _ := os.Stat(exe)
	if info.Mode()&0o111 == 0 {
		t.Fatal("not executable")
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".eimer-update-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

func TestApplyRejectsTamperedArchive(t *testing.T) {
	_, o := fakeGitHub(t, []byte("evil"), true)
	exe := filepath.Join(t.TempDir(), "eimer")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	o.Current, o.Exe = "0.1.0", exe
	if _, err := Apply(context.Background(), o); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("got %v", err)
	}
	if data, _ := os.ReadFile(exe); string(data) != "old" {
		t.Fatal("binary was replaced despite bad checksum")
	}
}

func TestApplyUnknownPlatform(t *testing.T) {
	_, o := fakeGitHub(t, []byte("bin"), false)
	o.Current, o.Exe, o.OS = "0.1.0", filepath.Join(t.TempDir(), "eimer"), "plan9"
	if _, err := Apply(context.Background(), o); err == nil || !strings.Contains(err.Error(), "no release 1.2.3 for plan9") {
		t.Fatalf("got %v", err)
	}
}

func TestNewer(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"1.2.3", "1.2.2", true}, {"1.2.3", "1.2.3", false}, {"1.2.3", "1.10.0", false}, {"2.0.0", "1.99.99", true},
		{"v1.0.1", "1.0.0", true}, {"1.0.0", "dev", true}, {"1.0.0", "0.3.0-4-gabc", true}, {"dev", "1.0.0", false},
		{"1.0.0-rc1", "0.9.0", false}, {"dev", "dev", false},
	} {
		if got := Newer(tc.a, tc.b); got != tc.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
