package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func estate(reports ...*Report) *Estate {
	return &Estate{Tool: "eimer", Version: "t", GeneratedAt: time.Now(), Reports: reports}
}

func TestCompareReportsChanges(t *testing.T) {
	before := &Report{Name: "lab", Buckets: []Bucket{
		{Name: "a", Versioning: Versioning{Probe: ok(), Status: "Enabled"}, Inventory: Inventory{Objects: 10, Bytes: 100}},
		{Name: "gone"},
	}, Findings: []Finding{{ID: "ENCRYPTION_OFF", Severity: Low, Bucket: "a"}}}
	after := &Report{Name: "lab", Buckets: []Bucket{
		{Name: "a", Versioning: Versioning{Probe: ok(), Status: "Suspended"}, Policy: Policy{Probe: ok(), Document: `{"Statement":[]}`}, Inventory: Inventory{Objects: 12, Bytes: 100}},
		{Name: "new"},
	}, Findings: []Finding{{ID: "VERSIONING_SUSPENDED", Severity: Medium, Bucket: "a"}}}

	diffs := Compare(estate(before), estate(after, &Report{Name: "extra"}))
	if len(diffs) != 2 || diffs[0].Endpoint != "extra" || diffs[1].Endpoint != "lab" {
		t.Fatalf("diffs: %+v", diffs)
	}
	kinds := map[string]int{}
	for _, c := range diffs[1].Changes {
		kinds[c.Kind]++
	}
	want := map[string]int{"bucket_added": 1, "bucket_removed": 1, "config": 2, "inventory": 1, "finding_new": 1, "finding_resolved": 1}
	for k, n := range want {
		if kinds[k] != n {
			t.Errorf("%s: got %d want %d in %+v", k, kinds[k], n, diffs[1].Changes)
		}
	}
	if !Changed(diffs) {
		t.Fatal("expected changes")
	}
	var text strings.Builder
	WriteDiff(&text, diffs)
	for _, want := range []string{"lab: 7 change(s)", "! finding_new", "versioning: Enabled -> Suspended", "policy: - -> sha256:", "objects 10 -> 12"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("missing %q in\n%s", want, text.String())
		}
	}
}

func TestCompareIdenticalIsQuiet(t *testing.T) {
	r := &Report{Endpoint: "http://x", Buckets: []Bucket{{Name: "a"}}, Findings: []Finding{{ID: "X", Bucket: "a"}}}
	diffs := Compare(estate(r), estate(r))
	if Changed(diffs) {
		t.Fatalf("unexpected: %+v", diffs)
	}
	diffs = Compare(estate(r), estate())
	if len(diffs) != 1 || diffs[0].Changes[0].Kind != "endpoint_removed" {
		t.Fatalf("removed endpoint: %+v", diffs)
	}
}

func TestEstateSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	e := estate(&Report{Tool: "eimer", Endpoint: "http://x", Findings: []Finding{{ID: "A", Severity: High}}})
	digest, err := e.Save(path)
	if err != nil || len(digest) != 64 {
		t.Fatalf("save: %v %q", err, digest)
	}
	side, err := os.ReadFile(path + ".sha256")
	if err != nil || !strings.HasPrefix(string(side), digest+"  ") {
		t.Fatalf("sidecar: %v %q", err, side)
	}
	got, err := Load(path)
	if err != nil || len(got.Reports) != 1 || got.Reports[0].Findings[0].Severity != High || got.Worst() != High {
		t.Fatalf("load: %v %+v", err, got)
	}
	if err := os.WriteFile(path, []byte(`{"tool":"other"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("foreign document accepted")
	}
}
