package audit

import (
	"testing"
	"time"
)

func ok() Probe { return Probe{Supported: true} }

// cleanBucket is fully compliant: nothing should fire.
func cleanBucket() Bucket {
	return Bucket{
		Name:       "clean",
		Versioning: Versioning{Probe: ok(), Status: "Enabled"},
		ObjectLock: ObjectLock{Probe: ok(), Enabled: true, Mode: "COMPLIANCE", RetentionDays: 30},
		Policy:     Policy{Probe: ok()},
		ACL:        ACL{Probe: ok(), Grants: 1},
		Lifecycle:  Lifecycle{Probe: ok()},
		Encryption: Encryption{Probe: ok(), Algorithm: "AES256"},
		Multipart:  Multipart{Probe: ok()},
	}
}

func ids(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.ID] = f
	}
	return m
}

func TestEvaluateCleanReportHasNoFindings(t *testing.T) {
	r := &Report{TLS: true, Buckets: []Bucket{cleanBucket()}}
	if fs := Evaluate(r); len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}

func TestEvaluateRules(t *testing.T) {
	later := time.Now().Add(24 * time.Hour)
	cases := []struct {
		name   string
		mutate func(*Bucket)
		want   string
		sev    Severity
	}{
		{"versioning off", func(b *Bucket) { b.Versioning.Status = "" }, "VERSIONING_OFF", Medium},
		{"versioning suspended", func(b *Bucket) { b.Versioning.Status = "Suspended" }, "VERSIONING_SUSPENDED", Medium},
		{"lock off", func(b *Bucket) { b.ObjectLock = ObjectLock{Probe: ok()} }, "LOCK_OFF", Info},
		{"lock without default", func(b *Bucket) { b.ObjectLock.Mode, b.ObjectLock.RetentionDays = "", 0 }, "LOCK_NO_DEFAULT_RETENTION", High},
		{"governance mode", func(b *Bucket) { b.ObjectLock.Mode = "GOVERNANCE" }, "LOCK_GOVERNANCE_MODE", Low},
		{"unlocked objects", func(b *Bucket) {
			b.Sample = []SampledObject{{Key: "a", RetainUntil: &later}, {Key: "b"}, {Key: "c", LegalHold: true}}
		}, "LOCK_UNLOCKED_OBJECTS", High},
		{"public policy string principal", func(b *Bucket) {
			b.Policy.Document = `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}`
		}, "POLICY_PUBLIC", High},
		{"public policy aws list principal", func(b *Bucket) {
			b.Policy.Document = `{"Statement":{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::1:root","*"]},"Action":"s3:*"}}`
		}, "POLICY_PUBLIC", High},
		{"lifecycle inside retention", func(b *Bucket) {
			b.Lifecycle.Rules = []LifecycleRule{{ID: "short", Enabled: true, ExpirationDays: 7}}
		}, "LIFECYCLE_EXPIRES_WITHIN_RETENTION", Medium},
		{"noncurrent expiry inside retention", func(b *Bucket) {
			b.Lifecycle.Rules = []LifecycleRule{{ID: "nc", Enabled: true, NoncurrentExpiryDays: 3}}
		}, "LIFECYCLE_EXPIRES_WITHIN_RETENTION", Medium},
		{"encryption off", func(b *Bucket) { b.Encryption.Algorithm = "" }, "ENCRYPTION_OFF", Low},
		{"acl public read", func(b *Bucket) { b.ACL.PublicRead = true }, "ACL_PUBLIC_READ", High},
		{"acl public write", func(b *Bucket) { b.ACL.PublicRead, b.ACL.PublicWrite = true, true }, "ACL_PUBLIC_WRITE", High},
		{"anonymous list", func(b *Bucket) { b.Exposure.AnonymousList = true }, "ANON_LIST", High},
		{"anonymous read", func(b *Bucket) { b.Exposure.AnonymousRead, b.Exposure.ProofKey = true, "k" }, "ANON_READ", High},
		{"stale multipart", func(b *Bucket) {
			old := time.Now().Add(-30 * 24 * time.Hour)
			b.Multipart.Uploads, b.Multipart.OldestInitiated = 2, &old
		}, "MULTIPART_STALE", Low},
		{"nonportable keys", func(b *Bucket) { b.NonPortable = []string{"/x (leading slash)"} }, "KEYS_NONPORTABLE", Low},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := cleanBucket()
			tc.mutate(&b)
			fs := Evaluate(&Report{TLS: true, StartedAt: time.Now(), Buckets: []Bucket{b}})
			if len(fs) != 1 {
				t.Fatalf("expected exactly one finding, got %+v", fs)
			}
			if fs[0].ID != tc.want || fs[0].Severity != tc.sev || fs[0].Bucket != "clean" {
				t.Fatalf("got %+v, want %s/%s", fs[0], tc.want, tc.sev)
			}
		})
	}
}

func TestEvaluateSilentOnUnsupportedOrErroredProbes(t *testing.T) {
	b := cleanBucket()
	b.Versioning = Versioning{}                                             // not supported (Garage)
	b.ObjectLock = ObjectLock{Probe: Probe{Supported: true, Error: "boom"}} // errored
	b.Encryption = Encryption{}
	b.Policy = Policy{Probe: Probe{Supported: true, Error: "AccessDenied"}, Document: `{"Statement":[{"Effect":"Allow","Principal":"*"}]}`}
	if fs := Evaluate(&Report{TLS: true, Buckets: []Bucket{b}}); len(fs) != 0 {
		t.Fatalf("unsupported or errored probes must not produce findings, got %+v", fs)
	}
}

func TestEvaluateLifecycleIgnoresDisabledRulesAndUnlockedBuckets(t *testing.T) {
	b := cleanBucket()
	b.Lifecycle.Rules = []LifecycleRule{{ID: "off", Enabled: false, ExpirationDays: 1}}
	if fs := Evaluate(&Report{TLS: true, Buckets: []Bucket{b}}); len(fs) != 0 {
		t.Fatalf("disabled rule fired: %+v", fs)
	}
	b = cleanBucket()
	b.ObjectLock = ObjectLock{Probe: ok()}
	b.Lifecycle.Rules = []LifecycleRule{{ID: "short", Enabled: true, ExpirationDays: 1}}
	if _, hit := ids(Evaluate(&Report{TLS: true, Buckets: []Bucket{b}}))["LIFECYCLE_EXPIRES_WITHIN_RETENTION"]; hit {
		t.Fatal("lifecycle rule fired on a bucket without object lock")
	}
}

func TestEvaluateFreshMultipartIsNotStale(t *testing.T) {
	b := cleanBucket()
	recent := time.Now().Add(-time.Hour)
	b.Multipart.Uploads, b.Multipart.OldestInitiated = 1, &recent
	if fs := Evaluate(&Report{TLS: true, StartedAt: time.Now(), Buckets: []Bucket{b}}); len(fs) != 0 {
		t.Fatalf("got %+v", fs)
	}
}

func TestEvaluateExposureErrorIsSilent(t *testing.T) {
	b := cleanBucket()
	b.Exposure = Exposure{AnonymousList: true, Error: "dial tcp: timeout"}
	if fs := Evaluate(&Report{TLS: true, Buckets: []Bucket{b}}); len(fs) != 0 {
		t.Fatalf("got %+v", fs)
	}
}

func TestEvaluateTLSCertificate(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		left time.Duration
		want string
		sev  Severity
	}{
		{-time.Hour, "TLS_CERT_EXPIRED", High},
		{5 * 24 * time.Hour, "TLS_CERT_EXPIRING", High},
		{20 * 24 * time.Hour, "TLS_CERT_EXPIRING", Medium},
	} {
		exp := now.Add(tc.left)
		fs := Evaluate(&Report{TLS: true, StartedAt: now, Hygiene: Hygiene{CertExpires: &exp, TLSVersion: "TLS 1.3"}})
		if len(fs) != 1 || fs[0].ID != tc.want || fs[0].Severity != tc.sev {
			t.Errorf("left=%s got %+v", tc.left, fs)
		}
	}
	exp := now.Add(365 * 24 * time.Hour)
	fs := Evaluate(&Report{TLS: true, StartedAt: now, Hygiene: Hygiene{CertExpires: &exp, TLSVersion: "TLS 1.1"}})
	if len(fs) != 1 || fs[0].ID != "TLS_OLD_VERSION" {
		t.Errorf("old tls: %+v", fs)
	}
}

func TestEvaluatePlaintextEndpoint(t *testing.T) {
	fs := Evaluate(&Report{TLS: false})
	if len(fs) != 1 || fs[0].ID != "PLAINTEXT_ENDPOINT" || fs[0].Bucket != "" {
		t.Fatalf("got %+v", fs)
	}
}

func TestPolicyIsPublicRejectsGarbageAndDeny(t *testing.T) {
	for _, doc := range []string{
		"", "not json", `{"Statement":[]}`,
		`{"Statement":[{"Effect":"Deny","Principal":"*"}]}`,
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:user/x"}}]}`,
		`{"Statement":[{"Effect":"Allow","Principal":{"Service":"*"}}]}`,
	} {
		if policyIsPublic(doc) {
			t.Errorf("%q wrongly flagged public", doc)
		}
	}
}

func TestWorst(t *testing.T) {
	r := &Report{Findings: []Finding{{Severity: Low}, {Severity: High}, {Severity: Info}}}
	if r.Worst() != High {
		t.Fatalf("got %s", r.Worst())
	}
	if (&Report{}).Worst() != Info {
		t.Fatal("empty report should be Info")
	}
}

func TestEvaluateSkippedBucketGetsOnlyTheNameFinding(t *testing.T) {
	fs := Evaluate(&Report{TLS: true, Buckets: []Bucket{{Name: "Models", Skipped: "invalid name"}}})
	if len(fs) != 1 || fs[0].ID != "BUCKET_NAME_INVALID" || fs[0].Severity != Medium {
		t.Fatalf("got %+v", fs)
	}
}

func TestGroupFindingsCollapsesByRule(t *testing.T) {
	fs := []Finding{
		{ID: "A", Severity: Low, Bucket: "b1"}, {ID: "B", Severity: High, Bucket: "b1"},
		{ID: "A", Severity: Low, Bucket: "b2"}, {ID: "C", Severity: Medium},
	}
	gs := groupFindings(fs)
	if len(gs) != 3 || gs[0].ID != "B" || gs[1].ID != "C" || gs[2].ID != "A" {
		t.Fatalf("order: %+v", gs)
	}
	if got := gs[2].Buckets; len(got) != 2 || got[0] != "b1" || got[1] != "b2" {
		t.Fatalf("buckets: %+v", got)
	}
	if gs[1].Buckets[0] != "endpoint" {
		t.Fatalf("endpoint scope: %+v", gs[1])
	}
	if s := scopeList([]string{"a", "b", "c", "d", "e", "f", "g"}); s != "a, b, c, d, e and 2 more (7 total)" {
		t.Fatalf("scopeList: %q", s)
	}
}
