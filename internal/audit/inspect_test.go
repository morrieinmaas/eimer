package audit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeS3 serves two buckets: "locked" is a fully configured WORM bucket with a public
// policy, one unprotected object and anonymous access; "minimal" answers like Garage
// (most config APIs unimplemented) and denies anonymous access.
func fakeS3(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(fakeHandler())
}

func fakeHandler() http.Handler {
	xmlErr := func(w http.ResponseWriter, status int, code string) {
		w.WriteHeader(status)
		fmt.Fprintf(w, `<?xml version="1.0"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "MinIO")
		q := r.URL.Query()
		path := strings.TrimPrefix(r.URL.Path, "/")
		bucket, key, _ := strings.Cut(path, "/")
		anonymous := r.Header.Get("Authorization") == ""

		switch {
		case strings.HasPrefix(path, "minio/admin/"):
			switch {
			case anonymous:
				xmlErr(w, 403, "AccessDenied")
			case path == "minio/admin/v3/info":
				fmt.Fprint(w, `{"mode":"online","buckets":{"count":2},"objects":{"count":5},"usage":{"size":9},"services":{"kms":{"status":"Online"},"audit":[{"webhook":{"status":"Online"}}]},
					"backend":{"backendType":"Erasure","onlineDisks":4,"offlineDisks":0,"standardSCParity":2},
					"servers":[{"state":"online","endpoint":"s1:9000","uptime":3600,"version":"2025-07-23T15:54:02Z","drives":[{"state":"ok"}]}]}`)
			case strings.HasSuffix(path, "/datausageinfo"):
				fmt.Fprint(w, `{"lastUpdate":"2026-10-07T00:00:00Z","bucketsUsageInfo":{"locked":{"size":777,"objectsCount":5000,"versionsCount":5001}}}`)
			case strings.HasSuffix(path, "/accountinfo"):
				fmt.Fprint(w, `{"accountName":"k"}`)
			default:
				xmlErr(w, 403, "AccessDenied") // IAM endpoints need the encrypted protocol; covered in package minio
			}

		case path == "":
			if anonymous {
				xmlErr(w, 403, "AccessDenied")
				return
			}
			fmt.Fprint(w, `<ListAllMyBucketsResult><Buckets>
				<Bucket><Name>minimal</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket>
				<Bucket><Name>locked</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket>
				</Buckets></ListAllMyBucketsResult>`)

		case bucket == "minimal":
			switch {
			case anonymous:
				xmlErr(w, 403, "AccessDenied")
			case q.Has("policy"):
				xmlErr(w, 404, "NoSuchBucketPolicy")
			case q.Has("lifecycle"):
				xmlErr(w, 404, "NoSuchLifecycleConfiguration")
			case q.Get("list-type") == "2":
				fmt.Fprint(w, `<ListBucketResult><Name>minimal</Name><KeyCount>3</KeyCount>
					<Contents><Key>/bad.bin</Key><Size>10</Size><LastModified>2025-01-01T00:00:00Z</LastModified></Contents>
					<Contents><Key>dir/</Key><Size>0</Size><LastModified>2025-06-01T00:00:00Z</LastModified></Contents>
					<Contents><Key>ok.bin</Key><Size>2000000</Size><LastModified>2026-03-01T00:00:00Z</LastModified></Contents>
					</ListBucketResult>`)
			default:
				xmlErr(w, 501, "NotImplemented")
			}

		case bucket == "locked" && key == "":
			switch {
			case q.Has("versioning"):
				fmt.Fprint(w, `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`)
			case q.Has("object-lock"):
				fmt.Fprint(w, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>
					<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>`)
			case q.Has("policy"):
				fmt.Fprint(w, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::locked/*"}]}`)
			case q.Has("acl"):
				fmt.Fprint(w, `<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList>
					<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>o</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>
					<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant>
					</AccessControlList></AccessControlPolicy>`)
			case q.Has("lifecycle"):
				fmt.Fprint(w, `<LifecycleConfiguration><Rule><ID>short</ID><Status>Enabled</Status><Expiration><Days>7</Days></Expiration></Rule></LifecycleConfiguration>`)
			case q.Has("encryption"):
				fmt.Fprint(w, `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)
			case q.Has("logging"):
				fmt.Fprint(w, `<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>x/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>`)
			case q.Has("replication"):
				xmlErr(w, 404, "ReplicationConfigurationNotFoundError")
			case q.Has("notification"):
				fmt.Fprint(w, `<NotificationConfiguration><QueueConfiguration><Id>q</Id><Queue>arn:minio:sqs::1:webhook</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>`)
			case q.Has("tagging"):
				fmt.Fprint(w, `<Tagging><TagSet><Tag><Key>owner</Key><Value>ops</Value></Tag></TagSet></Tagging>`)
			case q.Has("cors"):
				xmlErr(w, 404, "NoSuchCORSConfiguration")
			case q.Has("uploads"):
				fmt.Fprint(w, `<ListMultipartUploadsResult><Bucket>locked</Bucket>
					<Upload><Key>big.bin</Key><UploadId>u1</UploadId><Initiated>2025-01-01T00:00:00Z</Initiated></Upload>
					</ListMultipartUploadsResult>`)
			case q.Get("list-type") == "2":
				fmt.Fprint(w, `<ListBucketResult><Name>locked</Name><KeyCount>2</KeyCount>
					<Contents><Key>held.bin</Key><Size>500</Size><LastModified>2026-02-01T00:00:00Z</LastModified></Contents>
					<Contents><Key>loose.bin</Key><Size>150000000</Size><LastModified>2026-04-01T00:00:00Z</LastModified></Contents>
					</ListBucketResult>`)
			default:
				xmlErr(w, 400, "Unexpected")
			}

		case bucket == "locked" && key == "held.bin":
			switch {
			case q.Has("retention"):
				fmt.Fprint(w, `<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate></Retention>`)
			case q.Has("legal-hold"):
				fmt.Fprint(w, `<LegalHold><Status>OFF</Status></LegalHold>`)
			default: // anonymous one-byte GetObject
				w.Header().Set("Content-Range", "bytes 0-0/500")
				w.WriteHeader(206)
				fmt.Fprint(w, "x")
			}

		case bucket == "locked" && key == "loose.bin":
			xmlErr(w, 404, "NoSuchObjectLockConfiguration")

		default:
			xmlErr(w, 404, "NoSuchBucket")
		}
	})
}

func runFake(t *testing.T, srv *httptest.Server, buckets ...string) *Report {
	t.Helper()
	r, err := Run(context.Background(), Options{
		Endpoint: srv.URL, AccessKey: "k", SecretKey: "s", Sample: 10, ListMax: 100, Buckets: buckets, HTTP: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRunCollectsFactsAndFindings(t *testing.T) {
	srv := fakeS3(t)
	defer srv.Close()
	r := runFake(t, srv)

	if r.Engine != "MinIO" || r.TLS || r.Hygiene.ServerHeader != "MinIO" || r.Region != "us-east-1" {
		t.Fatalf("engine=%q tls=%v hygiene=%+v region=%q", r.Engine, r.TLS, r.Hygiene, r.Region)
	}
	if len(r.Buckets) != 2 || r.Buckets[0].Name != "locked" || r.Buckets[1].Name != "minimal" {
		t.Fatalf("buckets: %+v", r.Buckets)
	}

	locked := r.Buckets[0]
	if locked.Versioning.Status != "Enabled" {
		t.Errorf("versioning: %+v", locked.Versioning)
	}
	if !locked.ObjectLock.Enabled || locked.ObjectLock.Mode != "COMPLIANCE" || locked.ObjectLock.RetentionDays != 30 {
		t.Errorf("object lock: %+v", locked.ObjectLock)
	}
	if !strings.Contains(locked.Policy.Document, `"Principal":"*"`) {
		t.Errorf("policy: %+v", locked.Policy)
	}
	if locked.ACL.Grants != 2 || !locked.ACL.PublicRead || locked.ACL.PublicWrite {
		t.Errorf("acl: %+v", locked.ACL)
	}
	if !locked.Exposure.AnonymousList || !locked.Exposure.AnonymousRead || locked.Exposure.ProofKey != "held.bin" {
		t.Errorf("exposure: %+v", locked.Exposure)
	}
	if len(locked.Lifecycle.Rules) != 1 || locked.Lifecycle.Rules[0].ExpirationDays != 7 || !locked.Lifecycle.Rules[0].Enabled {
		t.Errorf("lifecycle: %+v", locked.Lifecycle)
	}
	if locked.Encryption.Algorithm != "AES256" || locked.Logging.TargetBucket != "logs" {
		t.Errorf("encryption/logging: %+v %+v", locked.Encryption, locked.Logging)
	}
	if !locked.Replication.OK() || locked.Replication.Rules != 0 || !locked.CORS.OK() || locked.CORS.Rules != 0 {
		t.Errorf("not-found should be a supported empty value: %+v %+v", locked.Replication, locked.CORS)
	}
	if locked.Notification.Targets != 1 || locked.Tagging.Tags["owner"] != "ops" {
		t.Errorf("notification/tagging: %+v %+v", locked.Notification, locked.Tagging)
	}
	if locked.Multipart.Uploads != 1 || locked.Multipart.OldestInitiated == nil {
		t.Errorf("multipart: %+v", locked.Multipart)
	}
	inv := locked.Inventory
	if !inv.Exact || inv.Objects != 5000 || inv.Bytes != 777 || inv.Versions != 5001 || inv.Truncated || inv.LargestKey != "loose.bin" ||
		inv.Bands.Under1KB != 1 || inv.Bands.Over100MB != 1 || inv.Oldest.Year() != 2026 || inv.Newest.Month() != time.April {
		t.Errorf("inventory: %+v", inv)
	}
	if len(locked.Sample) != 2 || !locked.Sample[0].Protected() || locked.Sample[1].Protected() || locked.Sample[1].Error != "" {
		t.Errorf("sample: %+v", locked.Sample)
	}
	if locked.Duration <= 0 || locked.SlowestProbe == "" || locked.SlowestSeconds <= 0 {
		t.Errorf("timing: %+v %q %v", locked.Duration, locked.SlowestProbe, locked.SlowestSeconds)
	}

	minimal := r.Buckets[1]
	if minimal.Versioning.Supported || minimal.ObjectLock.Supported || minimal.Encryption.Supported || minimal.ACL.Supported {
		t.Errorf("501 must map to unsupported: %+v", minimal)
	}
	if !minimal.Policy.OK() || minimal.Policy.Document != "" {
		t.Errorf("policy: %+v", minimal.Policy)
	}
	if minimal.Exposure.AnonymousList || minimal.Exposure.AnonymousRead || minimal.Exposure.Error != "" {
		t.Errorf("exposure should be denied: %+v", minimal.Exposure)
	}
	if minimal.Inventory.FolderMarkers != 1 || len(minimal.NonPortable) != 1 || !strings.Contains(minimal.NonPortable[0], "leading slash") {
		t.Errorf("inventory/nonportable: %+v %v", minimal.Inventory, minimal.NonPortable)
	}
	if minimal.Sample != nil {
		t.Errorf("no sample without object lock: %+v", minimal.Sample)
	}

	if r.MinIO == nil || !r.MinIO.Available || r.MinIO.Totals.Objects != 5 || r.MinIO.IAM.Error == "" || r.MinIO.Account != "k" {
		t.Fatalf("minio adapter: %+v", r.MinIO)
	}
	if r.Buckets[1].Inventory.Exact {
		t.Errorf("minimal has no usage entry and must keep its listed inventory: %+v", r.Buckets[1].Inventory)
	}

	got := ids(r.Findings)
	for _, want := range []string{
		"MINIO_ARCHIVED", "IAM_UNREADABLE",
		"PLAINTEXT_ENDPOINT", "LOCK_UNLOCKED_OBJECTS", "POLICY_PUBLIC", "ACL_PUBLIC_READ", "ANON_LIST", "ANON_READ",
		"LIFECYCLE_EXPIRES_WITHIN_RETENTION", "MULTIPART_STALE", "KEYS_NONPORTABLE",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing finding %s in %+v", want, r.Findings)
		}
	}
	for _, f := range r.Findings {
		if f.Bucket == "minimal" && f.ID != "KEYS_NONPORTABLE" {
			t.Errorf("unsupported probes produced a finding: %+v", f)
		}
	}
	if r.Worst() != High {
		t.Errorf("worst=%s", r.Worst())
	}

	features := map[string]bool{}
	for _, m := range r.Migration {
		features[m.Feature] = true
		if m.Support["Garage"] == "" {
			t.Errorf("no Garage column for %s", m.Feature)
		}
	}
	for _, want := range []string{"versioning", "object lock", "bucket policy", "ACL grants", "lifecycle", "event notifications", "default encryption", "bucket tags", "access logging"} {
		if !features[want] {
			t.Errorf("migration matrix missing %s: %+v", want, r.Migration)
		}
	}
	if features["replication"] || features["CORS"] {
		t.Errorf("unused features listed: %+v", r.Migration)
	}
}

func TestRunTimesOutASingleStallingCall(t *testing.T) {
	inner := fakeHandler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("uploads") {
			time.Sleep(400 * time.Millisecond) // one stalling call must not stall the run
		}
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()
	var log strings.Builder
	started := time.Now()
	r, err := Run(context.Background(), Options{Endpoint: srv.URL, AccessKey: "k", SecretKey: "s", ListMax: 10,
		Buckets: []string{"locked"}, HTTP: srv.Client(), Timeout: 100 * time.Millisecond, Log: &log})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(started); took > 3*time.Second {
		t.Fatalf("run took %s", took)
	}
	b := r.Buckets[0]
	if b.Multipart.Error == "" || b.SlowestProbe != "multipart" {
		t.Fatalf("multipart should have timed out and be the slowest: %+v slowest=%s", b.Multipart, b.SlowestProbe)
	}
	if !b.Versioning.OK() {
		t.Fatalf("other probes must be unaffected: %+v", b.Versioning)
	}
	if !strings.Contains(log.String(), "slowest multipart") {
		t.Fatalf("progress log:\n%s", log.String())
	}
}

func TestRunHonoursExplicitBucketList(t *testing.T) {
	srv := fakeS3(t)
	defer srv.Close()
	r := runFake(t, srv, "minimal")
	if len(r.Buckets) != 1 || r.Buckets[0].Name != "minimal" {
		t.Fatalf("buckets: %+v", r.Buckets)
	}
}

func TestRunRejectsHalfCredentials(t *testing.T) {
	if _, err := Run(context.Background(), Options{Endpoint: "http://x", AccessKey: "k"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunFailsFastWithoutCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent")
	_, err := Run(context.Background(), Options{Endpoint: "http://127.0.0.1:1"})
	if err == nil || !strings.Contains(err.Error(), "no credentials found") {
		t.Fatalf("got %v", err)
	}
}

func TestRunRetriesWithTheRegionTheServerNames(t *testing.T) {
	var regions []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(403)
			return
		}
		_, rest, _ := strings.Cut(auth, "Credential=")
		parts := strings.Split(strings.SplitN(rest, ",", 2)[0], "/")
		regions = append(regions, parts[2])
		if parts[2] != "eu-lab-1" {
			w.WriteHeader(400)
			fmt.Fprint(w, `<Error><Code>AuthorizationHeaderMalformed</Code><Message>The authorization header is malformed; the region 'us-east-1' is wrong; expecting 'eu-lab-1'</Message></Error>`)
			return
		}
		fmt.Fprint(w, `<ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>`)
	}))
	defer srv.Close()
	r, err := Run(context.Background(), Options{Endpoint: srv.URL, AccessKey: "k", SecretKey: "s", HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Region != "eu-lab-1" || len(regions) != 2 {
		t.Fatalf("region=%q attempts=%v", r.Region, regions)
	}
}

func TestFingerprintRecordsTLSAndClock(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "RustFS/1.0")
		w.Header().Set("Date", time.Now().Add(-10*time.Minute).UTC().Format(http.TimeFormat))
		w.WriteHeader(403)
	}))
	defer srv.Close()
	engine, h := fingerprint(context.Background(), srv.Client(), srv.URL)
	if engine != "RustFS" || !strings.HasPrefix(h.TLSVersion, "TLS 1.") || h.CertExpires == nil || h.ClockSkewSeconds > -500 {
		t.Fatalf("engine=%q hygiene=%+v", engine, h)
	}
	fs := Evaluate(&Report{TLS: true, Hygiene: h, StartedAt: time.Now()})
	if _, ok := ids(fs)["CLOCK_SKEW"]; !ok {
		t.Fatalf("findings: %+v", fs)
	}
}

func TestReportRendersBothFormats(t *testing.T) {
	srv := fakeS3(t)
	defer srv.Close()
	r := runFake(t, srv)

	var text, js strings.Builder
	if err := r.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"minio admin", "audit targets webhook", "s1:9000", "layout 1 node(s)", "site replication: not readable", "engine: MinIO", "compliance 30d", "PUBLIC", "PUBLIC READ", "LIST+READ", "1/2 locked", "n/a",
		"777 B", "1 open", "migration carry-over", "LOCK_UNLOCKED_OBJECTS",
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text report missing %q:\n%s", want, text.String())
		}
	}
	if err := r.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"severity": "high"`, `"retention_days": 30`, `"anonymous_read": true`, `"ge_100mb": 1`, `"feature": "object lock"`} {
		if !strings.Contains(js.String(), want) {
			t.Errorf("json report missing %q", want)
		}
	}
}

func TestInvalidBucketNamesAreSkippedWithoutRequests(t *testing.T) {
	for name, ok := range map[string]bool{
		"models": true, "a.b-c1": true, "Models": false, "ab": false, "-abc": false, "abc_d": false,
		strings.Repeat("a", 64): false,
	} {
		if validBucketName(name) != ok {
			t.Errorf("validBucketName(%q) = %v", name, !ok)
		}
	}
	srv := fakeS3(t)
	defer srv.Close()
	r := runFake(t, srv, "Models") // the fake would answer NoSuchBucket if asked
	if r.Buckets[0].Skipped == "" || r.Buckets[0].Versioning.Supported {
		t.Fatalf("expected skip without probes: %+v", r.Buckets[0])
	}
	if _, hit := ids(r.Findings)["BUCKET_NAME_INVALID"]; !hit {
		t.Fatalf("findings: %+v", r.Findings)
	}
	var text strings.Builder
	if err := r.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "Models  skipped: invalid name") {
		t.Fatalf("text:\n%s", text.String())
	}
}

func TestNonPortableKey(t *testing.T) {
	for key, want := range map[string]string{
		"fine/key.txt": "", "dir/": "", "/lead": "leading slash", "a//b": "empty path segment",
		"a\\b": "backslash", "a\x01b": "control character", "a/../b": "dot path segment",
		"\xff": "not valid UTF-8", strings.Repeat("k", 1025): "longer than 1024 bytes",
	} {
		if got := nonPortableKey(key); got != want {
			t.Errorf("nonPortableKey(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 999: "999 B", 1000: "1.0 kB", 150000000: "150.0 MB", 1_500_000_000_000: "1.5 TB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
