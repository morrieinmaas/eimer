package audit

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// staleMultipart is how long an unfinished multipart upload may sit before it is
// treated as leaked space rather than a transfer in progress.
const staleMultipart = 7 * 24 * time.Hour

// Evaluate derives findings from collected facts. It is pure: no I/O, no state.
func Evaluate(r *Report) []Finding {
	var out []Finding
	if !r.TLS {
		out = append(out, Finding{
			ID: "PLAINTEXT_ENDPOINT", Severity: Medium,
			Message: "endpoint is plain http: credentials and data travel unencrypted",
		})
	}
	out = append(out, evaluateEndpoint(r)...)
	out = append(out, evaluateMinIO(r)...)
	for i := range r.Buckets {
		out = append(out, evaluateBucket(&r.Buckets[i], r.StartedAt)...)
	}
	return out
}

// maxClockSkew is well inside SigV4's 15 minute window, so it warns before signing breaks.
const maxClockSkew = 5 * time.Minute

func evaluateEndpoint(r *Report) []Finding {
	var out []Finding
	add := func(id string, sev Severity, msg string) {
		out = append(out, Finding{ID: id, Severity: sev, Message: msg})
	}
	h := r.Hygiene
	if h.CertExpires != nil {
		left := h.CertExpires.Sub(r.StartedAt)
		switch {
		case left <= 0:
			add("TLS_CERT_EXPIRED", High, "TLS certificate expired on "+h.CertExpires.UTC().Format("2006-01-02"))
		case left < 14*24*time.Hour:
			add("TLS_CERT_EXPIRING", High, fmt.Sprintf("TLS certificate expires in %d days", int(left.Hours()/24)))
		case left < 30*24*time.Hour:
			add("TLS_CERT_EXPIRING", Medium, fmt.Sprintf("TLS certificate expires in %d days", int(left.Hours()/24)))
		}
	}
	if h.TLSVersion != "" && (h.TLSVersion == "TLS 1.0" || h.TLSVersion == "TLS 1.1" || strings.HasPrefix(h.TLSVersion, "SSL")) {
		add("TLS_OLD_VERSION", Medium, "endpoint negotiated "+h.TLSVersion+", below TLS 1.2")
	}
	if skew := time.Duration(h.ClockSkewSeconds * float64(time.Second)); skew > maxClockSkew || skew < -maxClockSkew {
		add("CLOCK_SKEW", Medium, fmt.Sprintf("server clock is off by %s; SigV4 requests fail beyond 15 minutes", skew))
	}
	return out
}

func evaluateBucket(b *Bucket, now time.Time) []Finding {
	var out []Finding
	add := func(id string, sev Severity, msg string) {
		out = append(out, Finding{ID: id, Severity: sev, Bucket: b.Name, Message: msg})
	}

	if b.Skipped != "" {
		add("BUCKET_NAME_INVALID", Medium, "bucket name is not S3 DNS-compatible: path-style clients cannot address it and it must be renamed before migrating to a strict engine")
		return out
	}

	v, lock := b.Versioning, b.ObjectLock

	if v.OK() {
		switch v.Status {
		case "Enabled":
		case "Suspended":
			add("VERSIONING_SUSPENDED", Medium, "versioning is suspended: new writes overwrite in place")
		default:
			add("VERSIONING_OFF", Medium, "versioning is off: overwrites and deletes are unrecoverable")
		}
	}

	if lock.OK() {
		switch {
		case !lock.Enabled:
			add("LOCK_OFF", Info, "object lock is not enabled (most engines only allow enabling it at bucket creation)")
		case lock.Mode == "":
			add("LOCK_NO_DEFAULT_RETENTION", High,
				"object lock is enabled but has no default retention: new objects are not protected unless each write sets retention")
		case lock.Mode == "GOVERNANCE":
			add("LOCK_GOVERNANCE_MODE", Low,
				"default retention is GOVERNANCE: users with s3:BypassGovernanceRetention can shorten or remove it")
		}
	}

	if lock.Enabled && len(b.Sample) > 0 {
		unlocked := 0
		for _, o := range b.Sample {
			if o.Error == "" && !o.Protected() {
				unlocked++
			}
		}
		if unlocked > 0 {
			add("LOCK_UNLOCKED_OBJECTS", High,
				fmt.Sprintf("%d of %d sampled objects have neither retention nor legal hold", unlocked, len(b.Sample)))
		}
	}

	if b.Policy.OK() && policyIsPublic(b.Policy.Document) {
		add("POLICY_PUBLIC", High, "bucket policy allows a wildcard principal")
	}

	if b.ACL.OK() {
		switch {
		case b.ACL.PublicWrite:
			add("ACL_PUBLIC_WRITE", High, "bucket ACL grants write to everyone")
		case b.ACL.PublicRead:
			add("ACL_PUBLIC_READ", High, "bucket ACL grants read to everyone")
		}
	}

	if b.Exposure.Error == "" {
		if b.Exposure.AnonymousRead {
			add("ANON_READ", High, fmt.Sprintf("an unauthenticated client can read objects (proven by fetching one byte of %q)", b.Exposure.ProofKey))
		}
		if b.Exposure.AnonymousList {
			add("ANON_LIST", High, "an unauthenticated client can list objects")
		}
	}

	if lock.Enabled && lock.RetentionDays > 0 && b.Lifecycle.OK() {
		for _, rule := range b.Lifecycle.Rules {
			if !rule.Enabled {
				continue
			}
			if slices.ContainsFunc([]int{rule.ExpirationDays, rule.NoncurrentExpiryDays}, func(d int) bool { return d > 0 && d < lock.RetentionDays }) {
				add("LIFECYCLE_EXPIRES_WITHIN_RETENTION", Medium,
					fmt.Sprintf("lifecycle rule %q expires inside the %d day default retention; engines differ on what happens", rule.ID, lock.RetentionDays))
			}
		}
	}

	if b.Encryption.OK() && b.Encryption.Algorithm == "" {
		add("ENCRYPTION_OFF", Low, "no default server-side encryption configured")
	}

	if b.Multipart.OK() && b.Multipart.OldestInitiated != nil && now.Sub(*b.Multipart.OldestInitiated) > staleMultipart {
		add("MULTIPART_STALE", Low,
			fmt.Sprintf("%d unfinished multipart upload(s), oldest from %s: they hold space, are invisible to listings and will not migrate",
				b.Multipart.Uploads, b.Multipart.OldestInitiated.UTC().Format("2006-01-02")))
	}

	if len(b.NonPortable) > 0 {
		add("KEYS_NONPORTABLE", Low, "object keys that other engines or tools may reject, e.g. "+strings.Join(b.NonPortable, "; "))
	}

	return out
}

// policyIsPublic reports whether any Allow statement names a wildcard principal.
// It is deliberately a coarse check: a public principal is worth a look even when
// conditions narrow it, and auditors want it on the list.
func policyIsPublic(doc string) bool {
	if strings.TrimSpace(doc) == "" {
		return false
	}
	var p struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		return false
	}
	type statement struct {
		Effect    string          `json:"Effect"`
		Principal json.RawMessage `json:"Principal"`
	}
	var stmts []statement
	// Statement may be a single object or an array.
	if err := json.Unmarshal(p.Statement, &stmts); err != nil {
		var one statement
		if err := json.Unmarshal(p.Statement, &one); err != nil {
			return false
		}
		stmts = []statement{one}
	}
	for _, s := range stmts {
		if s.Effect == "Allow" && principalIsWildcard(s.Principal) {
			return true
		}
	}
	return false
}

func principalIsWildcard(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "*"
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	aws, ok := m["AWS"]
	if !ok {
		return false
	}
	if json.Unmarshal(aws, &s) == nil {
		return s == "*"
	}
	var list []string
	return json.Unmarshal(aws, &list) == nil && slices.Contains(list, "*")
}
