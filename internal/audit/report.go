// Package audit inspects an S3-compatible endpoint and reports compliance findings.
//
// It is read-only by construction: the only S3 calls issued are ListBuckets, the
// GetBucket* configuration reads, ListObjectsV2, ListMultipartUploads,
// GetObject{Retention,LegalHold}, and for the exposure check an anonymous
// ListObjectsV2 plus a one-byte anonymous GetObject.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/morrieinmaas/eimer/internal/minio"
)

// Severity orders findings. Higher is worse.
type Severity int

// Severity levels, lowest to highest.
const (
	Info Severity = iota
	Low
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	default:
		return "info"
	}
}

// MarshalJSON renders the severity as its lowercase name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON parses the lowercase name written by MarshalJSON.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	switch str {
	case "high":
		*s = High
	case "medium":
		*s = Medium
	case "low":
		*s = Low
	case "info":
		*s = Info
	default:
		return fmt.Errorf("unknown severity %q", str)
	}
	return nil
}

// Finding is one rule violation on one bucket ("" for endpoint-level findings).
type Finding struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Bucket   string   `json:"bucket,omitempty"`
	Message  string   `json:"message"`
}

// Probe is the outcome of one configuration read. Exactly one of Supported=false,
// Error!="" or a value on the enclosing struct is meaningful.
type Probe struct {
	Supported bool   `json:"supported"`
	Error     string `json:"error,omitempty"`
}

// OK reports whether the probe produced a usable value.
func (p Probe) OK() bool { return p.Supported && p.Error == "" }

// ObjectLock is the bucket default object-lock configuration.
type ObjectLock struct {
	Probe
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode,omitempty"` // GOVERNANCE or COMPLIANCE
	RetentionDays int    `json:"retention_days,omitempty"`
}

// Versioning is the bucket versioning state.
type Versioning struct {
	Probe
	Status    string `json:"status,omitempty"` // Enabled, Suspended or "" (never enabled)
	MFADelete bool   `json:"mfa_delete"`
}

// Policy is the bucket policy document.
type Policy struct {
	Probe
	Document string `json:"document,omitempty"`
}

// ACL is the bucket access control list, reduced to what matters.
type ACL struct {
	Probe
	Grants      int  `json:"grants"`
	PublicRead  bool `json:"public_read"`
	PublicWrite bool `json:"public_write"`
}

// Exposure is the empirical anonymous-access check: what an unauthenticated
// client actually gets, regardless of what policy and ACL say.
type Exposure struct {
	AnonymousList bool   `json:"anonymous_list"`
	AnonymousRead bool   `json:"anonymous_read"`
	ProofKey      string `json:"proof_key,omitempty"` // object fetched (one byte) to prove read access
	Error         string `json:"error,omitempty"`
}

// Lifecycle summarises lifecycle rules.
type Lifecycle struct {
	Probe
	Rules []LifecycleRule `json:"rules,omitempty"`
}

// LifecycleRule is the subset of a lifecycle rule the rules engine looks at.
type LifecycleRule struct {
	ID                   string `json:"id,omitempty"`
	Enabled              bool   `json:"enabled"`
	ExpirationDays       int    `json:"expiration_days,omitempty"`
	NoncurrentExpiryDays int    `json:"noncurrent_expiration_days,omitempty"`
}

// Encryption is the default server-side encryption configuration.
type Encryption struct {
	Probe
	Algorithm string `json:"algorithm,omitempty"`
}

// Logging is the server access logging target.
type Logging struct {
	Probe
	TargetBucket string `json:"target_bucket,omitempty"`
}

// Replication reports whether a replication configuration exists.
type Replication struct {
	Probe
	Rules int `json:"rules"`
}

// Notification reports event notification targets.
type Notification struct {
	Probe
	Targets int `json:"targets"`
}

// Tagging reports bucket tags.
type Tagging struct {
	Probe
	Tags map[string]string `json:"tags,omitempty"`
}

// CORS reports CORS rules.
type CORS struct {
	Probe
	Rules int `json:"rules"`
}

// Multipart reports in-progress multipart uploads, which hold space invisibly.
type Multipart struct {
	Probe
	Uploads         int        `json:"uploads"`
	OldestInitiated *time.Time `json:"oldest_initiated,omitempty"`
}

// SizeBands counts objects by size, decimal units.
type SizeBands struct {
	Under1KB   int64 `json:"lt_1kb"`
	Under1MB   int64 `json:"lt_1mb"`
	Under100MB int64 `json:"lt_100mb"`
	Over100MB  int64 `json:"ge_100mb"`
}

// Inventory summarises the objects seen in a capped listing. Truncated means the
// cap was hit and Objects/Bytes are lower bounds, unless Exact says an engine
// adapter replaced them with server-side totals.
type Inventory struct {
	Objects       int64      `json:"objects"`
	Bytes         int64      `json:"bytes"`
	Truncated     bool       `json:"truncated"`
	Exact         bool       `json:"exact"`
	Versions      int64      `json:"versions,omitempty"`
	Oldest        *time.Time `json:"oldest,omitempty"`
	Newest        *time.Time `json:"newest,omitempty"`
	LargestBytes  int64      `json:"largest_bytes,omitempty"`
	LargestKey    string     `json:"largest_key,omitempty"`
	FolderMarkers int64      `json:"folder_markers"`
	Bands         SizeBands  `json:"size_bands"`
	Error         string     `json:"error,omitempty"`
}

// SampledObject is one object checked for per-object lock state.
type SampledObject struct {
	Key           string     `json:"key"`
	RetainUntil   *time.Time `json:"retain_until,omitempty"`
	RetentionMode string     `json:"retention_mode,omitempty"`
	LegalHold     bool       `json:"legal_hold"`
	Error         string     `json:"error,omitempty"`
}

// Protected reports whether the object has any lock applied.
func (o SampledObject) Protected() bool { return o.LegalHold || o.RetainUntil != nil }

// Bucket holds every fact collected about one bucket.
type Bucket struct {
	Name           string          `json:"name"`
	Created        *time.Time      `json:"created,omitempty"`
	Skipped        string          `json:"skipped,omitempty"` // why no probes ran, e.g. a name S3 clients cannot address
	Versioning     Versioning      `json:"versioning"`
	ObjectLock     ObjectLock      `json:"object_lock"`
	Policy         Policy          `json:"policy"`
	ACL            ACL             `json:"acl"`
	Exposure       Exposure        `json:"exposure"`
	Lifecycle      Lifecycle       `json:"lifecycle"`
	Encryption     Encryption      `json:"encryption"`
	Logging        Logging         `json:"logging"`
	Replication    Replication     `json:"replication"`
	Notification   Notification    `json:"notification"`
	Tagging        Tagging         `json:"tagging"`
	CORS           CORS            `json:"cors"`
	Multipart      Multipart       `json:"multipart"`
	Inventory      Inventory       `json:"inventory"`
	NonPortable    []string        `json:"nonportable_keys,omitempty"` // example keys other engines may reject
	Sample         []SampledObject `json:"sample,omitempty"`
	Duration       float64         `json:"duration_seconds"`
	SlowestProbe   string          `json:"slowest_probe,omitempty"`
	SlowestSeconds float64         `json:"slowest_seconds,omitempty"`
}

// Hygiene holds endpoint-level transport facts from the fingerprint request.
type Hygiene struct {
	ServerHeader     string     `json:"server_header,omitempty"`
	TLSVersion       string     `json:"tls_version,omitempty"`
	CertExpires      *time.Time `json:"cert_expires,omitempty"`
	CertIssuer       string     `json:"cert_issuer,omitempty"`
	ClockSkewSeconds float64    `json:"clock_skew_seconds"`
}

// Report is the full audit output for one endpoint.
type Report struct {
	Tool      string      `json:"tool"`
	Version   string      `json:"version"`
	Name      string      `json:"name,omitempty"` // estate label from the config file
	Endpoint  string      `json:"endpoint"`
	Engine    string      `json:"engine"`
	TLS       bool        `json:"tls"`
	Hygiene   Hygiene     `json:"hygiene"`
	Region    string      `json:"region"`
	StartedAt time.Time   `json:"started_at"`
	Duration  float64     `json:"duration_seconds"`
	Buckets   []Bucket    `json:"buckets"`
	Findings  []Finding   `json:"findings"`
	Migration []CarryOver `json:"migration,omitempty"`
	MinIO     *minio.Info `json:"minio,omitempty"` // engine adapter, present when the store is MinIO
}

// Worst returns the highest severity among findings, or Info when there are none.
func (r *Report) Worst() Severity {
	w := Info
	for _, f := range r.Findings {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

// WriteJSON renders the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText renders a human-readable report.
func (r *Report) WriteText(w io.Writer) error {
	tls := "no"
	if r.TLS {
		tls = "yes"
		if h := r.Hygiene; h.CertExpires != nil {
			tls = fmt.Sprintf("%s, cert expires %s", h.TLSVersion, h.CertExpires.UTC().Format("2006-01-02"))
		}
	}
	label := r.Endpoint
	if r.Name != "" {
		label = r.Name + " (" + r.Endpoint + ")"
	}
	fmt.Fprintf(w, "%s %s audit of %s\n", r.Tool, r.Version, label)
	fmt.Fprintf(w, "engine: %s   tls: %s   region: %s   buckets: %d   started: %s   took: %.1fs\n\n",
		r.Engine, tls, r.Region, len(r.Buckets), r.StartedAt.UTC().Format(time.RFC3339), r.Duration)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "BUCKET\tVERSIONING\tOBJECT LOCK\tPOLICY\tACL\tANONYMOUS\tENCRYPTION\tSAMPLE")
	for _, b := range r.Buckets {
		if b.Skipped != "" {
			fmt.Fprintf(tw, "%s\tskipped: %s\t-\t-\t-\t-\t-\t-\n", b.Name, b.Skipped)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			b.Name, versioningCell(b.Versioning), lockCell(b.ObjectLock), policyCell(b.Policy),
			aclCell(b.ACL), exposureCell(b.Exposure), encryptionCell(b.Encryption), sampleCell(b))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "BUCKET\tOBJECTS\tSIZE\tOLDEST\tNEWEST\tLIFECYCLE\tREPLICATION\tNOTIFY\tMULTIPART")
	for _, b := range r.Buckets {
		if b.Skipped != "" {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			b.Name, countCell(b.Inventory), sizeCell(b.Inventory), dateCell(b.Inventory.Oldest), dateCell(b.Inventory.Newest),
			lifecycleCell(b.Lifecycle), replicationCell(b.Replication), notificationCell(b.Notification), multipartCell(b.Multipart))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(r.Migration) > 0 {
		fmt.Fprintln(w)
		writeMigration(w, r.Migration)
	}
	if r.MinIO != nil {
		fmt.Fprintln(w)
		writeMinIO(w, r.MinIO)
	}

	fmt.Fprintln(w)
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "no findings")
		return nil
	}
	fmt.Fprintf(w, "%d finding(s)\n", len(r.Findings))
	for _, g := range groupFindings(r.Findings) {
		fmt.Fprintf(w, "  [%-6s] %-34s %s\n", g.Severity, g.ID, g.Message)
		fmt.Fprintf(w, "%*s%s\n", 12, "", scopeList(g.Buckets))
	}
	return nil
}

// findingGroup is one rule and every bucket it fired on, for the text report.
type findingGroup struct {
	ID       string
	Severity Severity
	Message  string // the first message; per-bucket detail lives in the JSON report
	Buckets  []string
}

// groupFindings collapses identical rule hits across buckets, highest severity first.
func groupFindings(findings []Finding) []findingGroup {
	byID := map[string]*findingGroup{}
	var order []string
	for _, f := range findings {
		g, ok := byID[f.ID]
		if !ok {
			g = &findingGroup{ID: f.ID, Severity: f.Severity, Message: f.Message}
			byID[f.ID] = g
			order = append(order, f.ID)
		}
		bucket := f.Bucket
		if bucket == "" {
			bucket = "endpoint"
		}
		g.Buckets = append(g.Buckets, bucket)
	}
	groups := make([]findingGroup, 0, len(order))
	for _, id := range order {
		groups = append(groups, *byID[id])
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Severity > groups[j].Severity })
	return groups
}

// scopeList names up to five buckets and counts the rest.
func scopeList(buckets []string) string {
	const show = 5
	if len(buckets) <= show {
		return strings.Join(buckets, ", ")
	}
	return fmt.Sprintf("%s and %d more (%d total)", strings.Join(buckets[:show], ", "), len(buckets)-show, len(buckets))
}

func probeCell(p Probe) (string, bool) {
	switch {
	case p.Error != "":
		return "error: " + p.Error, true
	case !p.Supported:
		return "n/a", true
	}
	return "", false
}

func versioningCell(v Versioning) string {
	if s, ok := probeCell(v.Probe); ok {
		return s
	}
	if v.Status == "" {
		return "off"
	}
	return strings.ToLower(v.Status)
}

func lockCell(l ObjectLock) string {
	if s, ok := probeCell(l.Probe); ok {
		return s
	}
	if !l.Enabled {
		return "off"
	}
	if l.Mode == "" {
		return "on, no default"
	}
	return fmt.Sprintf("%s %dd", strings.ToLower(l.Mode), l.RetentionDays)
}

func policyCell(p Policy) string {
	if s, ok := probeCell(p.Probe); ok {
		return s
	}
	if p.Document == "" {
		return "none"
	}
	if policyIsPublic(p.Document) {
		return "PUBLIC"
	}
	return "set"
}

func aclCell(a ACL) string {
	if s, ok := probeCell(a.Probe); ok {
		return s
	}
	switch {
	case a.PublicWrite:
		return "PUBLIC WRITE"
	case a.PublicRead:
		return "PUBLIC READ"
	}
	return "private"
}

func exposureCell(e Exposure) string {
	switch {
	case e.Error != "":
		return "error: " + e.Error
	case e.AnonymousRead && e.AnonymousList:
		return "LIST+READ"
	case e.AnonymousRead:
		return "READ"
	case e.AnonymousList:
		return "LIST"
	}
	return "denied"
}

func lifecycleCell(l Lifecycle) string {
	if s, ok := probeCell(l.Probe); ok {
		return s
	}
	return fmt.Sprintf("%d rule(s)", len(l.Rules))
}

func encryptionCell(e Encryption) string {
	if s, ok := probeCell(e.Probe); ok {
		return s
	}
	if e.Algorithm == "" {
		return "off"
	}
	return e.Algorithm
}

func replicationCell(r Replication) string {
	if s, ok := probeCell(r.Probe); ok {
		return s
	}
	if r.Rules == 0 {
		return "none"
	}
	return fmt.Sprintf("%d rule(s)", r.Rules)
}

func notificationCell(n Notification) string {
	if s, ok := probeCell(n.Probe); ok {
		return s
	}
	if n.Targets == 0 {
		return "none"
	}
	return fmt.Sprintf("%d target(s)", n.Targets)
}

func multipartCell(m Multipart) string {
	if s, ok := probeCell(m.Probe); ok {
		return s
	}
	if m.Uploads == 0 {
		return "none"
	}
	return fmt.Sprintf("%d open", m.Uploads)
}

func countCell(inv Inventory) string {
	if inv.Error != "" {
		return "error: " + inv.Error
	}
	if inv.Truncated && !inv.Exact {
		return fmt.Sprintf(">=%d", inv.Objects)
	}
	return fmt.Sprintf("%d", inv.Objects)
}

func sizeCell(inv Inventory) string {
	if inv.Error != "" {
		return "-"
	}
	s := humanBytes(inv.Bytes)
	if inv.Truncated && !inv.Exact {
		return ">=" + s
	}
	return s
}

func dateCell(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format("2006-01-02")
}

func sampleCell(b Bucket) string {
	if len(b.Sample) == 0 {
		return "-"
	}
	locked := 0
	for _, o := range b.Sample {
		if o.Protected() {
			locked++
		}
	}
	return fmt.Sprintf("%d/%d locked", locked, len(b.Sample))
}

// humanBytes formats with decimal units, as the storage industry quotes capacity.
func humanBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}
