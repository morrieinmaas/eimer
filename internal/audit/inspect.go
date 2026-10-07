package audit

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/morrieinmaas/eimer/internal/minio"
	"github.com/morrieinmaas/eimer/internal/tunnel"
)

// Options configures one audit run.
type Options struct {
	Name      string // estate label, optional
	Endpoint  string
	Via       string // ssh host to forward through; the audit then runs locally against a tunnel
	Region    string
	AccessKey string // empty: fall back to the default AWS credential chain
	SecretKey string
	Buckets   []string      // empty: every bucket the credentials can list
	Sample    int           // objects to check per object-locked bucket
	ListMax   int           // objects listed per bucket for the inventory, 0 disables listing
	Insecure  bool          // skip TLS verification
	Parallel  int           // buckets inspected concurrently
	Timeout   time.Duration // per S3 call, retries included; 0 means 30 seconds
	Version   string
	HTTP      *http.Client // nil: a client with Insecure applied
	Log       io.Writer    // progress lines per bucket; nil for silence
}

// Run inspects the endpoint and returns a report with findings already evaluated.
func Run(ctx context.Context, o Options) (*Report, error) {
	if o.Region == "" {
		o.Region = "us-east-1"
	}
	if o.Parallel <= 0 {
		o.Parallel = 8
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	r := &Report{
		Tool:      "eimer",
		Version:   o.Version,
		Name:      o.Name,
		Endpoint:  o.Endpoint,
		Via:       o.Via,
		TLS:       strings.HasPrefix(strings.ToLower(o.Endpoint), "https://"),
		StartedAt: time.Now(),
	}

	serverName := ""
	var tun *tunnel.Tunnel
	if o.Via != "" {
		var err error
		if tun, err = tunnel.Open(ctx, o.Via, o.Endpoint); err != nil {
			return nil, err
		}
		defer tun.Close()
		if u, err := url.Parse(o.Endpoint); err == nil {
			serverName = u.Hostname() // the certificate names the real host, not 127.0.0.1
		}
		if o.Endpoint, err = tun.Rewrite(o.Endpoint); err != nil {
			return nil, err
		}
		fmt.Fprintf(o.Log, "%s: tunnel via %s, %s -> %s\n", r.Endpoint, o.Via, tun.Local, tun.Remote)
	}

	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: o.Timeout}
		if o.Insecure || serverName != "" {
			t := http.DefaultTransport.(*http.Transport).Clone()
			t.TLSClientConfig = &tls.Config{InsecureSkipVerify: o.Insecure, ServerName: serverName, MinVersion: tls.VersionTLS12} //nolint:gosec // --insecure is the operator's explicit choice
			o.HTTP.Transport = t
		}
	}

	client, creds, err := newClient(ctx, o, false)
	if err != nil {
		return nil, err
	}
	r.Engine, r.Hygiene = fingerprint(ctx, o.HTTP, o.Endpoint)

	fmt.Fprintf(o.Log, "%s: engine %s\n", r.Endpoint, r.Engine)
	names := o.Buckets
	if len(names) == 0 {
		names, err = listBuckets(ctx, client)
		if region, ok := expectedRegion(err); ok && region != o.Region {
			// MinIO names the region it wants in the error; one retry saves the user a guess.
			o.Region = region
			if client, creds, err = newClient(ctx, o, false); err == nil {
				names, err = listBuckets(ctx, client)
			}
		}
		if err != nil {
			if msg := tun.Stderr(); msg != "" {
				return nil, fmt.Errorf("list buckets: %w (ssh via %s said: %s)", err, o.Via, msg)
			}
			return nil, fmt.Errorf("list buckets: %w", err)
		}
	}
	r.Region = o.Region
	fmt.Fprintf(o.Log, "%s: %d bucket(s), %d in parallel, %s per call\n", r.Endpoint, len(names), o.Parallel, o.Timeout)

	anon, _, err := newClient(ctx, o, true)
	if err != nil {
		return nil, err
	}

	r.Buckets = make([]Bucket, len(names))
	var wg sync.WaitGroup
	sem := make(chan struct{}, o.Parallel)
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r.Buckets[i] = inspectBucket(ctx, client, anon, name, o)
			b := &r.Buckets[i]
			fmt.Fprintf(o.Log, "  %-40s %6.1fs  slowest %s %.1fs\n", name, b.Duration, b.SlowestProbe, b.SlowestSeconds)
		}(i, name)
	}
	wg.Wait()

	if strings.HasPrefix(r.Engine, "MinIO") {
		started := time.Now()
		r.MinIO = minio.Collect(ctx, minio.Options{Endpoint: o.Endpoint, Region: o.Region,
			AccessKey: creds.AccessKeyID, SecretKey: creds.SecretAccessKey, HTTP: o.HTTP})
		applyUsage(r.Buckets, r.MinIO.Usage)
		fmt.Fprintf(o.Log, "%s: minio admin %.1fs available=%v\n", r.Endpoint, time.Since(started).Seconds(), r.MinIO.Available)
	}

	r.Migration = Migration(r.Buckets)
	r.Findings = Evaluate(r)
	r.Duration = time.Since(r.StartedAt).Seconds()
	return r, nil
}

func newClient(ctx context.Context, o Options, anonymous bool) (*s3.Client, aws.Credentials, error) {
	loaders := []func(*config.LoadOptions) error{
		config.WithRegion(o.Region),
		config.WithHTTPClient(o.HTTP),
		config.WithRetryMaxAttempts(3),
		// Self-hosted stores never hand out EC2 instance roles; probing the metadata
		// service only turns "no credentials" into a slow, confusing timeout.
		config.WithEC2IMDSClientEnableState(imds.ClientDisabled),
	}
	switch {
	case anonymous:
		loaders = append(loaders, config.WithCredentialsProvider(aws.AnonymousCredentials{}))
	case o.AccessKey != "" || o.SecretKey != "":
		if o.AccessKey == "" || o.SecretKey == "" {
			return nil, aws.Credentials{}, errors.New("access key and secret key must be given together")
		}
		loaders = append(loaders, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(o.AccessKey, o.SecretKey, "")))
	}
	cfg, err := config.LoadDefaultConfig(ctx, loaders...)
	if err != nil {
		return nil, aws.Credentials{}, fmt.Errorf("load aws config: %w", err)
	}
	var creds aws.Credentials
	if !anonymous {
		if creds, err = cfg.Credentials.Retrieve(ctx); err != nil {
			return nil, creds, errors.New("no credentials found: pass --access-key and --secret-key, or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
		}
	}
	return s3.NewFromConfig(cfg, func(so *s3.Options) {
		so.BaseEndpoint = aws.String(o.Endpoint)
		so.UsePathStyle = true
		// Flexible checksums break several non-AWS engines; only send them when the API requires it.
		so.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		so.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	}), creds, nil
}

var expectingRegion = regexp.MustCompile(`expecting '([^']+)'`)

// expectedRegion extracts the region a MinIO-style AuthorizationHeaderMalformed error asks for.
func expectedRegion(err error) (string, bool) {
	var ae smithy.APIError
	if !errors.As(err, &ae) || ae.ErrorCode() != "AuthorizationHeaderMalformed" {
		return "", false
	}
	m := expectingRegion.FindStringSubmatch(ae.ErrorMessage())
	if m == nil {
		return "", false
	}
	return m[1], true
}

// fingerprint identifies the engine and records transport facts with unauthenticated
// GETs. Most engines name themselves in the Server header. RustFS sends none but serves
// /health, which MinIO does not; both serve MinIO's /minio/health/live.
func fingerprint(ctx context.Context, hc *http.Client, endpoint string) (string, Hygiene) {
	var h Hygiene
	get := func(path string) (int, *http.Response) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+path, nil)
		if err != nil {
			return 0, nil
		}
		resp, err := hc.Do(req)
		if err != nil {
			return 0, nil
		}
		_ = resp.Body.Close()
		return resp.StatusCode, resp
	}
	_, resp := get("/")
	if resp == nil {
		return "unknown", h
	}
	h.ServerHeader = resp.Header.Get("Server")
	if date, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		h.ClockSkewSeconds = time.Until(date).Round(time.Second).Seconds()
	}
	if cs := resp.TLS; cs != nil {
		h.TLSVersion = tls.VersionName(cs.Version)
		if len(cs.PeerCertificates) > 0 {
			cert := cs.PeerCertificates[0]
			expires := cert.NotAfter
			h.CertExpires = &expires
			h.CertIssuer = cert.Issuer.CommonName
		}
	}
	if h.ServerHeader != "" {
		for _, known := range []string{"MinIO", "RustFS", "Garage", "SeaweedFS", "Ceph", "AmazonS3"} {
			if strings.Contains(strings.ToLower(h.ServerHeader), strings.ToLower(known)) {
				return known, h
			}
		}
		return h.ServerHeader, h
	}
	if code, _ := get("/health"); code == http.StatusOK {
		return "RustFS (probable)", h
	}
	if code, _ := get("/minio/health/live"); code == http.StatusOK {
		return "MinIO-compatible", h
	}
	return "unknown", h
}

func listBuckets(ctx context.Context, c *s3.Client) ([]string, error) {
	var names []string
	p := s3.NewListBucketsPaginator(c, &s3.ListBucketsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, b := range page.Buckets {
			names = append(names, aws.ToString(b.Name))
		}
	}
	sort.Strings(names)
	return names, nil
}

func inspectBucket(parent context.Context, c, anon *s3.Client, name string, o Options) (b Bucket) {
	b = Bucket{Name: name}
	if !validBucketName(name) {
		b.Skipped = "invalid name"
		return b
	}
	n := aws.String(name)
	started := time.Now()
	defer func() { b.Duration = time.Since(started).Seconds() }()

	// timed runs one step under its own deadline and remembers the slowest one, so a
	// stalling call shows up by name in the report instead of as a silent hang.
	timed := func(step string, fn func(ctx context.Context) error) error {
		ctx, cancel := context.WithTimeout(parent, o.Timeout)
		defer cancel()
		t0 := time.Now()
		err := fn(ctx)
		if d := time.Since(t0).Seconds(); d > b.SlowestSeconds {
			b.SlowestProbe, b.SlowestSeconds = step, d
		}
		return err
	}
	probe := func(step string, fn func(ctx context.Context) error) Probe {
		return classify(timed(step, fn))
	}

	b.Versioning.Probe = probe("versioning", func(ctx context.Context) error {
		out, err := c.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: n})
		if err != nil {
			return err
		}
		b.Versioning.Status = string(out.Status)
		b.Versioning.MFADelete = out.MFADelete == types.MFADeleteStatusEnabled
		return nil
	})

	b.ObjectLock.Probe = probe("object-lock", func(ctx context.Context) error {
		out, err := c.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: n})
		if err != nil {
			return err
		}
		cfg := out.ObjectLockConfiguration
		if cfg == nil || cfg.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
			return nil
		}
		b.ObjectLock.Enabled = true
		if cfg.Rule != nil && cfg.Rule.DefaultRetention != nil {
			dr := cfg.Rule.DefaultRetention
			b.ObjectLock.Mode = string(dr.Mode)
			b.ObjectLock.RetentionDays = int(aws.ToInt32(dr.Days)) + 365*int(aws.ToInt32(dr.Years))
		}
		return nil
	})

	b.Policy.Probe = probe("policy", func(ctx context.Context) error {
		out, err := c.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: n})
		if err != nil {
			return err
		}
		b.Policy.Document = aws.ToString(out.Policy)
		return nil
	})

	b.ACL.Probe = probe("acl", func(ctx context.Context) error {
		out, err := c.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: n})
		if err != nil {
			return err
		}
		b.ACL.Grants = len(out.Grants)
		for _, g := range out.Grants {
			if g.Grantee == nil || g.Grantee.Type != types.TypeGroup {
				continue
			}
			uri := aws.ToString(g.Grantee.URI)
			if !strings.HasSuffix(uri, "/AllUsers") && !strings.HasSuffix(uri, "/AuthenticatedUsers") {
				continue
			}
			switch g.Permission {
			case types.PermissionRead, types.PermissionReadAcp:
				b.ACL.PublicRead = true
			case types.PermissionWrite, types.PermissionWriteAcp, types.PermissionFullControl:
				b.ACL.PublicRead = true
				b.ACL.PublicWrite = true
			}
		}
		return nil
	})

	b.Lifecycle.Probe = probe("lifecycle", func(ctx context.Context) error {
		out, err := c.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: n})
		if err != nil {
			return err
		}
		for _, rule := range out.Rules {
			lr := LifecycleRule{ID: aws.ToString(rule.ID), Enabled: rule.Status == types.ExpirationStatusEnabled}
			if rule.Expiration != nil {
				lr.ExpirationDays = int(aws.ToInt32(rule.Expiration.Days))
			}
			if rule.NoncurrentVersionExpiration != nil {
				lr.NoncurrentExpiryDays = int(aws.ToInt32(rule.NoncurrentVersionExpiration.NoncurrentDays))
			}
			b.Lifecycle.Rules = append(b.Lifecycle.Rules, lr)
		}
		return nil
	})

	b.Encryption.Probe = probe("encryption", func(ctx context.Context) error {
		out, err := c.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: n})
		if err != nil {
			return err
		}
		if cfg := out.ServerSideEncryptionConfiguration; cfg != nil {
			for _, rule := range cfg.Rules {
				if rule.ApplyServerSideEncryptionByDefault != nil {
					b.Encryption.Algorithm = string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
					break
				}
			}
		}
		return nil
	})

	b.Logging.Probe = probe("logging", func(ctx context.Context) error {
		out, err := c.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: n})
		if err != nil {
			return err
		}
		if out.LoggingEnabled != nil {
			b.Logging.TargetBucket = aws.ToString(out.LoggingEnabled.TargetBucket)
		}
		return nil
	})

	b.Replication.Probe = probe("replication", func(ctx context.Context) error {
		out, err := c.GetBucketReplication(ctx, &s3.GetBucketReplicationInput{Bucket: n})
		if err != nil {
			return err
		}
		if out.ReplicationConfiguration != nil {
			b.Replication.Rules = len(out.ReplicationConfiguration.Rules)
		}
		return nil
	})

	b.Notification.Probe = probe("notification", func(ctx context.Context) error {
		out, err := c.GetBucketNotificationConfiguration(ctx, &s3.GetBucketNotificationConfigurationInput{Bucket: n})
		if err != nil {
			return err
		}
		b.Notification.Targets = len(out.LambdaFunctionConfigurations) + len(out.QueueConfigurations) + len(out.TopicConfigurations)
		return nil
	})

	b.Tagging.Probe = probe("tagging", func(ctx context.Context) error {
		out, err := c.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: n})
		if err != nil {
			return err
		}
		for _, t := range out.TagSet {
			if b.Tagging.Tags == nil {
				b.Tagging.Tags = map[string]string{}
			}
			b.Tagging.Tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
		return nil
	})

	b.CORS.Probe = probe("cors", func(ctx context.Context) error {
		out, err := c.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: n})
		if err != nil {
			return err
		}
		b.CORS.Rules = len(out.CORSRules)
		return nil
	})

	b.Multipart.Probe = probe("multipart", func(ctx context.Context) error {
		out, err := c.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: n, MaxUploads: aws.Int32(1000)})
		if err != nil {
			return err
		}
		b.Multipart.Uploads = len(out.Uploads)
		for _, u := range out.Uploads {
			if u.Initiated != nil && (b.Multipart.OldestInitiated == nil || u.Initiated.Before(*b.Multipart.OldestInitiated)) {
				b.Multipart.OldestInitiated = u.Initiated
			}
		}
		return nil
	})

	var objects []types.Object
	if err := timed("list", func(ctx context.Context) error {
		var truncated bool
		var err error
		objects, truncated, err = listObjects(ctx, c, name, o.ListMax)
		if err != nil {
			return err
		}
		b.Inventory = inventory(objects, truncated)
		b.NonPortable = nonPortableKeys(objects, 5)
		return nil
	}); err != nil {
		b.Inventory.Error = describe(err)
	}

	_ = timed("anonymous", func(ctx context.Context) error {
		b.Exposure = exposure(ctx, anon, name, firstFileKey(objects))
		return nil
	})

	if b.ObjectLock.Enabled && o.Sample > 0 {
		_ = timed("sample", func(ctx context.Context) error {
			b.Sample = sampleObjects(ctx, c, name, objects, o.Sample)
			return nil
		})
	}
	return b
}

// listObjects returns up to limit objects. ponytail: the first keys in listing order, not a
// spread across the key space; prefix-stratified sampling is the upgrade if an estate
// turns out to hide its interesting objects at the end of the alphabet.
func listObjects(ctx context.Context, c *s3.Client, bucket string, limit int) ([]types.Object, bool, error) {
	if limit <= 0 {
		return nil, false, nil
	}
	var objects []types.Object
	// Ask for exactly the cap: on big MinIO buckets a 1000-key page costs 10 to 30 seconds.
	p := s3.NewListObjectsV2Paginator(c, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), MaxKeys: aws.Int32(int32(min(limit, 1000)))})
	for p.HasMorePages() && len(objects) < limit {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, false, err
		}
		objects = append(objects, page.Contents...)
	}
	if len(objects) > limit {
		return objects[:limit], true, nil
	}
	return objects, p.HasMorePages(), nil
}

func inventory(objects []types.Object, truncated bool) Inventory {
	inv := Inventory{Truncated: truncated}
	for _, obj := range objects {
		size := aws.ToInt64(obj.Size)
		key := aws.ToString(obj.Key)
		inv.Objects++
		inv.Bytes += size
		if size == 0 && strings.HasSuffix(key, "/") {
			inv.FolderMarkers++
		}
		switch {
		case size < 1_000:
			inv.Bands.Under1KB++
		case size < 1_000_000:
			inv.Bands.Under1MB++
		case size < 100_000_000:
			inv.Bands.Under100MB++
		default:
			inv.Bands.Over100MB++
		}
		if size > inv.LargestBytes {
			inv.LargestBytes, inv.LargestKey = size, key
		}
		if t := obj.LastModified; t != nil {
			if inv.Oldest == nil || t.Before(*inv.Oldest) {
				inv.Oldest = t
			}
			if inv.Newest == nil || t.After(*inv.Newest) {
				inv.Newest = t
			}
		}
	}
	return inv
}

func nonPortableKeys(objects []types.Object, limit int) []string {
	var out []string
	for _, obj := range objects {
		if len(out) == limit {
			break
		}
		key := aws.ToString(obj.Key)
		if why := nonPortableKey(key); why != "" {
			out = append(out, fmt.Sprintf("%s (%s)", key, why))
		}
	}
	return out
}

func firstFileKey(objects []types.Object) string {
	for _, obj := range objects {
		if key := aws.ToString(obj.Key); !strings.HasSuffix(key, "/") && aws.ToInt64(obj.Size) > 0 {
			return key
		}
	}
	return ""
}

// exposure asks the store, without credentials, for a listing and for one byte of
// one object. Policy and ACL say what should happen; this is what does happen.
func exposure(ctx context.Context, anon *s3.Client, bucket, key string) Exposure {
	var e Exposure
	_, err := anon.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), MaxKeys: aws.Int32(1)})
	switch {
	case err == nil:
		e.AnonymousList = true
	case !isAPIError(err):
		e.Error = describe(err)
		return e
	}
	if key == "" {
		return e
	}
	out, err := anon.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Range: aws.String("bytes=0-0")})
	switch {
	case err == nil:
		_, _ = io.Copy(io.Discard, out.Body)
		_ = out.Body.Close()
		e.AnonymousRead = true
		e.ProofKey = key
	case !isAPIError(err):
		e.Error = describe(err)
	}
	return e
}

// sampleObjects checks per-object lock state on the first n listed objects.
func sampleObjects(ctx context.Context, c *s3.Client, bucket string, objects []types.Object, n int) []SampledObject {
	var sample []SampledObject
	for _, obj := range objects {
		if len(sample) == n {
			break
		}
		key := aws.ToString(obj.Key)
		so := SampledObject{Key: key}
		ret, err := c.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: aws.String(bucket), Key: aws.String(key)})
		switch {
		case err == nil && ret.Retention != nil:
			so.RetentionMode = string(ret.Retention.Mode)
			so.RetainUntil = ret.Retention.RetainUntilDate
		case err != nil && !isNotFound(err):
			so.Error = describe(err)
		}
		hold, err := c.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{Bucket: aws.String(bucket), Key: aws.String(key)})
		switch {
		case err == nil && hold.LegalHold != nil:
			so.LegalHold = hold.LegalHold.Status == types.ObjectLockLegalHoldStatusOn
		case err != nil && !isNotFound(err) && so.Error == "":
			so.Error = describe(err)
		}
		sample = append(sample, so)
	}
	return sample
}

// classify turns a configuration read's error into a probe outcome. "Not found" codes
// mean the feature is supported but unset, which is a value, not an error.
func classify(err error) Probe {
	switch {
	case err == nil, isNotFound(err):
		return Probe{Supported: true}
	case isUnsupported(err):
		return Probe{Supported: false}
	default:
		return Probe{Supported: true, Error: describe(err)}
	}
}

var notFoundCodes = map[string]bool{
	"NoSuchBucketPolicy":                             true,
	"NoSuchLifecycleConfiguration":                   true,
	"NoSuchTagSet":                                   true,
	"NoSuchCORSConfiguration":                        true,
	"ObjectLockConfigurationNotFoundError":           true,
	"NoSuchObjectLockConfiguration":                  true,
	"ServerSideEncryptionConfigurationNotFoundError": true,
	"ReplicationConfigurationNotFoundError":          true,
}

func isAPIError(err error) bool {
	var ae smithy.APIError
	return errors.As(err, &ae)
}

func isNotFound(err error) bool {
	var ae smithy.APIError
	return errors.As(err, &ae) && notFoundCodes[ae.ErrorCode()]
}

func isUnsupported(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "NotImplemented", "MethodNotAllowed", "UnsupportedOperation":
			return true
		}
	}
	var re *awshttp.ResponseError
	return errors.As(err, &re) && (re.HTTPStatusCode() == http.StatusNotImplemented || re.HTTPStatusCode() == http.StatusMethodNotAllowed)
}

func describe(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return err.Error()
}

// validBucketName applies the S3 DNS-compatible naming rules: 3 to 63 characters of
// lowercase letters, digits, dots and hyphens, starting and ending with a letter or digit.
// Legacy MinIO accepted more; path-style addressing and most other engines do not.
func validBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if i == 0 || i == len(name)-1 {
			if !alnum {
				return false
			}
			continue
		}
		if !alnum && c != '-' && c != '.' {
			return false
		}
	}
	return true
}
