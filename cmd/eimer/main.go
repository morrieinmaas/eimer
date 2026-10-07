// Command eimer audits S3-compatible endpoints for object-lock, versioning, exposure and
// migration posture, and diffs two reports to show drift.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/morrieinmaas/eimer/internal/audit"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

const usage = `eimer: offline compliance audit for S3-compatible object stores

usage:
  eimer audit --endpoint URL [flags]      audit one endpoint (or every [[estate]] in the config)
  eimer diff OLD.json NEW.json            show what changed between two reports
  eimer version

The audit is read-only and nothing leaves your machine except S3 reads to the endpoint.

Every flag can also come from an EIMER_* environment variable or a TOML file
(--config, else ./eimer.toml, else ~/.config/eimer/config.toml). Precedence:
flags, then environment, then file, then defaults. Credentials are also read
from AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY and MINIO_ACCESS_KEY/MINIO_SECRET_KEY.

exit codes:
  0  audit ran, no high-severity findings (diff: no changes)
  1  usage, configuration or connection error
  3  at least one high-severity finding
  4  diff found changes
`

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("eimer", version)
	case "audit":
		os.Exit(runAudit(os.Args[2:]))
	case "diff":
		os.Exit(runDiff(os.Args[2:]))
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
}

// preScan finds a flag's value before the flag set exists, so --config and --env-file
// can seed the defaults the other flags are parsed against.
func preScan(args []string, name, envName string) string {
	for i, a := range args {
		a = strings.TrimLeft(a, "-")
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			return v
		}
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return os.Getenv(envName)
}

func configPathFromArgs(args []string) string { return preScan(args, "config", "EIMER_CONFIG") }

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "eimer:", err)
	return 1
}

func runAudit(args []string) int {
	getenv := os.Getenv
	if path := preScan(args, "env-file", "EIMER_ENV_FILE"); path != "" {
		var err error
		if getenv, err = loadEnvFile(path, os.Getenv); err != nil {
			return fail(err)
		}
	}
	cfg, err := loadConfig(configPathFromArgs(args), getenv)
	if err != nil {
		return fail(err)
	}

	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	var configPath string
	var buckets multiFlag
	fs.StringVar(&configPath, "config", "", "TOML config file (default: ./eimer.toml, then ~/.config/eimer/config.toml)")
	fs.StringVar(&cfg.EnvFile, "env-file", cfg.EnvFile, "KEY=VALUE file whose variables take precedence over the environment, e.g. a gitignored .env with the keys")
	fs.IntVar(&cfg.Timeout, "timeout", cfg.Timeout, "seconds allowed per S3 call, retries included")
	fs.BoolVar(&cfg.Verbose, "v", cfg.Verbose, "progress and per-bucket timing on stderr")
	fs.StringVar(&cfg.Endpoint, "endpoint", cfg.Endpoint, "S3 endpoint URL, e.g. https://s3.example.org:9000")
	fs.StringVar(&cfg.Region, "region", cfg.Region, "signing region; some engines reject a mismatch")
	fs.StringVar(&cfg.AccessKey, "access-key", cfg.AccessKey, "access key (default: env, then the AWS profile chain)")
	fs.StringVar(&cfg.SecretKey, "secret-key", cfg.SecretKey, "secret key")
	fs.Var(&buckets, "bucket", "audit only this bucket; repeatable (default: every bucket listed)")
	fs.IntVar(&cfg.Sample, "sample", cfg.Sample, "objects to check for per-object retention in each object-locked bucket, 0 disables")
	fs.IntVar(&cfg.ListMax, "list-max", cfg.ListMax, "objects listed per bucket for the inventory and exposure checks, 0 disables")
	fs.IntVar(&cfg.Parallel, "parallel", cfg.Parallel, "buckets inspected concurrently")
	fs.BoolVar(&cfg.Insecure, "insecure", cfg.Insecure, "skip TLS certificate verification")
	fs.BoolVar(&cfg.JSON, "json", cfg.JSON, "emit the full report as JSON on stdout instead of text")
	fs.StringVar(&cfg.Out, "out", cfg.Out, "also write the JSON report to this file, with a .sha256 sidecar")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage, "\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if len(buckets) > 0 {
		cfg.Buckets = buckets
	}

	targets := cfg.targets(getenv)
	for i := range targets {
		if targets[i].Endpoint == "" {
			return fail(fmt.Errorf("an endpoint is required (--endpoint, EIMER_ENDPOINT, or endpoint in the config file)"))
		}
		if !strings.HasPrefix(targets[i].Endpoint, "http://") && !strings.HasPrefix(targets[i].Endpoint, "https://") {
			targets[i].Endpoint = "https://" + targets[i].Endpoint
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// A dropped ssh session must not kill a long audit: with SIGPIPE ignored, writes to a
	// dead terminal fail quietly and the evidence file still gets written.
	signal.Ignore(syscall.SIGPIPE)

	estate := &audit.Estate{Tool: "eimer", Version: version, GeneratedAt: time.Now()}
	for _, t := range targets {
		report, err := audit.Run(ctx, audit.Options{
			Name:      t.Name,
			Endpoint:  t.Endpoint,
			Region:    t.Region,
			AccessKey: t.AccessKey,
			SecretKey: t.SecretKey,
			Buckets:   t.Buckets,
			Sample:    cfg.Sample,
			ListMax:   cfg.ListMax,
			Parallel:  cfg.Parallel,
			Insecure:  *t.Insecure,
			Timeout:   time.Duration(cfg.Timeout) * time.Second,
			Version:   version,
			Log:       logWriter(cfg.Verbose),
		})
		if err != nil {
			label := t.Name
			if label == "" {
				label = t.Endpoint
			}
			return fail(fmt.Errorf("%s: %w", label, err))
		}
		estate.Reports = append(estate.Reports, report)
	}

	// Save before printing: the file is the deliverable, the terminal may be gone.
	if cfg.Out != "" {
		digest, err := estate.Save(cfg.Out)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (sha256 %s)\n", cfg.Out, digest)
	}
	if cfg.JSON {
		err = estate.WriteJSON(os.Stdout)
	} else {
		err = estate.WriteText(os.Stdout)
	}
	if err != nil {
		return fail(err)
	}
	if estate.Worst() >= audit.High {
		return 3
	}
	return 0
}

func logWriter(verbose bool) io.Writer {
	if verbose {
		return os.Stderr
	}
	return io.Discard
}

func runDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, "usage: eimer diff OLD.json NEW.json\n") }
	if err := fs.Parse(args); err != nil || fs.NArg() != 2 {
		fs.Usage()
		return 1
	}
	old, err := audit.Load(fs.Arg(0))
	if err != nil {
		return fail(err)
	}
	cur, err := audit.Load(fs.Arg(1))
	if err != nil {
		return fail(err)
	}
	diffs := audit.Compare(old, cur)
	audit.WriteDiff(os.Stdout, diffs)
	if audit.Changed(diffs) {
		return 4
	}
	return 0
}
