package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaultsWhenNothingIsSet(t *testing.T) {
	t.Chdir(t.TempDir()) // no ./eimer.toml here
	c, err := loadConfig("", envFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, defaults()) {
		t.Fatalf("got %+v", c)
	}
}

func TestFileThenEnvPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eimer.toml")
	if err := os.WriteFile(path, []byte(`
endpoint = "https://file.example"
region = "eu-file-1"
access_key = "filekey"
buckets = ["a", "b"]
sample = 5
insecure = true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(path, envFrom(map[string]string{
		"EIMER_REGION":  "eu-env-1",
		"EIMER_BUCKETS": "x, y,,z",
		"EIMER_JSON":    "true",
		"EIMER_SAMPLE":  "7",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Endpoint: "https://file.example", Region: "eu-env-1", AccessKey: "filekey",
		Buckets: []string{"x", "y", "z"}, Sample: 7, ListMax: 200, Parallel: 8, Insecure: true, JSON: true, Timeout: 30,
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("got %+v\nwant %+v", c, want)
	}
}

func TestCredentialEnvFallbackOrder(t *testing.T) {
	t.Chdir(t.TempDir())
	c, err := loadConfig("", envFrom(map[string]string{
		"AWS_ACCESS_KEY_ID":   "aws",
		"MINIO_ROOT_USER":     "minio",
		"MINIO_SECRET_KEY":    "miniosecret",
		"AWS_DEFAULT_REGION":  "eu-aws-1",
		"MINIO_ROOT_PASSWORD": "ignored",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKey != "aws" || c.SecretKey != "miniosecret" || c.Region != "eu-aws-1" {
		t.Fatalf("got %+v", c)
	}
}

func TestBadEnvValuesAreReported(t *testing.T) {
	t.Chdir(t.TempDir())
	_, err := loadConfig("", envFrom(map[string]string{"EIMER_SAMPLE": "many", "EIMER_INSECURE": "yes please"}))
	if err == nil || !strings.Contains(err.Error(), "EIMER_SAMPLE") || !strings.Contains(err.Error(), "EIMER_INSECURE") {
		t.Fatalf("got %v", err)
	}
}

func TestExplicitMissingFileIsAnError(t *testing.T) {
	if _, err := loadConfig(filepath.Join(t.TempDir(), "nope.toml"), envFrom(nil)); err == nil {
		t.Fatal("expected error")
	}
}

func TestConfigPathFromArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--config", "a.toml", "--json"}, "a.toml"},
		{[]string{"-config=b.toml"}, "b.toml"},
		{[]string{"--endpoint", "x"}, ""},
	} {
		if got := configPathFromArgs(tc.args); got != tc.want {
			t.Errorf("%v: got %q want %q", tc.args, got, tc.want)
		}
	}
}

func TestExampleConfigParses(t *testing.T) {
	c, err := loadConfig("../../eimer.example.toml", envFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint == "" || c.Sample != 20 || c.Parallel != 8 {
		t.Fatalf("example config should carry the documented defaults, got %+v", c)
	}
}

func TestEstateTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eimer.toml")
	if err := os.WriteFile(path, []byte(`
region = "eu-global-1"
access_key = "topkey"
secret_key = "topsecret"

[[estate]]
name = "lab"
endpoint = "http://10.0.0.11:9000"
region = "eu-lab-1"
access_key_env = "LAB_KEY"
secret_key_env = "LAB_SECRET"

[[estate]]
endpoint = "https://rustfs.example"
insecure = true
buckets = ["a"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(path, envFrom(map[string]string{"LAB_KEY": "wk", "LAB_SECRET": "ws"}))
	if err != nil {
		t.Fatal(err)
	}
	ts := c.targets(envFrom(map[string]string{"LAB_KEY": "wk", "LAB_SECRET": "ws"}))
	if len(ts) != 2 {
		t.Fatalf("targets: %+v", ts)
	}
	w, r := ts[0], ts[1]
	if w.Name != "lab" || w.Region != "eu-lab-1" || w.AccessKey != "wk" || w.SecretKey != "ws" || *w.Insecure {
		t.Errorf("lab: %+v", w)
	}
	if r.Name != "https://rustfs.example" || r.Region != "eu-global-1" || r.AccessKey != "topkey" || !*r.Insecure || len(r.Buckets) != 1 {
		t.Errorf("rustfs: %+v", r)
	}
	single := defaults()
	single.Endpoint = "http://one"
	if ts := single.targets(envFrom(nil)); len(ts) != 1 || ts[0].Endpoint != "http://one" || ts[0].Name != "" {
		t.Errorf("single: %+v", ts)
	}
}

func TestLoadEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("# keys\nexport MINIO_ACCESSKEY=ak\nMINIO_SECRETKEY='s k'\nMINIO_REGION=\"eu-x-1\"\nbroken line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	getenv, err := loadEnvFile(path, envFrom(map[string]string{"MINIO_REGION": "from-env", "OTHER": "o"}))
	if err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig("", getenv)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKey != "ak" || c.SecretKey != "s k" || c.Region != "eu-x-1" || getenv("OTHER") != "o" {
		t.Fatalf("got %+v", c)
	}
	if _, err := loadEnvFile(filepath.Join(t.TempDir(), "missing"), envFrom(nil)); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestPreScan(t *testing.T) {
	if got := preScan([]string{"--env-file", "x.env", "-v"}, "env-file", "EIMER_ENV_FILE"); got != "x.env" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("EIMER_ENV_FILE", "from-env")
	if got := preScan([]string{"-v"}, "env-file", "EIMER_ENV_FILE"); got != "from-env" {
		t.Fatalf("got %q", got)
	}
}
