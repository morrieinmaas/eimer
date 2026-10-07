package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is every setting the audit command accepts. Precedence, highest first:
// command-line flags, EIMER_* environment variables, the TOML file, defaults.
type Config struct {
	Endpoint  string   `toml:"endpoint"`
	Via       string   `toml:"via"`
	Region    string   `toml:"region"`
	AccessKey string   `toml:"access_key"`
	SecretKey string   `toml:"secret_key"`
	Buckets   []string `toml:"buckets"`
	Sample    int      `toml:"sample"`
	ListMax   int      `toml:"list_max"`
	Parallel  int      `toml:"parallel"`
	Insecure  bool     `toml:"insecure"`
	JSON      bool     `toml:"json"`
	Out       string   `toml:"out"`
	Timeout   int      `toml:"timeout"` // seconds per S3 call
	Verbose   bool     `toml:"verbose"`
	EnvFile   string   `toml:"env_file"`
	Estates   []Estate `toml:"estate"`
}

// Estate is one endpoint in a multi-endpoint config. Unset fields inherit the
// top-level values. Credentials can name environment variables instead of
// carrying secrets in the file.
type Estate struct {
	Name         string   `toml:"name"`
	Endpoint     string   `toml:"endpoint"`
	Via          string   `toml:"via"`
	Region       string   `toml:"region"`
	AccessKey    string   `toml:"access_key"`
	SecretKey    string   `toml:"secret_key"`
	AccessKeyEnv string   `toml:"access_key_env"`
	SecretKeyEnv string   `toml:"secret_key_env"`
	Buckets      []string `toml:"buckets"`
	Insecure     *bool    `toml:"insecure"`
}

// targets expands the config into the endpoints to audit: the estate list when
// present, else the single top-level endpoint.
func (c Config) targets(getenv func(string) string) []Estate {
	if len(c.Estates) == 0 {
		return []Estate{{Endpoint: c.Endpoint, Via: c.Via, Region: c.Region, AccessKey: c.AccessKey, SecretKey: c.SecretKey, Buckets: c.Buckets, Insecure: &c.Insecure}}
	}
	out := make([]Estate, 0, len(c.Estates))
	for _, e := range c.Estates {
		if e.AccessKeyEnv != "" {
			e.AccessKey = getenv(e.AccessKeyEnv)
		}
		if e.SecretKeyEnv != "" {
			e.SecretKey = getenv(e.SecretKeyEnv)
		}
		if e.Region == "" {
			e.Region = c.Region
		}
		if e.Via == "" {
			e.Via = c.Via
		}
		if e.AccessKey == "" && e.SecretKey == "" {
			e.AccessKey, e.SecretKey = c.AccessKey, c.SecretKey
		}
		if e.Insecure == nil {
			v := c.Insecure
			e.Insecure = &v
		}
		if e.Name == "" {
			e.Name = e.Endpoint
		}
		out = append(out, e)
	}
	return out
}

func defaults() Config {
	return Config{Region: "us-east-1", Sample: 20, ListMax: 200, Parallel: 8, Timeout: 30}
}

// envNames maps each setting to the environment variables consulted, first match wins.
// The AWS and MinIO names are there so credentials already in a shell just work.
var envNames = map[string][]string{
	"endpoint":   {"EIMER_ENDPOINT", "MINIO_URL", "MINIO_ENDPOINT", "S3_ENDPOINT", "AWS_ENDPOINT_URL"},
	"via":        {"EIMER_VIA"},
	"region":     {"EIMER_REGION", "AWS_REGION", "AWS_DEFAULT_REGION", "MINIO_REGION"},
	"access_key": {"EIMER_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "MINIO_ACCESS_KEY", "MINIO_ACCESSKEY", "MINIO_ROOT_USER"},
	"secret_key": {"EIMER_SECRET_KEY", "AWS_SECRET_ACCESS_KEY", "MINIO_SECRET_KEY", "MINIO_SECRETKEY", "MINIO_ROOT_PASSWORD"},
	"buckets":    {"EIMER_BUCKETS"},
	"sample":     {"EIMER_SAMPLE"},
	"list_max":   {"EIMER_LIST_MAX"},
	"parallel":   {"EIMER_PARALLEL"},
	"insecure":   {"EIMER_INSECURE"},
	"json":       {"EIMER_JSON"},
	"out":        {"EIMER_OUT"},
	"timeout":    {"EIMER_TIMEOUT"},
	"verbose":    {"EIMER_VERBOSE"},
}

// loadEnvFile parses KEY=VALUE lines (dotenv style: comments, blank lines, optional
// "export ", single or double quotes) and returns a getenv that prefers the file.
func loadEnvFile(path string, getenv func(string) string) (func(string) string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	vars := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		vars[strings.TrimSpace(k)] = v
	}
	return func(key string) string {
		if v, ok := vars[key]; ok {
			return v
		}
		return getenv(key)
	}, nil
}

// defaultConfigPaths are tried in order when --config is not given. A missing file is fine.
func defaultConfigPaths() []string {
	paths := []string{"eimer.toml"}
	if dir, err := os.UserConfigDir(); err == nil {
		paths = append(paths, filepath.Join(dir, "eimer", "config.toml"))
	}
	return paths
}

// loadConfig builds the pre-flag configuration: defaults, then the TOML file, then env.
// path "" means "first default path that exists"; an explicit path must exist.
func loadConfig(path string, getenv func(string) string) (Config, error) {
	c := defaults()
	if path == "" {
		for _, p := range defaultConfigPaths() {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	if path != "" {
		if _, err := toml.DecodeFile(path, &c); err != nil {
			return c, fmt.Errorf("config %s: %w", path, err)
		}
	}
	return c, applyEnv(&c, getenv)
}

func applyEnv(c *Config, getenv func(string) string) error {
	lookup := func(key string) (string, bool) {
		for _, name := range envNames[key] {
			if v := getenv(name); v != "" {
				return v, true
			}
		}
		return "", false
	}
	var errs []error
	setInt := func(key string, dst *int) {
		if v, ok := lookup(key); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %q is not a number", envNames[key][0], v))
				return
			}
			*dst = n
		}
	}
	setBool := func(key string, dst *bool) {
		if v, ok := lookup(key); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %q is not a boolean", envNames[key][0], v))
				return
			}
			*dst = b
		}
	}
	if v, ok := lookup("endpoint"); ok {
		c.Endpoint = v
	}
	if v, ok := lookup("via"); ok {
		c.Via = v
	}
	if v, ok := lookup("region"); ok {
		c.Region = v
	}
	if v, ok := lookup("access_key"); ok {
		c.AccessKey = v
	}
	if v, ok := lookup("secret_key"); ok {
		c.SecretKey = v
	}
	if v, ok := lookup("buckets"); ok {
		c.Buckets = splitList(v)
	}
	if v, ok := lookup("out"); ok {
		c.Out = v
	}
	setInt("timeout", &c.Timeout)
	setBool("verbose", &c.Verbose)
	setInt("sample", &c.Sample)
	setInt("list_max", &c.ListMax)
	setInt("parallel", &c.Parallel)
	setBool("insecure", &c.Insecure)
	setBool("json", &c.JSON)
	return errors.Join(errs...)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
