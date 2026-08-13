// Copyright 2022 Su Yang
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// --- CSV helpers ---

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "empty", input: "", want: nil},
		{name: "single", input: "download.docker.com", want: []string{"download.docker.com"}},
		{name: "multiple", input: "a.example.com,b.example.com", want: []string{"a.example.com", "b.example.com"}},
		{name: "trims whitespace", input: " a.example.com , b.example.com ", want: []string{"a.example.com", "b.example.com"}},
		{name: "drops blank entries", input: "a.example.com,,b.example.com,", want: []string{"a.example.com", "b.example.com"}},
		{name: "only separators", input: ",,,", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitCSV(tt.input); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("splitCSV(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParsePortCSV(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{name: "empty", input: "", want: nil},
		{name: "single", input: "443", want: []int{443}},
		{name: "multiple", input: "443,8443", want: []int{443, 8443}},
		{name: "trims whitespace", input: " 443 , 8443 ", want: []int{443, 8443}},
		{name: "ignores blank entries", input: "443,,8443,", want: []int{443, 8443}},

		// A bad entry is an error rather than a silent drop: dropping it
		// would quietly narrow which repositories are reachable.
		{name: "non numeric", input: "443,https", wantErr: true},
		{name: "port zero", input: "0", wantErr: true},
		{name: "port too high", input: "65536", wantErr: true},
		{name: "negative", input: "-1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePortCSV(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parsePortCSV(%q) = %#v, want an error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePortCSV(%q) unexpected error: %v", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parsePortCSV(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildCLIConfigRejectsBadPortList(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	defineFlags(flags)
	if err := flags.Parse([]string{"-connect-ports=443,ssh"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	if _, _, err := buildCLIConfig(flags, DefaultHost, DefaultPort, DefaultCacheDir, 0, 0, 0); err == nil {
		t.Fatal("buildCLIConfig accepted a malformed port list; a typo must not silently narrow the allowlist")
	}
}

// --- validation ---

func TestValidateConnect(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ConnectConfig
		wantErr bool
	}{
		{
			name: "disabled skips all checks",
			cfg:  ConnectConfig{Enabled: false, AllowedPorts: []int{0}, AllowedHosts: []string{"*"}},
		},
		{
			name: "enabled with empty allowlist is valid deny-all",
			cfg:  ConnectConfig{Enabled: true},
		},
		{
			name: "valid hosts and ports",
			cfg: ConnectConfig{
				Enabled:      true,
				AllowedHosts: []string{"download.docker.com", "*.saltproject.io"},
				AllowedPorts: []int{443, 8443},
			},
		},
		{
			name:    "port too low",
			cfg:     ConnectConfig{Enabled: true, AllowedPorts: []int{0}},
			wantErr: true,
		},
		{
			name:    "port too high",
			cfg:     ConnectConfig{Enabled: true, AllowedPorts: []int{65536}},
			wantErr: true,
		},
		{
			name:    "blank host entry",
			cfg:     ConnectConfig{Enabled: true, AllowedHosts: []string{"  "}},
			wantErr: true,
		},
		{
			// The matcher trims, so the validator must too, or a space
			// installs the pattern the guard exists to reject.
			name:    "whitespace does not slip a wildcard past the guard",
			cfg:     ConnectConfig{Enabled: true, AllowedHosts: []string{" *.com"}},
			wantErr: true,
		},
		{
			name:    "bare wildcard is refused",
			cfg:     ConnectConfig{Enabled: true, AllowedHosts: []string{"*"}},
			wantErr: true,
		},
		{
			name:    "malformed wildcard is refused",
			cfg:     ConnectConfig{Enabled: true, AllowedHosts: []string{"*docker.com"}},
			wantErr: true,
		},
		{
			name:    "wildcard covering a whole TLD",
			cfg:     ConnectConfig{Enabled: true, AllowedHosts: []string{"*.com"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConnect(&tt.cfg)
			if tt.wantErr && err == nil {
				t.Fatal("validateConnect() = nil, want an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateConnect() = %v, want nil", err)
			}
		})
	}
}

func TestValidateConfigRejectsOpenRelay(t *testing.T) {
	cfg := &Config{
		Listen:   "0.0.0.0:3142",
		CacheDir: t.TempDir(),
		Connect:  ConnectConfig{Enabled: true, AllowedHosts: []string{"*"}},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("ValidateConfig accepted a bare \"*\" allowlist; that is an open relay")
	}
}

// --- YAML ---

func TestConnectFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apt-proxy.yaml")
	content := `
connect:
  enabled: true
  allowed_hosts:
    - download.docker.com
    - "*.saltproject.io"
  allowed_ports:
    - 443
    - 8443
  max_concurrent: 32
  idle_timeout_sec: 30
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}

	if !cfg.Connect.Enabled {
		t.Error("Connect.Enabled = false, want true")
	}
	wantHosts := []string{"download.docker.com", "*.saltproject.io"}
	if !reflect.DeepEqual(cfg.Connect.AllowedHosts, wantHosts) {
		t.Errorf("AllowedHosts = %#v, want %#v", cfg.Connect.AllowedHosts, wantHosts)
	}
	wantPorts := []int{443, 8443}
	if !reflect.DeepEqual(cfg.Connect.AllowedPorts, wantPorts) {
		t.Errorf("AllowedPorts = %#v, want %#v", cfg.Connect.AllowedPorts, wantPorts)
	}
	if cfg.Connect.MaxConcurrent != 32 {
		t.Errorf("MaxConcurrent = %d, want 32", cfg.Connect.MaxConcurrent)
	}
	if cfg.Connect.IdleTimeout != 30*time.Second {
		t.Errorf("IdleTimeout = %v, want 30s", cfg.Connect.IdleTimeout)
	}
}

func TestConnectYAMLDefaultsToDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apt-proxy.yaml")
	if err := os.WriteFile(path, []byte("server:\n  port: \"3142\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if cfg.Connect.Enabled {
		t.Error("Connect.Enabled = true for a config with no connect section, want false")
	}
	if len(cfg.Connect.AllowedHosts) != 0 {
		t.Errorf("AllowedHosts = %#v, want empty (deny all)", cfg.Connect.AllowedHosts)
	}
}

func TestConnectYAMLExplicitFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apt-proxy.yaml")
	if err := os.WriteFile(path, []byte("connect:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if cfg.Connect.Enabled {
		t.Error("Connect.Enabled = true, want false")
	}
}

// --- defaults ---

func TestApplyDefaultsConnect(t *testing.T) {
	cfg := applyDefaults(&Config{})

	if cfg.Connect.Enabled {
		t.Error("Connect.Enabled = true by default; tunnelling must be opt-in")
	}
	if len(cfg.Connect.AllowedHosts) != 0 {
		t.Error("a default allowlist was populated; the default must be deny-all")
	}
	if cfg.Connect.MaxConcurrent != DefaultConnectMaxConcurrent {
		t.Errorf("MaxConcurrent = %d, want %d", cfg.Connect.MaxConcurrent, DefaultConnectMaxConcurrent)
	}
	if cfg.Connect.IdleTimeout != time.Duration(DefaultConnectIdleTimeoutSec)*time.Second {
		t.Errorf("IdleTimeout = %v, want %ds", cfg.Connect.IdleTimeout, DefaultConnectIdleTimeoutSec)
	}
}

// An explicit zero must survive as "off" all the way to the tunnel package,
// which reads a zero as "apply the built-in default". Driven through the real
// flag path, because that is where the translation happens.
func TestConnectLimitsOffViaFlags(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	defineFlags(flags)
	if err := flags.Parse([]string{"-connect", "-connect-max-concurrent=0", "-connect-idle-timeout=0"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	cliCfg, ex, err := buildCLIConfig(flags, DefaultHost, DefaultPort, DefaultCacheDir, 0, 0, 0)
	if err != nil {
		t.Fatalf("buildCLIConfig: %v", err)
	}
	cfg := applyDefaultsWithExplicit(cliCfg, ex)

	if cfg.Connect.MaxConcurrent >= 0 {
		t.Errorf("MaxConcurrent = %d, want a negative value so the tunnel treats it as unlimited", cfg.Connect.MaxConcurrent)
	}
	if cfg.Connect.IdleTimeout >= 0 {
		t.Errorf("IdleTimeout = %v, want a negative duration so the tunnel treats it as disabled", cfg.Connect.IdleTimeout)
	}
}

// Both CONNECT limits use 0 for "off" at every input boundary, and both must
// arrive at the tunnel as a value it does not mistake for "unset".
func TestConnectOffSentinel(t *testing.T) {
	if got := connectOff(0); got >= 0 {
		t.Errorf("connectOff(0) = %d, want negative", got)
	}
	for _, v := range []int{1, 256, -1} {
		if got := connectOff(v); got != v {
			t.Errorf("connectOff(%d) = %d, want %d", v, got, v)
		}
	}
}

func TestConnectLimitsOffViaYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apt-proxy.yaml")
	body := "connect:\n  enabled: true\n  max_concurrent: 0\n  idle_timeout_sec: 0\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fileCfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	cfg := applyDefaultsWithExplicit(fileCfg, &cliExplicit{})

	if cfg.Connect.MaxConcurrent >= 0 {
		t.Errorf("MaxConcurrent = %d, want negative; YAML 0 must disable the cap like the flag does", cfg.Connect.MaxConcurrent)
	}
	if cfg.Connect.IdleTimeout >= 0 {
		t.Errorf("IdleTimeout = %v, want negative; YAML 0 must disable reaping like the flag does", cfg.Connect.IdleTimeout)
	}
}

func TestConnectLimitsDefaultWhenAbsentFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apt-proxy.yaml")
	if err := os.WriteFile(path, []byte("connect:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fileCfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	cfg := applyDefaultsWithExplicit(fileCfg, &cliExplicit{})

	if cfg.Connect.MaxConcurrent != DefaultConnectMaxConcurrent {
		t.Errorf("MaxConcurrent = %d, want the default %d", cfg.Connect.MaxConcurrent, DefaultConnectMaxConcurrent)
	}
	if cfg.Connect.IdleTimeoutSec != DefaultConnectIdleTimeoutSec {
		t.Errorf("IdleTimeoutSec = %d, want the default %d", cfg.Connect.IdleTimeoutSec, DefaultConnectIdleTimeoutSec)
	}
}

func TestConnectIdleDuration(t *testing.T) {
	if got := connectIdleDuration(30); got != 30*time.Second {
		t.Errorf("connectIdleDuration(30) = %v, want 30s", got)
	}
	// Negative is the resolved "disabled" sentinel that connectOff produces.
	if got := connectIdleDuration(-1); got >= 0 {
		t.Errorf("connectIdleDuration(-1) = %v, want a negative duration", got)
	}
}

// --- merging ---

func TestMergeConfigsWithExplicitConnect(t *testing.T) {
	base := &Config{Connect: ConnectConfig{
		Enabled:        true,
		AllowedHosts:   []string{"base.example.com"},
		AllowedPorts:   []int{443},
		MaxConcurrent:  10,
		IdleTimeoutSec: 90,
	}}
	override := &Config{Connect: ConnectConfig{
		Enabled:        false,
		AllowedHosts:   []string{"override.example.com"},
		AllowedPorts:   []int{8443},
		MaxConcurrent:  20,
		IdleTimeoutSec: 30,
		IdleTimeout:    30 * time.Second,
	}}

	t.Run("explicit false disables", func(t *testing.T) {
		got := MergeConfigsWithExplicit(base, override, &cliExplicit{ConnectEnabled: true})
		if got.Connect.Enabled {
			t.Error("an explicit --connect=false must override an enabled file config")
		}
	})

	t.Run("unset leaves base alone", func(t *testing.T) {
		got := MergeConfigsWithExplicit(base, override, &cliExplicit{})
		if !got.Connect.Enabled {
			t.Error("base Enabled=true was dropped despite no explicit override")
		}
		if !reflect.DeepEqual(got.Connect.AllowedHosts, []string{"base.example.com"}) {
			t.Errorf("AllowedHosts = %#v, want the base list", got.Connect.AllowedHosts)
		}
	})

	t.Run("explicit values win", func(t *testing.T) {
		got := MergeConfigsWithExplicit(base, override, &cliExplicit{
			ConnectAllowedHosts:  true,
			ConnectAllowedPorts:  true,
			ConnectMaxConcurrent: true,
			ConnectIdleTimeout:   true,
		})
		if !reflect.DeepEqual(got.Connect.AllowedHosts, []string{"override.example.com"}) {
			t.Errorf("AllowedHosts = %#v, want the override list", got.Connect.AllowedHosts)
		}
		if !reflect.DeepEqual(got.Connect.AllowedPorts, []int{8443}) {
			t.Errorf("AllowedPorts = %#v, want [8443]", got.Connect.AllowedPorts)
		}
		if got.Connect.MaxConcurrent != 20 {
			t.Errorf("MaxConcurrent = %d, want 20", got.Connect.MaxConcurrent)
		}
		if got.Connect.IdleTimeout != 30*time.Second {
			t.Errorf("IdleTimeout = %v, want 30s", got.Connect.IdleTimeout)
		}
	})

	t.Run("allowlist is copied not aliased", func(t *testing.T) {
		got := MergeConfigsWithExplicit(base, override, &cliExplicit{ConnectAllowedHosts: true})
		got.Connect.AllowedHosts[0] = "mutated.example.com"
		if override.Connect.AllowedHosts[0] != "override.example.com" {
			t.Error("merge aliased the override slice; a later mutation corrupted it")
		}
	})
}

func TestMergeConfigsConnect(t *testing.T) {
	base := &Config{Connect: ConnectConfig{
		Enabled:      false,
		AllowedHosts: []string{"base.example.com"},
	}}
	override := &Config{Connect: ConnectConfig{
		Enabled:        true,
		AllowedHosts:   []string{"override.example.com"},
		AllowedPorts:   []int{8443},
		MaxConcurrent:  20,
		IdleTimeoutSec: 30,
		IdleTimeout:    30 * time.Second,
	}}

	got := MergeConfigs(base, override)

	if !got.Connect.Enabled {
		t.Error("Enabled = false, want true from the override")
	}
	if !reflect.DeepEqual(got.Connect.AllowedHosts, []string{"override.example.com"}) {
		t.Errorf("AllowedHosts = %#v, want the override list", got.Connect.AllowedHosts)
	}
	if !reflect.DeepEqual(got.Connect.AllowedPorts, []int{8443}) {
		t.Errorf("AllowedPorts = %#v, want [8443]", got.Connect.AllowedPorts)
	}
	if got.Connect.MaxConcurrent != 20 {
		t.Errorf("MaxConcurrent = %d, want 20", got.Connect.MaxConcurrent)
	}
	if got.Connect.IdleTimeout != 30*time.Second {
		t.Errorf("IdleTimeout = %v, want 30s", got.Connect.IdleTimeout)
	}
}

func TestMergeConfigsConnectKeepsBaseWhenOverrideEmpty(t *testing.T) {
	base := &Config{Connect: ConnectConfig{
		Enabled:      true,
		AllowedHosts: []string{"base.example.com"},
		AllowedPorts: []int{443},
	}}

	got := MergeConfigs(base, &Config{})

	if !got.Connect.Enabled {
		t.Error("an empty override disabled the base config")
	}
	if !reflect.DeepEqual(got.Connect.AllowedHosts, []string{"base.example.com"}) {
		t.Errorf("AllowedHosts = %#v, want the base list", got.Connect.AllowedHosts)
	}
}

// --- CLI / ENV ---

func TestBuildCLIConfigConnectFlags(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	defineFlags(flags)
	if err := flags.Parse([]string{
		"-connect",
		"-connect-allow=download.docker.com, *.saltproject.io ,",
		"-connect-ports=443,8443",
		"-connect-max-concurrent=64",
		"-connect-idle-timeout=45",
	}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	cfg, ex, err := buildCLIConfig(flags, DefaultHost, DefaultPort, DefaultCacheDir, 0, 0, 0)
	if err != nil {
		t.Fatalf("buildCLIConfig: %v", err)
	}

	if !cfg.Connect.Enabled {
		t.Error("Connect.Enabled = false, want true")
	}
	wantHosts := []string{"download.docker.com", "*.saltproject.io"}
	if !reflect.DeepEqual(cfg.Connect.AllowedHosts, wantHosts) {
		t.Errorf("AllowedHosts = %#v, want %#v", cfg.Connect.AllowedHosts, wantHosts)
	}
	if !reflect.DeepEqual(cfg.Connect.AllowedPorts, []int{443, 8443}) {
		t.Errorf("AllowedPorts = %#v, want [443 8443]", cfg.Connect.AllowedPorts)
	}
	if cfg.Connect.MaxConcurrent != 64 {
		t.Errorf("MaxConcurrent = %d, want 64", cfg.Connect.MaxConcurrent)
	}
	if cfg.Connect.IdleTimeout != 45*time.Second {
		t.Errorf("IdleTimeout = %v, want 45s", cfg.Connect.IdleTimeout)
	}

	for name, set := range map[string]bool{
		"ConnectEnabled":       ex.ConnectEnabled,
		"ConnectAllowedHosts":  ex.ConnectAllowedHosts,
		"ConnectAllowedPorts":  ex.ConnectAllowedPorts,
		"ConnectMaxConcurrent": ex.ConnectMaxConcurrent,
		"ConnectIdleTimeout":   ex.ConnectIdleTimeout,
	} {
		if !set {
			t.Errorf("explicit mask %s = false, want true", name)
		}
	}
}

func TestBuildCLIConfigConnectFromEnv(t *testing.T) {
	t.Setenv(EnvConnectEnabled, "true")
	t.Setenv(EnvConnectAllowedHosts, "apt.shq.nz")
	t.Setenv(EnvConnectAllowedPorts, "443")
	t.Setenv(EnvConnectMaxConcurrent, "8")

	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	defineFlags(flags)
	if err := flags.Parse(nil); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	cfg, ex, err := buildCLIConfig(flags, DefaultHost, DefaultPort, DefaultCacheDir, 0, 0, 0)
	if err != nil {
		t.Fatalf("buildCLIConfig: %v", err)
	}

	if !cfg.Connect.Enabled {
		t.Error("Connect.Enabled = false, want true from ENV")
	}
	if !reflect.DeepEqual(cfg.Connect.AllowedHosts, []string{"apt.shq.nz"}) {
		t.Errorf("AllowedHosts = %#v, want [apt.shq.nz]", cfg.Connect.AllowedHosts)
	}
	if cfg.Connect.MaxConcurrent != 8 {
		t.Errorf("MaxConcurrent = %d, want 8", cfg.Connect.MaxConcurrent)
	}
	if !ex.ConnectEnabled || !ex.ConnectAllowedHosts {
		t.Error("ENV-supplied values must set the explicit mask")
	}
}

func TestBuildCLIConfigConnectDefaults(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	defineFlags(flags)
	if err := flags.Parse(nil); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	cfg, ex, err := buildCLIConfig(flags, DefaultHost, DefaultPort, DefaultCacheDir, 0, 0, 0)
	if err != nil {
		t.Fatalf("buildCLIConfig: %v", err)
	}

	if cfg.Connect.Enabled {
		t.Error("Connect.Enabled = true with no flags; tunnelling must be opt-in")
	}
	if len(cfg.Connect.AllowedHosts) != 0 {
		t.Errorf("AllowedHosts = %#v, want empty (deny all)", cfg.Connect.AllowedHosts)
	}
	if ex.ConnectEnabled {
		t.Error("explicit mask set without a flag or ENV value")
	}
}
