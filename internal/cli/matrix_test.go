package cli

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soulteary/apt-proxy/internal/config"
	"github.com/soulteary/apt-proxy/internal/tunnel"
)

// Every input path for both CONNECT limits, asserted at the value the
// Tunneler actually uses. Two blockers so far were a sentinel translated on
// one path and not another; this closes the class rather than the instance.
func TestConnectLimitsAcrossEveryInputPath(t *testing.T) {
	const (
		defaultMax  = 256
		defaultIdle = 120 * time.Second
	)

	tests := []struct {
		name     string
		args     []string
		env      map[string]string
		yaml     string
		wantMax  int   // -1 means "expect unlimited"
		wantIdle int64 // -1 means "expect disabled", else nanoseconds
	}{
		{name: "nothing set", wantMax: defaultMax, wantIdle: int64(defaultIdle)},

		{name: "CLI zero", args: []string{"-connect-max-concurrent=0", "-connect-idle-timeout=0"}, wantMax: -1, wantIdle: -1},
		{name: "CLI value", args: []string{"-connect-max-concurrent=7", "-connect-idle-timeout=30"}, wantMax: 7, wantIdle: int64(30 * time.Second)},

		{name: "ENV zero", env: map[string]string{"APT_PROXY_CONNECT_MAX_CONCURRENT": "0", "APT_PROXY_CONNECT_IDLE_TIMEOUT": "0"}, wantMax: -1, wantIdle: -1},
		{name: "ENV value", env: map[string]string{"APT_PROXY_CONNECT_MAX_CONCURRENT": "9", "APT_PROXY_CONNECT_IDLE_TIMEOUT": "45"}, wantMax: 9, wantIdle: int64(45 * time.Second)},

		{name: "YAML zero", yaml: "connect:\n  enabled: true\n  max_concurrent: 0\n  idle_timeout_sec: 0\n", wantMax: -1, wantIdle: -1},
		{name: "YAML value", yaml: "connect:\n  enabled: true\n  max_concurrent: 5\n  idle_timeout_sec: 15\n", wantMax: 5, wantIdle: int64(15 * time.Second)},
		{name: "YAML absent", yaml: "connect:\n  enabled: true\n", wantMax: defaultMax, wantIdle: int64(defaultIdle)},

		{name: "CLI zero overrides YAML value", args: []string{"-connect-max-concurrent=0", "-connect-idle-timeout=0"},
			yaml: "connect:\n  enabled: true\n  max_concurrent: 5\n  idle_timeout_sec: 15\n", wantMax: -1, wantIdle: -1},
		{name: "CLI value overrides YAML zero", args: []string{"-connect-max-concurrent=3", "-connect-idle-timeout=9"},
			yaml: "connect:\n  enabled: true\n  max_concurrent: 0\n  idle_timeout_sec: 0\n", wantMax: 3, wantIdle: int64(9 * time.Second)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Neutralise any config the developer actually runs with:
			// rows without an explicit -config otherwise pick one up
			// through FindConfigFile and assert against it.
			t.Setenv("APT_PROXY_CONFIG_FILE", "")
			t.Setenv("HOME", t.TempDir())

			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			args := tt.args
			if tt.yaml != "" {
				path := filepath.Join(t.TempDir(), "apt-proxy.yaml")
				if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
					t.Fatalf("write yaml: %v", err)
				}
				args = append(append([]string{}, args...), "-config="+path)
			}

			origArgs, origFlags := os.Args, flag.CommandLine
			t.Cleanup(func() { os.Args, flag.CommandLine = origArgs, origFlags })
			os.Args = append([]string{"apt-proxy"}, args...)
			flag.CommandLine = flag.NewFlagSet("apt-proxy", flag.ContinueOnError)
			cfg, err := config.ParseFlagsWithConfigFile()
			if err != nil {
				t.Fatalf("ParseFlagsWithConfigFile: %v", err)
			}

			tn := tunnel.New(tunnel.Config{
				Enabled:       true,
				MaxConcurrent: cfg.Connect.MaxConcurrent,
				IdleTimeout:   cfg.Connect.IdleTimeout,
			}, nil)

			// Probe the cap through behaviour, not the field.
			granted := 0
			for i := 0; i < defaultMax+20; i++ {
				if _, ok := tn.Acquire(); ok {
					granted++
				}
			}
			wantGranted := tt.wantMax
			if tt.wantMax == -1 {
				wantGranted = defaultMax + 20
			}
			if granted != wantGranted {
				t.Errorf("cap: granted %d, want %d (config MaxConcurrent=%d)", granted, wantGranted, cfg.Connect.MaxConcurrent)
			}

			gotIdle := tn.IdleTimeout()
			if tt.wantIdle == -1 {
				if gotIdle >= 0 {
					t.Errorf("idle: %v, want disabled (config IdleTimeout=%v)", gotIdle, cfg.Connect.IdleTimeout)
				}
			} else if int64(gotIdle) != tt.wantIdle {
				t.Errorf("idle: %v, want %v", gotIdle, time.Duration(tt.wantIdle))
			}
		})
	}
}
