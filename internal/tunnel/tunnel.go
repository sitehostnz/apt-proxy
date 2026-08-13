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

// Package tunnel implements HTTP CONNECT tunnelling so apt can reach
// repositories published only over HTTPS.
//
// When apt is pointed at a proxy and a source uses https://, it sends
// "CONNECT host:443" and expects a raw TCP tunnel, after which apt and the
// origin perform their own TLS handshake. The relayed bytes are ciphertext,
// so a tunnelled repository can be reached but never cached.
//
// A CONNECT proxy that accepts arbitrary destinations is an open relay, so
// tunnelling is disabled by default and denies anything not allowlisted.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Errors returned by Authorize and Acquire. Callers map these onto HTTP
// status codes with StatusFor.
var (
	ErrDisabled       = errors.New("tunnel: CONNECT support is disabled")
	ErrHostNotAllowed = errors.New("tunnel: destination host is not allowed")
	ErrPortNotAllowed = errors.New("tunnel: destination port is not allowed")

	// ErrInvalidTarget means the request-target was not usable authority-form.
	ErrInvalidTarget = errors.New("tunnel: invalid CONNECT target")

	// ErrTooManyTunnels is deliberate back-pressure: an unbounded tunnel
	// count is how a proxy runs itself out of file descriptors.
	ErrTooManyTunnels = errors.New("tunnel: concurrent tunnel limit reached")
)

// Defaults applied when the corresponding Config field is zero.
const (
	DefaultMaxConcurrent = 256
	DefaultDialTimeout   = 10 * time.Second
	DefaultIdleTimeout   = 120 * time.Second

	// maxTargetLen rejects absurd request-targets early. 263 is a
	// maximum-length DNS name (253) plus ":65535".
	maxTargetLen = 263

	defaultAllowedPort = 443
)

// Config controls CONNECT tunnelling behaviour. Zero selects the default for
// each field; MaxConcurrent and IdleTimeout additionally read a negative
// value as unlimited and disabled respectively.
type Config struct {
	Enabled bool

	// AllowedHosts is the destination allowlist. Entries are an exact
	// hostname ("download.docker.com") or a wildcard ("*.docker.com", which
	// matches subdomains but not the bare domain). Empty denies everything.
	AllowedHosts []string

	// AllowedPorts defaults to 443 only.
	AllowedPorts []int

	MaxConcurrent int
	DialTimeout   time.Duration

	// IdleTimeout tears down a tunnel that has carried no bytes in either
	// direction, so a stalled client cannot pin a file descriptor open.
	IdleTimeout time.Duration
}

// Dialer opens the upstream connection; it exists so tests can substitute a
// fake without touching the network.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Tunneler authorises and establishes CONNECT tunnels.
type Tunneler struct {
	enabled       bool
	hosts         *hostMatcher
	ports         map[int]struct{}
	maxConcurrent int
	dialTimeout   time.Duration
	idleTimeout   time.Duration
	dialer        Dialer

	active atomic.Int64
}

// New builds a Tunneler from cfg. A nil dialer falls back to a net.Dialer.
func New(cfg Config, dialer Dialer) *Tunneler {
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	ports := make(map[int]struct{}, len(cfg.AllowedPorts))
	for _, p := range cfg.AllowedPorts {
		ports[p] = struct{}{}
	}
	if len(ports) == 0 {
		ports[defaultAllowedPort] = struct{}{}
	}

	t := &Tunneler{
		enabled:       cfg.Enabled,
		hosts:         newHostMatcher(cfg.AllowedHosts),
		ports:         ports,
		maxConcurrent: cfg.MaxConcurrent,
		dialTimeout:   cfg.DialTimeout,
		idleTimeout:   cfg.IdleTimeout,
		dialer:        dialer,
	}
	if t.maxConcurrent == 0 {
		t.maxConcurrent = DefaultMaxConcurrent
	}
	if t.dialTimeout <= 0 {
		t.dialTimeout = DefaultDialTimeout
	}
	if t.idleTimeout == 0 {
		t.idleTimeout = DefaultIdleTimeout
	}
	return t
}

// IdleTimeout returns the configured inactivity timeout.
func (t *Tunneler) IdleTimeout() time.Duration { return t.idleTimeout }

// Active returns the number of currently open tunnels.
func (t *Tunneler) Active() int64 { return t.active.Load() }

// Authorize validates a CONNECT request-target against the allowlists and
// returns the canonical "host:port" to dial.
//
// rawTarget must be the verbatim authority-form request-target, never a
// routed path.
func (t *Tunneler) Authorize(rawTarget string) (string, error) {
	if !t.enabled {
		return "", ErrDisabled
	}

	host, port, err := parseTarget(rawTarget)
	if err != nil {
		return "", err
	}
	if !t.hosts.match(host) {
		return "", ErrHostNotAllowed
	}
	if _, ok := t.ports[port]; !ok {
		return "", ErrPortNotAllowed
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// Acquire reserves a tunnel slot. The returned release must be called
// exactly once; ok is false when the concurrency limit has been reached.
func (t *Tunneler) Acquire() (release func(), ok bool) {
	if n := t.active.Add(1); t.maxConcurrent > 0 && n > int64(t.maxConcurrent) {
		t.active.Add(-1)
		return func() {}, false
	}

	// once guards against a double release deflating the gauge, which would
	// eventually let the concurrency cap be exceeded.
	var once sync.Once
	return func() { once.Do(func() { t.active.Add(-1) }) }, true
}

// Dial opens the upstream connection for an authorised target.
func (t *Tunneler) Dial(ctx context.Context, target string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, t.dialTimeout)
	defer cancel()
	return t.dialer.DialContext(dialCtx, "tcp", target)
}

// StatusFor maps an Authorize/Acquire/Dial error onto the HTTP status the
// proxy should return.
func StatusFor(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrDisabled):
		return http.StatusMethodNotAllowed
	case errors.Is(err, ErrInvalidTarget):
		return http.StatusBadRequest
	case errors.Is(err, ErrHostNotAllowed), errors.Is(err, ErrPortNotAllowed):
		return http.StatusForbidden
	case errors.Is(err, ErrTooManyTunnels):
		return http.StatusServiceUnavailable
	case isTimeout(err):
		return http.StatusGatewayTimeout
	default:
		return http.StatusBadGateway
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// parseTarget splits an authority-form CONNECT target into host and port.
func parseTarget(rawTarget string) (host string, port int, err error) {
	target := strings.TrimSpace(rawTarget)
	if target == "" || len(target) > maxTargetLen {
		return "", 0, ErrInvalidTarget
	}

	hostPart, portPart, splitErr := net.SplitHostPort(target)
	if splitErr != nil || hostPart == "" {
		return "", 0, ErrInvalidTarget
	}

	portNum, convErr := strconv.Atoi(portPart)
	if convErr != nil || portNum < 1 || portNum > 65535 {
		return "", 0, ErrInvalidTarget
	}

	// Lowercase once, here, so the allowlist check and the dial both use the
	// same string and "DOCKER.COM" cannot bypass an entry.
	return strings.ToLower(hostPart), portNum, nil
}

// hostMatcher performs allowlist matching without regular expressions, so a
// hostile or careless pattern cannot cause catastrophic backtracking.
type hostMatcher struct {
	exact    map[string]struct{}
	suffixes []string
}

func newHostMatcher(patterns []string) *hostMatcher {
	m := &hostMatcher{exact: make(map[string]struct{}, len(patterns))}
	for _, raw := range patterns {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			m.suffixes = append(m.suffixes, p[1:])
			continue
		}
		m.exact[p] = struct{}{}
	}
	return m
}

// match reports whether host is allowed. An empty allowlist matches nothing.
// A "*.docker.com" suffix deliberately excludes the bare "docker.com".
func (m *hostMatcher) match(host string) bool {
	if _, ok := m.exact[host]; ok {
		return true
	}
	for _, suffix := range m.suffixes {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}
	return false
}

// ConnectEstablished is written to the client once the upstream is open.
// A CONNECT response carries no body, and framing headers here would
// desynchronise the tunnel, so it is written raw rather than through the
// HTTP server's response path.
const ConnectEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n"

// StatusLine renders a bare response head for the failure paths, which also
// have to be written directly onto a hijacked connection.
func StatusLine(code int) string {
	return fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", code, http.StatusText(code))
}

// Splice copies bytes in both directions until either side finishes, then
// returns the error that ended the tunnel (nil for a clean close).
//
// Both goroutines are joined before returning, so the caller may close the
// upstream connection knowing nothing still references it.
func Splice(client, upstream net.Conn, idleTimeout time.Duration) error {
	c := &idleConn{Conn: client, idle: idleTimeout}
	u := &idleConn{Conn: upstream, idle: idleTimeout}

	var wg sync.WaitGroup
	errs := make(chan error, 2)

	// Stopping dst unblocks the opposite direction, which is parked reading
	// it. Report before stopping: the error induced in the loser must not
	// beat the winner's onto the channel, or a clean close is reported as a
	// timeout.
	pump := func(dst, src *idleConn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		errs <- err
		dst.stop()
	}

	wg.Add(2)
	go pump(u, c)
	go pump(c, u)

	// Wait, rather than just draining errs: a pump touches its connection
	// again after sending. Returning early lets the caller close a socket
	// the server has already recycled into its pool, which races and panics.
	// errs is buffered for both sends, so this cannot deadlock.
	wg.Wait()

	first := <-errs
	<-errs
	return first
}

// idleConn turns the connection's absolute deadlines into an inactivity
// timeout by pushing the deadline out before every operation.
type idleConn struct {
	net.Conn
	idle time.Duration

	mu      sync.Mutex
	stopped bool
}

// stop ends the tunnel by setting an immediate deadline, and latches so a
// concurrent touch cannot push the deadline back out and leave the peer
// parked for another idle period.
//
// A deadline rather than Close: fasthttp's hijacked connection implements
// Close as a no-op, because the server closes the socket itself once the
// hijack handler returns. The deadline is the only mechanism that reliably
// wakes a peer goroutine.
func (c *idleConn) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopped = true
	// Unconditional: a disabled idle timeout still needs an unblock path.
	_ = c.SetDeadline(time.Now())
}

func (c *idleConn) touch() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.idle > 0 && !c.stopped {
		_ = c.SetDeadline(time.Now().Add(c.idle))
	}
}

func (c *idleConn) Read(p []byte) (int, error)  { c.touch(); return c.Conn.Read(p) }
func (c *idleConn) Write(p []byte) (int, error) { c.touch(); return c.Conn.Write(p) }
