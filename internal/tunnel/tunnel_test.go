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

package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- test doubles ---

// fakeDialer returns a preset connection or error without touching the network.
type fakeDialer struct {
	conn net.Conn
	err  error

	mu      sync.Mutex
	network string
	address string
	calls   int
	// block, when set, holds the dial until the context is cancelled so the
	// dial-timeout path can be exercised deterministically.
	block bool
}

func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.network, d.address = network, address
	d.calls++
	blocking := d.block
	d.mu.Unlock()

	if blocking {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return d.conn, d.err
}

func (d *fakeDialer) lastAddress() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.address
}

func (d *fakeDialer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// tcpPair returns two ends of a real loopback TCP connection. Real sockets
// are used rather than net.Pipe so deadline and half-close behaviour matches
// what the daemon sees in production.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, aerr := ln.Accept()
		ch <- accepted{c, aerr}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatalf("accept: %v", got.err)
	}

	t.Cleanup(func() {
		_ = client.Close()
		_ = got.conn.Close()
	})
	return client, got.conn
}

// echoListener accepts connections and echoes everything back.
func echoListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// --- parseTarget ---

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{name: "host and port", input: "download.docker.com:443", wantHost: "download.docker.com", wantPort: 443},
		{name: "uppercase is normalised", input: "Download.Docker.COM:443", wantHost: "download.docker.com", wantPort: 443},
		{name: "surrounding space tolerated", input: "  repo.saltproject.io:443  ", wantHost: "repo.saltproject.io", wantPort: 443},
		{name: "ipv4 literal", input: "192.0.2.10:443", wantHost: "192.0.2.10", wantPort: 443},
		{name: "ipv6 literal", input: "[2001:db8::1]:443", wantHost: "2001:db8::1", wantPort: 443},
		{name: "lowest valid port", input: "example.com:1", wantHost: "example.com", wantPort: 1},
		{name: "highest valid port", input: "example.com:65535", wantHost: "example.com", wantPort: 65535},

		{name: "empty", input: "", wantErr: true},
		{name: "only whitespace", input: "   ", wantErr: true},
		{name: "no port", input: "example.com", wantErr: true},
		{name: "empty host", input: ":443", wantErr: true},
		{name: "empty port", input: "example.com:", wantErr: true},
		{name: "non numeric port", input: "example.com:https", wantErr: true},
		{name: "port zero", input: "example.com:0", wantErr: true},
		{name: "port too high", input: "example.com:65536", wantErr: true},
		{name: "negative port", input: "example.com:-1", wantErr: true},
		{name: "trailing path", input: "example.com:443/dists", wantErr: true},
		{name: "unbracketed ipv6", input: "2001:db8::1:443", wantErr: true},
		{name: "at the length limit", input: strings.Repeat("a", maxTargetLen-4) + ":443", wantHost: strings.Repeat("a", maxTargetLen-4), wantPort: 443},
		{name: "over the length limit", input: strings.Repeat("a", maxTargetLen) + ":443", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseTarget(tt.input)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidTarget) {
					t.Fatalf("parseTarget(%q) error = %v, want ErrInvalidTarget", tt.input, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTarget(%q) unexpected error: %v", tt.input, err)
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("parseTarget(%q) = (%q, %d), want (%q, %d)", tt.input, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

// --- host allowlist ---

func TestHostMatcher(t *testing.T) {
	m := newHostMatcher([]string{
		"download.docker.com",
		"*.saltproject.io",
		"  APT.SHQ.NZ  ",
		"",
		"   ",
	})

	allowed := []string{
		"download.docker.com",
		"repo.saltproject.io",
		"deep.nested.saltproject.io",
		"apt.shq.nz",
	}
	for _, host := range allowed {
		if !m.match(host) {
			t.Errorf("match(%q) = false, want true", host)
		}
	}

	denied := []string{
		"docker.com",
		"download.docker.com.evil.net",
		"saltproject.io",     // wildcard must not match the bare domain
		"evilsaltproject.io", // suffix must align on a label boundary
		"notdownload.docker.com",
		"",
	}
	for _, host := range denied {
		if m.match(host) {
			t.Errorf("match(%q) = true, want false", host)
		}
	}
}

func TestHostMatcherEmptyDeniesEverything(t *testing.T) {
	m := newHostMatcher(nil)
	for _, host := range []string{"download.docker.com", "localhost", "127.0.0.1"} {
		if m.match(host) {
			t.Errorf("empty allowlist matched %q; default must be deny", host)
		}
	}
}

// --- Authorize ---

func TestAuthorizeDisabled(t *testing.T) {
	tn := New(Config{Enabled: false, AllowedHosts: []string{"download.docker.com"}}, &fakeDialer{})
	if _, err := tn.Authorize("download.docker.com:443"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Authorize error = %v, want ErrDisabled", err)
	}
}

func TestAuthorize(t *testing.T) {
	tn := New(Config{
		Enabled:      true,
		AllowedHosts: []string{"download.docker.com", "*.saltproject.io"},
		AllowedPorts: []int{443, 8443},
	}, &fakeDialer{})

	tests := []struct {
		name    string
		target  string
		want    string
		wantErr error
	}{
		{name: "allowed exact host", target: "download.docker.com:443", want: "download.docker.com:443"},
		{name: "allowed wildcard host", target: "repo.saltproject.io:443", want: "repo.saltproject.io:443"},
		{name: "allowed alternate port", target: "download.docker.com:8443", want: "download.docker.com:8443"},
		{name: "canonicalises case", target: "DOWNLOAD.DOCKER.COM:443", want: "download.docker.com:443"},
		{name: "denied host", target: "evil.example.com:443", wantErr: ErrHostNotAllowed},
		{name: "denied port", target: "download.docker.com:25", wantErr: ErrPortNotAllowed},
		{name: "malformed target", target: "not-a-target", wantErr: ErrInvalidTarget},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tn.Authorize(tt.target)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Authorize(%q) error = %v, want %v", tt.target, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Authorize(%q) unexpected error: %v", tt.target, err)
			}
			if got != tt.want {
				t.Fatalf("Authorize(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

func TestAuthorizeDefaultPortsAllowOnly443(t *testing.T) {
	tn := New(Config{Enabled: true, AllowedHosts: []string{"example.com"}}, &fakeDialer{})

	if _, err := tn.Authorize("example.com:443"); err != nil {
		t.Fatalf("port 443 should be allowed by default, got %v", err)
	}
	for _, port := range []string{"80", "22", "25", "3142"} {
		if _, err := tn.Authorize("example.com:" + port); !errors.Is(err, ErrPortNotAllowed) {
			t.Errorf("port %s error = %v, want ErrPortNotAllowed", port, err)
		}
	}
}

// --- concurrency cap ---

func TestAcquireLimit(t *testing.T) {
	tn := New(Config{Enabled: true, MaxConcurrent: 2}, &fakeDialer{})

	first, ok := tn.Acquire()
	if !ok {
		t.Fatal("first Acquire failed")
	}
	second, ok := tn.Acquire()
	if !ok {
		t.Fatal("second Acquire failed")
	}
	if got := tn.Active(); got != 2 {
		t.Fatalf("Active() = %d, want 2", got)
	}

	if _, ok := tn.Acquire(); ok {
		t.Fatal("third Acquire succeeded, want rejection at the cap")
	}
	if got := tn.Active(); got != 2 {
		t.Fatalf("Active() = %d after rejection, want 2 (rejected slot must roll back)", got)
	}

	first()
	if got := tn.Active(); got != 1 {
		t.Fatalf("Active() = %d after release, want 1", got)
	}

	// A second release of the same slot must not deflate the gauge.
	first()
	if got := tn.Active(); got != 1 {
		t.Fatalf("Active() = %d after double release, want 1", got)
	}

	third, ok := tn.Acquire()
	if !ok {
		t.Fatal("Acquire after release failed, slot was not returned")
	}
	second()
	third()
	if got := tn.Active(); got != 0 {
		t.Fatalf("Active() = %d after all releases, want 0", got)
	}
}

func TestAcquireRejectedReleaseIsNoOp(t *testing.T) {
	tn := New(Config{Enabled: true, MaxConcurrent: 1}, &fakeDialer{})

	keep, ok := tn.Acquire()
	if !ok {
		t.Fatal("first Acquire failed")
	}
	release, ok := tn.Acquire()
	if ok {
		t.Fatal("second Acquire succeeded, want rejection")
	}

	release() // must not corrupt the counter
	if got := tn.Active(); got != 1 {
		t.Fatalf("Active() = %d, want 1", got)
	}
	keep()
}

func TestAcquireUnlimited(t *testing.T) {
	tn := New(Config{Enabled: true, MaxConcurrent: -1}, &fakeDialer{})

	releases := make([]func(), 0, 64)
	for i := 0; i < 64; i++ {
		release, ok := tn.Acquire()
		if !ok {
			t.Fatalf("Acquire %d rejected, want unlimited", i)
		}
		releases = append(releases, release)
	}
	if got := tn.Active(); got != 64 {
		t.Fatalf("Active() = %d, want 64", got)
	}
	for _, release := range releases {
		release()
	}
	if got := tn.Active(); got != 0 {
		t.Fatalf("Active() = %d, want 0", got)
	}
}

func TestAcquireIsRaceFree(t *testing.T) {
	const limit = 8
	tn := New(Config{Enabled: true, MaxConcurrent: limit}, &fakeDialer{})

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		granted int
	)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, ok := tn.Acquire()
			if !ok {
				return
			}
			mu.Lock()
			granted++
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()

	if got := tn.Active(); got != 0 {
		t.Fatalf("Active() = %d after all goroutines finished, want 0", got)
	}
	if granted == 0 {
		t.Fatal("no tunnel was ever granted")
	}
}

// --- defaults ---

func TestNewAppliesDefaults(t *testing.T) {
	tn := New(Config{Enabled: true}, nil)

	if tn.maxConcurrent != DefaultMaxConcurrent {
		t.Errorf("maxConcurrent = %d, want %d", tn.maxConcurrent, DefaultMaxConcurrent)
	}
	if tn.dialTimeout != DefaultDialTimeout {
		t.Errorf("dialTimeout = %v, want %v", tn.dialTimeout, DefaultDialTimeout)
	}
	if tn.IdleTimeout() != DefaultIdleTimeout {
		t.Errorf("IdleTimeout() = %v, want %v", tn.IdleTimeout(), DefaultIdleTimeout)
	}
	if tn.dialer == nil {
		t.Error("dialer = nil, want a default net.Dialer")
	}
	if _, ok := tn.ports[443]; !ok {
		t.Error("default port allowlist does not contain 443")
	}
}

func TestNewHonoursExplicitValues(t *testing.T) {
	tn := New(Config{
		Enabled:       true,
		AllowedPorts:  []int{8443},
		MaxConcurrent: 7,
		DialTimeout:   3 * time.Second,
		IdleTimeout:   -1,
	}, &fakeDialer{})

	if tn.maxConcurrent != 7 {
		t.Errorf("maxConcurrent = %d, want 7", tn.maxConcurrent)
	}
	if tn.dialTimeout != 3*time.Second {
		t.Errorf("dialTimeout = %v, want 3s", tn.dialTimeout)
	}
	if tn.IdleTimeout() != -1 {
		t.Errorf("IdleTimeout() = %v, want -1 (disabled)", tn.IdleTimeout())
	}
	if _, ok := tn.ports[443]; ok {
		t.Error("explicit port list must replace the default, not extend it")
	}
}

// --- Dial ---

func TestDialPassesTargetThrough(t *testing.T) {
	client, _ := tcpPair(t)
	dialer := &fakeDialer{conn: client}
	tn := New(Config{Enabled: true}, dialer)

	conn, err := tn.Dial(context.Background(), "download.docker.com:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if conn != client {
		t.Error("Dial returned a different connection than the dialer produced")
	}
	if got := dialer.lastAddress(); got != "download.docker.com:443" {
		t.Errorf("dialed address = %q, want %q", got, "download.docker.com:443")
	}
	if dialer.network != "tcp" {
		t.Errorf("dialed network = %q, want tcp", dialer.network)
	}
	if got := dialer.callCount(); got != 1 {
		t.Errorf("dialer called %d times, want exactly 1", got)
	}
}

func TestDialPropagatesError(t *testing.T) {
	wantErr := errors.New("connection refused")
	tn := New(Config{Enabled: true}, &fakeDialer{err: wantErr})

	if _, err := tn.Dial(context.Background(), "example.com:443"); !errors.Is(err, wantErr) {
		t.Fatalf("Dial error = %v, want %v", err, wantErr)
	}
}

func TestDialAppliesTimeout(t *testing.T) {
	tn := New(Config{Enabled: true, DialTimeout: 50 * time.Millisecond}, &fakeDialer{block: true})

	start := time.Now()
	_, err := tn.Dial(context.Background(), "example.com:443")
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Dial took %v, timeout was not applied", elapsed)
	}
}

func TestDialHonoursCallerCancellation(t *testing.T) {
	tn := New(Config{Enabled: true, DialTimeout: time.Hour}, &fakeDialer{block: true})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := tn.Dial(ctx, "example.com:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial error = %v, want context.Canceled", err)
	}
}

// --- StatusFor ---

func TestStatusFor(t *testing.T) {
	timeoutErr := &net.OpError{Op: "dial", Err: &timeoutError{}}

	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil", err: nil, want: http.StatusOK},
		{name: "disabled", err: ErrDisabled, want: http.StatusMethodNotAllowed},
		{name: "invalid target", err: ErrInvalidTarget, want: http.StatusBadRequest},
		{name: "host denied", err: ErrHostNotAllowed, want: http.StatusForbidden},
		{name: "port denied", err: ErrPortNotAllowed, want: http.StatusForbidden},
		{name: "at capacity", err: ErrTooManyTunnels, want: http.StatusServiceUnavailable},
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: http.StatusGatewayTimeout},
		{name: "net timeout", err: timeoutErr, want: http.StatusGatewayTimeout},
		{name: "wrapped sentinel", err: wrap(ErrHostNotAllowed), want: http.StatusForbidden},
		{name: "unknown", err: errors.New("boom"), want: http.StatusBadGateway},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StatusFor(tt.err); got != tt.want {
				t.Fatalf("StatusFor(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func wrap(err error) error { return &wrappedError{err} }

type wrappedError struct{ err error }

func (w *wrappedError) Error() string { return "wrapped: " + w.err.Error() }
func (w *wrappedError) Unwrap() error { return w.err }

type timeoutError struct{}

func (*timeoutError) Error() string   { return "i/o timeout" }
func (*timeoutError) Timeout() bool   { return true }
func (*timeoutError) Temporary() bool { return true }

// --- Splice ---

func TestSpliceCopiesBothDirections(t *testing.T) {
	client, clientPeer := tcpPair(t)
	upstream, upstreamPeer := tcpPair(t)

	spliceErr := make(chan error, 1)
	go func() { spliceErr <- Splice(client, upstream, time.Second) }()

	// client -> upstream
	if _, err := clientPeer.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
		t.Fatalf("write from client: %v", err)
	}
	buf := make([]byte, 16)
	if err := readFull(upstreamPeer, buf); err != nil {
		t.Fatalf("read at upstream: %v", err)
	}
	if string(buf) != "GET / HTTP/1.1\r\n" {
		t.Fatalf("upstream received %q", buf)
	}

	// upstream -> client
	if _, err := upstreamPeer.Write([]byte("HTTP/1.1 200 OK\r\n")); err != nil {
		t.Fatalf("write from upstream: %v", err)
	}
	buf = make([]byte, 17)
	if err := readFull(clientPeer, buf); err != nil {
		t.Fatalf("read at client: %v", err)
	}
	if string(buf) != "HTTP/1.1 200 OK\r\n" {
		t.Fatalf("client received %q", buf)
	}

	_ = clientPeer.Close()
	select {
	case err := <-spliceErr:
		if err != nil {
			t.Fatalf("Splice returned %v, want nil on clean close", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Splice did not return after the client closed")
	}
}

func TestSpliceReturnsWhenUpstreamCloses(t *testing.T) {
	client, _ := tcpPair(t)
	upstream, upstreamPeer := tcpPair(t)

	spliceErr := make(chan error, 1)
	go func() { spliceErr <- Splice(client, upstream, time.Second) }()

	_ = upstreamPeer.Close()

	select {
	case err := <-spliceErr:
		if err != nil {
			t.Fatalf("Splice returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Splice did not return after the upstream closed")
	}
}

func TestSpliceIdleTimeout(t *testing.T) {
	client, _ := tcpPair(t)
	upstream, _ := tcpPair(t)

	start := time.Now()
	err := Splice(client, upstream, 100*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Splice returned nil, want an idle timeout error")
	}
	if !isTimeout(err) {
		t.Fatalf("Splice error = %v, want a timeout error", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("idle timeout took %v, far longer than configured", elapsed)
	}
}

func TestSpliceIdleTimeoutDisabled(t *testing.T) {
	client, clientPeer := tcpPair(t)
	upstream, _ := tcpPair(t)

	spliceErr := make(chan error, 1)
	go func() { spliceErr <- Splice(client, upstream, -1) }()

	// With the idle check disabled the tunnel must stay open while quiet.
	select {
	case err := <-spliceErr:
		t.Fatalf("Splice returned early with %v; idle timeout should be disabled", err)
	case <-time.After(300 * time.Millisecond):
	}

	_ = clientPeer.Close()
	select {
	case <-spliceErr:
	case <-time.After(5 * time.Second):
		t.Fatal("Splice did not return after close")
	}
}

func TestSpliceLeavesNoGoroutines(t *testing.T) {
	upstreamLn := echoListener(t)

	before := runtime.NumGoroutine()
	for i := 0; i < 30; i++ {
		client, clientPeer := tcpPair(t)
		upstream, err := net.Dial("tcp", upstreamLn.Addr().String())
		if err != nil {
			t.Fatalf("dial upstream: %v", err)
		}

		done := make(chan struct{})
		go func() {
			_ = Splice(client, upstream, 2*time.Second)
			_ = upstream.Close()
			close(done)
		}()

		if _, err := clientPeer.Write([]byte("ping")); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 4)
		if err := readFull(clientPeer, buf); err != nil {
			t.Fatalf("echo read: %v", err)
		}
		_ = clientPeer.Close()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("Splice %d did not tear down", i)
		}
	}

	after := settledGoroutines(before)
	if after > before+2 {
		t.Fatalf("goroutines grew from %d to %d across 30 tunnels; suspect a leak", before, after)
	}
}

// --- idleConn ---

// TestIdleConnStopIsSticky is the regression guard for the defect where the
// idle refresh overwrote the immediate deadline Splice sets to unblock a
// peer, stalling teardown for a further idle period while holding two file
// descriptors, a goroutine and a concurrency slot.
//
// It is deliberately at the idleConn level: driven through Splice the race
// window is almost always missed, because a flooding peer leaves the reader
// with buffered data and it unblocks for the wrong reason.
func TestIdleConnStopIsSticky(t *testing.T) {
	client, _ := tcpPair(t) // the peer never writes
	c := &idleConn{Conn: client, idle: 2 * time.Second}

	c.stop()

	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read returned a nil error after stop(), want a timeout")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Read blocked for %v after stop(); the idle refresh wiped the deadline", elapsed)
	}

	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("Write succeeded after stop(), want a timeout")
	}
}

// A disabled idle timeout must still be able to tear a tunnel down.
func TestIdleConnStopWorksWithIdleDisabled(t *testing.T) {
	client, _ := tcpPair(t)
	c := &idleConn{Conn: client, idle: -1}

	c.stop()

	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read returned a nil error after stop(), want a timeout")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Read blocked for %v; stop() must not depend on the idle timeout", elapsed)
	}
}

func TestIdleConnRefreshesDeadlines(t *testing.T) {
	client, peer := tcpPair(t)
	c := &idleConn{Conn: client, idle: 5 * time.Second}

	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("idleConn.Read: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("read %q, want hello", buf)
	}

	if _, err := c.Write([]byte("world")); err != nil {
		t.Fatalf("idleConn.Write: %v", err)
	}
	got := make([]byte, 5)
	if err := readFull(peer, got); err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if string(got) != "world" {
		t.Fatalf("peer read %q, want world", got)
	}
}

func TestIdleConnZeroDisablesDeadlines(t *testing.T) {
	client, peer := tcpPair(t)
	c := &idleConn{Conn: client, idle: 0}

	if _, err := peer.Write([]byte("hi")); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("Read with idle=0: %v", err)
	}
	if _, err := c.Write([]byte("yo")); err != nil {
		t.Fatalf("Write with idle=0: %v", err)
	}
	got := make([]byte, 2)
	if err := readFull(peer, got); err != nil {
		t.Fatalf("peer read: %v", err)
	}
}

// --- constants ---

func TestConnectEstablishedIsAValidStatusLine(t *testing.T) {
	if !strings.HasPrefix(ConnectEstablished, "HTTP/1.1 200 ") {
		t.Fatalf("ConnectEstablished = %q, want a 200 status line", ConnectEstablished)
	}
	if !strings.HasSuffix(ConnectEstablished, "\r\n\r\n") {
		t.Fatalf("ConnectEstablished = %q, want a blank line terminating the head", ConnectEstablished)
	}
	// A CONNECT success must not frame a body; Content-Length or
	// Transfer-Encoding here would desynchronise the tunnel.
	lower := strings.ToLower(ConnectEstablished)
	if strings.Contains(lower, "content-length") || strings.Contains(lower, "transfer-encoding") {
		t.Fatalf("ConnectEstablished = %q, must not carry body framing headers", ConnectEstablished)
	}
}

func TestStatusLine(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{code: http.StatusForbidden, want: "HTTP/1.1 403 Forbidden\r\n\r\n"},
		{code: http.StatusBadGateway, want: "HTTP/1.1 502 Bad Gateway\r\n\r\n"},
		{code: http.StatusServiceUnavailable, want: "HTTP/1.1 503 Service Unavailable\r\n\r\n"},
		{code: http.StatusGatewayTimeout, want: "HTTP/1.1 504 Gateway Timeout\r\n\r\n"},
	}
	for _, tt := range tests {
		if got := StatusLine(tt.code); got != tt.want {
			t.Errorf("StatusLine(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}

	// Like ConnectEstablished, these go straight onto a hijacked connection,
	// so body framing would desynchronise whatever follows.
	for _, tt := range tests {
		lower := strings.ToLower(StatusLine(tt.code))
		if strings.Contains(lower, "content-length") || strings.Contains(lower, "transfer-encoding") {
			t.Errorf("StatusLine(%d) carries body framing headers", tt.code)
		}
	}
}

// --- helpers ---

// settledGoroutines polls until the goroutine count stops shrinking, so a
// still-unwinding runtime does not make the leak check flaky.
func settledGoroutines(baseline int) int {
	current := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		if current <= baseline+2 {
			return current
		}
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
		current = runtime.NumGoroutine()
	}
	return current
}

func readFull(c net.Conn, buf []byte) error {
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	_, err := io.ReadFull(c, buf)
	return err
}
