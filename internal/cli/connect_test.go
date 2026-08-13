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

package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	logger "github.com/soulteary/logger-kit"

	"github.com/soulteary/apt-proxy/internal/config"
	"github.com/soulteary/apt-proxy/internal/tunnel"
)

// connectTestServer boots a real Server on a loopback listener.
//
// A real socket is required rather than app.Test: Fiber's test transport is
// backed by a pair of byte buffers, not a duplex connection, so a hijacked
// tunnel cannot be exercised through it.
func connectTestServer(t *testing.T, connectCfg config.ConnectConfig) (*Server, string) {
	t.Helper()

	cfg := withTestMirrors(&config.Config{
		CacheDir: t.TempDir(),
		Listen:   "127.0.0.1:0",
		Connect:  connectCfg,
	})

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.app.Listener(ln) }()

	t.Cleanup(func() {
		_ = srv.app.Shutdown()
		if srv.cache != nil {
			_ = srv.cache.Close()
		}
	})

	addr := ln.Addr().String()
	for i := 0; i < 100; i++ {
		c, derr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			return srv, addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s never started accepting", addr)
	return nil, ""
}

// echoProxy boots an echo origin plus a proxy allowlisted to reach it.
func echoProxy(t *testing.T, cfg config.ConnectConfig) (srv *Server, proxyAddr, origin string) {
	t.Helper()

	origin = echoOrigin(t)
	host, portStr, err := net.SplitHostPort(origin)
	if err != nil {
		t.Fatalf("split origin %q: %v", origin, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse origin port %q: %v", portStr, err)
	}

	cfg.Enabled = true
	cfg.AllowedHosts = []string{host}
	cfg.AllowedPorts = []int{port}

	srv, proxyAddr = connectTestServer(t, cfg)
	return srv, proxyAddr, origin
}

// sendConnect issues a raw CONNECT and returns the status line plus the
// still-open connection, so a caller can keep using an established tunnel.
func sendConnect(t *testing.T, proxyAddr, target string, extraHeaders ...string) (*bufio.Reader, net.Conn, string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	for _, h := range extraHeaders {
		req += h + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	return br, conn, strings.TrimSpace(status)
}

// drainHeaders consumes response headers up to and including the blank line.
func drainHeaders(t *testing.T, br *bufio.Reader) {
	t.Helper()
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			return
		}
	}
}

// echoOrigin is a stand-in upstream that echoes whatever it receives.
func echoOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func TestConnectDisabledByDefault(t *testing.T) {
	_, addr := connectTestServer(t, config.ConnectConfig{})

	_, _, status := sendConnect(t, addr, "download.docker.com:443")
	if !strings.Contains(status, "405") {
		t.Fatalf("status = %q, want 405 when CONNECT is disabled", status)
	}
}

func TestConnectDefaultDeniesUnlistedHost(t *testing.T) {
	// Enabled but with no allowlist: every destination must be refused.
	_, addr := connectTestServer(t, config.ConnectConfig{Enabled: true})

	_, _, status := sendConnect(t, addr, "download.docker.com:443")
	if !strings.Contains(status, "403") {
		t.Fatalf("status = %q, want 403 with an empty allowlist", status)
	}
}

func TestConnectRejections(t *testing.T) {
	_, addr, origin := echoProxy(t, config.ConnectConfig{})
	host, _, err := net.SplitHostPort(origin)
	if err != nil {
		t.Fatalf("split origin: %v", err)
	}

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "host not allowed", target: "evil.example.com:443", want: "403"},
		{name: "port not allowed", target: host + ":25", want: "403"},
		{name: "malformed target", target: "no-port-here", want: "400"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, status := sendConnect(t, addr, tt.target)
			if !strings.Contains(status, tt.want) {
				t.Fatalf("status = %q, want %s", status, tt.want)
			}
		})
	}
}

func TestConnectTunnelsBytes(t *testing.T) {
	_, addr, origin := echoProxy(t, config.ConnectConfig{})

	br, conn, status := sendConnect(t, addr, origin)
	if !strings.Contains(status, "200") {
		t.Fatalf("status = %q, want 200 Connection Established", status)
	}
	drainHeaders(t, br)

	if _, err := conn.Write([]byte("nftables-monitor\n")); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	echo, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if strings.TrimSpace(echo) != "nftables-monitor" {
		t.Fatalf("echo = %q, want %q", strings.TrimSpace(echo), "nftables-monitor")
	}
}

// TestConnectWithConnectionClose pins behaviour that the underlying server's
// own documentation gets wrong: it states the hijack handler is skipped when
// Connection: close is present. That early exit only applies when the server
// writes the response itself, which the tunnel deliberately suppresses. apt
// sends Connection: close in some configurations, so this must keep working.
func TestConnectWithConnectionClose(t *testing.T) {
	_, addr, origin := echoProxy(t, config.ConnectConfig{})

	br, conn, status := sendConnect(t, addr, origin, "Connection: close")
	if !strings.Contains(status, "200") {
		t.Fatalf("status = %q, want 200 even with Connection: close", status)
	}
	drainHeaders(t, br)

	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if strings.TrimSpace(echo) != "ping" {
		t.Fatalf("echo = %q, want ping", strings.TrimSpace(echo))
	}
}

func TestConnectRefusedUpstreamReturnsBadGateway(t *testing.T) {
	// Reserve a port then release it so the dial is refused rather than
	// hanging, which is the behaviour apt needs to avoid a stalled update.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := ln.Addr().String()
	host, portStr, err := net.SplitHostPort(dead)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	deadPort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	_ = ln.Close()

	_, addr := connectTestServer(t, config.ConnectConfig{
		Enabled:      true,
		AllowedHosts: []string{host},
		AllowedPorts: []int{deadPort},
	})

	_, _, status := sendConnect(t, addr, dead)
	if !strings.Contains(status, "502") {
		t.Fatalf("status = %q, want 502 for a refused upstream", status)
	}
}

func TestConnectConcurrencyLimit(t *testing.T) {
	_, addr, origin := echoProxy(t, config.ConnectConfig{MaxConcurrent: 1})

	// Hold one tunnel open.
	br, _, status := sendConnect(t, addr, origin)
	if !strings.Contains(status, "200") {
		t.Fatalf("first CONNECT status = %q, want 200", status)
	}
	drainHeaders(t, br)

	// The second must be refused rather than queued or leaked.
	_, _, second := sendConnect(t, addr, origin)
	if !strings.Contains(second, "503") {
		t.Fatalf("second CONNECT status = %q, want 503 at the cap", second)
	}
}

// TestConnectEndToEndTLS is the acceptance test: a stock HTTP client
// configured to use apt-proxy fetches a package index from an HTTPS origin,
// with TLS terminating at the origin rather than at the proxy.
func TestConnectEndToEndTLS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "Package: nftables-monitor\n")
	}))
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatalf("parse origin URL: %v", err)
	}
	port, err := strconv.Atoi(originURL.Port())
	if err != nil {
		t.Fatalf("parse origin port: %v", err)
	}

	_, addr := connectTestServer(t, config.ConnectConfig{
		Enabled:      true,
		AllowedHosts: []string{originURL.Hostname()},
		AllowedPorts: []int{port},
	})

	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: originRootCAs(t, origin)},
		},
	}

	resp, err := client.Get(origin.URL + "/dists/noble/InRelease")
	if err != nil {
		t.Fatalf("GET through tunnel: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "nftables-monitor") {
		t.Fatalf("body = %q, want the origin's content", body)
	}
}

// TestConnectReleasesSlots drives many sequential tunnels and asserts the
// concurrency accounting returns to zero. A slot that is not released is how
// a tunnelling proxy slowly runs out of file descriptors, which is the exact
// failure this feature must not reintroduce.
func TestConnectReleasesSlots(t *testing.T) {
	srv, addr, origin := echoProxy(t, config.ConnectConfig{IdleTimeout: 2 * time.Second})

	for i := 0; i < 25; i++ {
		_, conn, status := sendConnect(t, addr, origin)
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT %d status = %q, want 200", i, status)
		}
		// Client hangs up, as apt does when a fetch completes.
		_ = conn.Close()
	}

	waitForIdle(t, srv, "sequential tunnels")
}

// TestConnectSurvivesAbandonedHijack is the regression guard for a slot and
// socket leak that a client could trigger at will.
//
// fasthttp abandons a hijack if flushing a pending response fails, so a
// pipelined request followed by an abort reaches the hijack block with dirty
// buffered data and the callback never runs. Anything acquired before the
// callback is stranded for the life of the process; at the default cap, a
// few hundred of these disable tunnelling entirely.
//
// The trigger is statistical: a flush that happens to succeed opens a normal
// tunnel instead. 25 iterations makes it reliable, but a single green run is
// weaker evidence than it looks.
func TestConnectSurvivesAbandonedHijack(t *testing.T) {
	srv, addr, origin := echoProxy(t, config.ConnectConfig{})

	for i := 0; i < 25; i++ {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		tcp, ok := conn.(*net.TCPConn)
		if !ok {
			t.Fatalf("dial %d did not yield a TCP connection", i)
		}
		// One segment carrying both requests, so the response to the first is
		// still buffered when the server reaches the hijack for the second.
		req := "GET /_/ping HTTP/1.1\r\nHost: p\r\n\r\n" +
			"CONNECT " + origin + " HTTP/1.1\r\nHost: " + origin + "\r\n\r\n"
		if _, err := tcp.Write([]byte(req)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		// RST rather than FIN, so the pending flush fails.
		_ = tcp.SetLinger(0)
		_ = tcp.Close()
	}

	waitForIdle(t, srv, "aborted pipelined requests")
}

func TestTunnelMetricIsExported(t *testing.T) {
	_, addr := connectTestServer(t, config.ConnectConfig{Enabled: true})

	resp, err := http.Get("http://" + addr + "/metrics") //nolint:noctx // short-lived test request
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics: %v", err)
	}
	if !strings.Contains(string(body), "apt_proxy_connect_tunnels_active") {
		t.Fatal("apt_proxy_connect_tunnels_active missing from /metrics")
	}
}

func TestRegisterTunnelMetricsIsSafeWithoutRegistry(t *testing.T) {
	// Guards the nil paths so a partially built Server cannot panic.
	(&Server{}).registerTunnelMetrics()
}

// --- openTunnel failure paths ---
//
// Driven directly rather than through a socket: once a connection is
// hijacked there is no way to make the client write fail on demand.

func TestOpenTunnelRefusedAtCapacity(t *testing.T) {
	srv := &Server{
		log:    testLogger(),
		tunnel: tunnel.New(tunnel.Config{Enabled: true, MaxConcurrent: 1}, nil),
	}
	hold, ok := srv.tunnel.Acquire()
	if !ok {
		t.Fatal("could not take the only slot")
	}
	defer hold()

	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	go srv.openTunnel(context.Background(), client, "example.com:443")

	status := readStatusLine(t, peer)
	if !strings.Contains(status, "503") {
		t.Fatalf("status = %q, want 503 at the cap", status)
	}
}

func TestOpenTunnelDialFailureReportsStatus(t *testing.T) {
	srv := &Server{
		log:    testLogger(),
		tunnel: tunnel.New(tunnel.Config{Enabled: true}, &failingDialer{}),
	}

	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	done := make(chan struct{})
	go func() {
		srv.openTunnel(context.Background(), client, "example.com:443")
		close(done)
	}()

	status := readStatusLine(t, peer)
	if !strings.Contains(status, "502") {
		t.Fatalf("status = %q, want 502 when the dial fails", status)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("openTunnel did not return after the dial failed")
	}
	if srv.tunnel.Active() != 0 {
		t.Errorf("Active() = %d after a failed dial, want 0; the slot was not released", srv.tunnel.Active())
	}
}

func TestOpenTunnelClientWriteFails(t *testing.T) {
	upstream, upstreamPeer := net.Pipe()
	defer upstreamPeer.Close()

	srv := &Server{
		log:    testLogger(),
		tunnel: tunnel.New(tunnel.Config{Enabled: true}, &fixedDialer{conn: upstream}),
	}

	client, clientPeer := net.Pipe()
	defer client.Close()
	defer clientPeer.Close()

	done := make(chan struct{})
	go func() {
		srv.openTunnel(context.Background(), &failingConn{Conn: client}, "example.com:443")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("openTunnel did not return after the client write failed")
	}

	// The upstream must be closed even though the tunnel never opened,
	// otherwise a failed handshake leaks a socket per attempt.
	if _, err := upstream.Write([]byte("x")); err == nil {
		t.Error("upstream was left open after a failed client write")
	}
	if srv.tunnel.Active() != 0 {
		t.Errorf("Active() = %d, want 0", srv.tunnel.Active())
	}
}

func TestOpenTunnelLogsSpliceError(t *testing.T) {
	upstream, upstreamPeer := net.Pipe()
	defer upstreamPeer.Close()

	srv := &Server{
		log: testLogger(),
		tunnel: tunnel.New(tunnel.Config{
			Enabled:     true,
			IdleTimeout: 100 * time.Millisecond,
		}, &fixedDialer{conn: upstream}),
	}

	client, clientPeer := net.Pipe()
	defer clientPeer.Close()

	// Drain the CONNECT status line so the write completes, then go quiet so
	// the idle timeout fires and Splice returns an error.
	go func() {
		buf := make([]byte, len(tunnel.ConnectEstablished))
		_, _ = io.ReadFull(clientPeer, buf)
	}()

	done := make(chan struct{})
	go func() {
		srv.openTunnel(context.Background(), client, "example.com:443")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("openTunnel did not return after the idle timeout")
	}
}

func TestWriteStatusToleratesDeadClient(t *testing.T) {
	srv := &Server{log: testLogger()}

	client, peer := net.Pipe()
	_ = client.Close()
	_ = peer.Close()

	// Must not panic when the client has already gone.
	srv.writeStatus(client, http.StatusBadGateway, "example.com:443")
}

// --- helpers ---

// waitForIdle polls until every tunnel slot has been returned.
func waitForIdle(t *testing.T, srv *Server, what string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if srv.tunnel.Active() == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Active() = %d after %s, want 0", srv.tunnel.Active(), what)
}

func readStatusLine(t *testing.T, c net.Conn) string {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	return strings.TrimSpace(line)
}

func testLogger() *logger.Logger {
	return logger.New(logger.Config{Level: logger.ErrorLevel, Output: io.Discard})
}

// failingConn makes Write fail, standing in for a client that hung up
// between the proxy accepting the CONNECT and the tunnel opening.
type failingConn struct {
	net.Conn
}

func (*failingConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type failingDialer struct{}

func (*failingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, io.ErrClosedPipe
}

type fixedDialer struct{ conn net.Conn }

func (d *fixedDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func originRootCAs(t *testing.T, s *httptest.Server) *x509.CertPool {
	t.Helper()
	tr, ok := s.Client().Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatal("httptest server did not expose a TLS client config")
	}
	return tr.TLSClientConfig.RootCAs
}
