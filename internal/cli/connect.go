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
	"context"
	"net"

	"github.com/gofiber/fiber/v2"

	"github.com/soulteary/apt-proxy/internal/tunnel"
)

// handleConnect serves HTTP CONNECT by opening a raw TCP tunnel to the
// requested origin.
//
// Everything that needs releasing is acquired inside the hijack callback.
// fasthttp does not guarantee the callback runs at all: it abandons the
// hijack if flushing a pending response or clearing the deadline fails,
// which a client can force by pipelining a request and aborting. Acquiring
// outside would strand a concurrency slot and an upstream socket per
// attempt, until the cap was exhausted and tunnelling stopped for everyone.
func (s *Server) handleConnect(c *fiber.Ctx) error {
	fctx := c.Context()

	// The CONNECT request-target is authority-form ("host:443"). Read it
	// verbatim from the request line: the router's path has been through URI
	// normalisation and is not a trustworthy destination.
	rawTarget := string(fctx.Request.Header.RequestURI())

	// Authorization holds no resources, so it can answer through Fiber.
	target, err := s.tunnel.Authorize(rawTarget)
	if err != nil {
		s.log.Warn().
			Err(err).
			Str("target", rawTarget).
			Str("client", c.IP()).
			Msg("rejected CONNECT request")
		return c.SendStatus(tunnel.StatusFor(err))
	}

	// Capture the context value, never the *fiber.Ctx: Fiber returns the Ctx
	// to its pool before the hijack callback runs.
	dialCtx := c.UserContext()

	// Suppress the server's own response; everything from here is raw bytes.
	fctx.HijackSetNoResponse(true)
	fctx.Hijack(func(client net.Conn) {
		s.openTunnel(dialCtx, client, target)
	})

	return nil
}

// openTunnel reserves a slot, dials the origin and pumps bytes, reporting
// failures as a bare status line because the connection is already hijacked.
func (s *Server) openTunnel(ctx context.Context, client net.Conn, target string) {
	release, ok := s.tunnel.Acquire()
	if !ok {
		s.log.Warn().
			Str("target", target).
			Int64("active", s.tunnel.Active()).
			Msg("refused CONNECT: concurrent tunnel limit reached")
		s.writeStatus(client, tunnel.StatusFor(tunnel.ErrTooManyTunnels), target)
		return
	}
	defer release()

	upstream, err := s.tunnel.Dial(ctx, target)
	if err != nil {
		s.log.Error().Err(err).Str("target", target).Msg("CONNECT upstream dial failed")
		s.writeStatus(client, tunnel.StatusFor(err), target)
		return
	}
	defer func() { _ = upstream.Close() }()

	s.log.Debug().
		Str("target", target).
		Int64("active", s.tunnel.Active()).
		Msg("CONNECT tunnel established")

	if _, err := client.Write([]byte(tunnel.ConnectEstablished)); err != nil {
		s.log.Debug().Err(err).Str("target", target).Msg("CONNECT client went away before the tunnel opened")
		return
	}

	if err := tunnel.Splice(client, upstream, s.tunnel.IdleTimeout()); err != nil {
		s.log.Debug().Err(err).Str("target", target).Msg("CONNECT tunnel closed")
	}
}

// writeStatus reports a failure on an already-hijacked connection. The
// server closes the connection once the hijack callback returns.
func (s *Server) writeStatus(client net.Conn, code int, target string) {
	if _, err := client.Write([]byte(tunnel.StatusLine(code))); err != nil {
		s.log.Debug().Err(err).Str("target", target).Int("status", code).Msg("failed to report CONNECT failure")
	}
}
