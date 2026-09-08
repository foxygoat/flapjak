package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"
	"time"
)

// ErrServerClosed is returned by [Server.Serve] and its variants after
// [Server.Shutdown] or [Server.Close] is called.
var ErrServerClosed = errors.New("ldap: server closed")

// shutdownPollInterval is how often Shutdown re-checks whether the connections
// still running an operation have finished.
const shutdownPollInterval = 100 * time.Millisecond

// Server serves LDAP.
//
// It follows the model of net/http.Server: one Server serves any number of
// listeners, each passed to a separate call to [Server.Serve] or
// [Server.ServeTLS] running on its own goroutine. Serving both a plain LDAP
// port and an LDAPS port is two calls:
//
//	srv := &ldap.Server{Handler: h, TLSConfig: cfg}
//	go srv.ListenAndServe(":389")
//	go srv.ListenAndServeTLS(":636")
//
// The Server tracks every listener and connection it is given, so
// [Server.Shutdown] stops all of them together.
//
// TLSConfig is shared: it secures the listeners passed to ServeTLS and answers
// StartTLS on the ones passed to Serve. A connection arriving on a listener
// that is already TLS is recognised as secure either way, so wrapping a
// listener with tls.NewListener and passing it to Serve works too.
//
// The zero value is not usable: at minimum a Handler must be set. Fields must
// be set before serving and not changed after: each connection takes its own
// copy of them as it is accepted, so a later change reaches new connections
// only, and races with the accept loop reading them. A Server must not be
// copied after first use.
type Server struct {
	// Handler serves the directory operations. It is required.
	Handler Handler

	// TLSConfig secures ServeTLS listeners and answers StartTLS on plain
	// ones. If nil, ServeTLS fails and StartTLS is refused.
	TLSConfig *tls.Config

	// Logger receives connection and operation logs. If nil,
	// slog.Default is used.
	Logger *slog.Logger

	// IdleTimeout is how long a connection may go without sending a
	// message before it is closed. Zero means no limit.
	IdleTimeout time.Duration

	// WriteTimeout bounds a single response write. Zero means no limit.
	WriteTimeout time.Duration

	mu        sync.Mutex
	closing   bool
	listeners []net.Listener
	conns     map[*conn]struct{}
}

// ListenAndServe listens on the given TCP address and serves plain LDAP,
// accepting StartTLS if the server has a TLS configuration.
//
// Unlike net/http.Server there is no Addr field, because a Server here is
// expected to have more than one listener and a single address field would
// only describe one of them.
func (s *Server) ListenAndServe(addr string) error {
	// net.Listen rather than ListenConfig.Listen: that context covers only
	// resolving the address, not the listener it returns, so taking one
	// here would look like a way to stop the server and not be one.
	// Shutdown and Close are that.
	ln, err := net.Listen("tcp", addr) //nolint:noctx // see above
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	return s.Serve(ln)
}

// ListenAndServeTLS listens on the given TCP address and serves LDAPS,
// encrypting connections from the first byte using TLSConfig.
func (s *Server) ListenAndServeTLS(addr string) error {
	if s.TLSConfig == nil {
		return fmt.Errorf("%w: cannot serve LDAPS on %s", ErrNoTLSConfig, addr)
	}
	ln, err := net.Listen("tcp", addr) //nolint:noctx // see ListenAndServe
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	return s.ServeTLS(ln)
}

// Serve accepts plain LDAP connections on ln until the server is shut down,
// at which point it returns [ErrServerClosed].
//
// StartTLS is available on these connections if TLSConfig is set. A listener
// that is already a TLS listener may be passed here; its connections are
// recognised as secure.
func (s *Server) Serve(ln net.Listener) error {
	return s.serve(ln, false)
}

// ServeTLS wraps ln in TLSConfig and serves LDAPS on it until the server is
// shut down, at which point it returns [ErrServerClosed].
func (s *Server) ServeTLS(ln net.Listener) error {
	if s.TLSConfig == nil {
		return ErrNoTLSConfig
	}
	return s.serve(tls.NewListener(ln, s.TLSConfig), true)
}

func (s *Server) serve(ln net.Listener, secure bool) error {
	if s.Handler == nil {
		return ErrNoHandler
	}
	if !s.registerListener(ln) {
		// Shut down before this listener could be added; close the
		// listener we were handed rather than leaking it.
		_ = ln.Close()
		return ErrServerClosed
	}
	defer s.deregisterListener(ln)

	s.logger().Info("listening", "address", ln.Addr().String(), "tls", secure)

	// The root of every connection's context. Cancelling a connection is
	// what close does; stopping the server is Shutdown or Close, so there
	// is nothing above this to inherit from.
	ctx := context.Background()

	for {
		nc, err := ln.Accept()
		if err != nil {
			if s.isClosing() {
				return ErrServerClosed
			}
			if nerr, ok := errors.AsType[net.Error](err); ok && nerr.Timeout() {
				continue
			}
			return fmt.Errorf("accept on %s: %w", ln.Addr(), err)
		}

		c := newConn(ctx, s, nc)
		if !s.registerConn(c) {
			c.close()
			return ErrServerClosed
		}
		go func() {
			defer s.deregisterConn(c)
			c.serve()
		}()
	}
}

// Shutdown stops the server gracefully. It closes every listener, then puts
// each connection into draining: requests arriving from then on are refused
// with unavailable, and a connection closes once the searches and compares
// already running on it finish. If ctx expires first, Shutdown returns its
// error and leaves those connections running; call [Server.Close] to drop
// them.
//
// Only search and compare are waited for. Bind, unbind, WhoAmI and StartTLS
// run on the connection's read loop rather than on their own goroutines, and
// one already inside its handler is not waited for: the connection closes
// under it and its response is not delivered. StartTLS never reaches a handler;
// [Handler] asks that the three it does define be quick for the same reason.
//
// Refusing new requests is what makes this terminate. A client is free to keep
// issuing requests, and one that does would never be found idle.
//
// The grace period is the deadline on ctx, so it is chosen per shutdown rather
// than configured on the Server.
//
// Shutdown does not wait for Serve to return. Once Shutdown returns, every
// Serve call is either returning or about to return [ErrServerClosed].
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	err := s.closeListenersLocked()
	conns := slices.Collect(maps.Keys(s.conns))
	s.mu.Unlock()

	// Outside the lock: shutting down an idle connection closes it, and its
	// serve goroutine then deregisters itself, which takes s.mu.
	for _, c := range conns {
		c.shutdown()
	}

	ticker := time.NewTicker(shutdownPollInterval)
	defer ticker.Stop()
	for s.connCount() > 0 {
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-ticker.C:
		}
	}

	return err
}

// Close stops the server immediately, closing every listener and connection
// and cancelling the context of every operation still running. Handlers
// observing that cancellation see the same thing they would from an Abandon.
//
// For an orderly stop, use [Server.Shutdown].
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.closeListenersLocked()
	s.closing = true
	for c := range s.conns {
		// Cancels the connection's operations as well as closing it.
		c.close()
	}
	// The connection goroutines deregister themselves once they unwind.
	return err
}

func (s *Server) closeListenersLocked() error {
	var err error
	for _, listener := range s.listeners {
		if cerr := listener.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}
	s.listeners = nil
	return err
}

// connCount reports how many connections are still open. Connections
// deregister themselves as they unwind, so this reaching zero is what tells
// Shutdown that every one of them has finished.
func (s *Server) connCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// registerListener adds a listener, reporting false if the server is
// already shutting down and the listener was not added.
func (s *Server) registerListener(ln net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closing {
		return false
	}
	s.listeners = append(s.listeners, ln)
	return true
}

func (s *Server) deregisterListener(ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = slices.DeleteFunc(s.listeners, func(l net.Listener) bool {
		return l == ln
	})
}

// registerConn adds a connection, reporting false if the server is
// already shutting down and the connection was not added.
func (s *Server) registerConn(c *conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closing {
		return false
	}
	if s.conns == nil {
		s.conns = make(map[*conn]struct{})
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) deregisterConn(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

func (s *Server) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
