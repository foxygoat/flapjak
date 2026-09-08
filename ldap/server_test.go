package ldap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/matryer/is"
)

const (
	adminDN  = "cn=admin,dc=example,dc=com"
	adminPw  = "secret"
	baseDN   = "dc=example,dc=com"
	testWait = 5 * time.Second
)

// testHandler is a Handler whose operations can be replaced per test. The
// embedded Unsupported supplies everything left unset.
type testHandler struct {
	Unsupported
	bind    func(*BindRequest) error
	search  func(context.Context, *SearchRequest, *SearchResponse) error
	compare func(*CompareRequest) (bool, error)
	whoami  func(*WhoAmIRequest) (string, error)
}

// Compare declines the comparison unless a test supplies one, so that the
// embedded Unsupported is still what answers by default.
func (h *testHandler) Compare(ctx context.Context, r *CompareRequest) (bool, error) {
	if h.compare != nil {
		return h.compare(r)
	}
	return h.Unsupported.Compare(ctx, r)
}

func (h *testHandler) Bind(_ context.Context, r *BindRequest) error {
	if h.bind != nil {
		return h.bind(r)
	}
	switch {
	case r.SASL():
		// Must come first: a SASL bind also has an empty Name and
		// Password, so an anonymous check would swallow it.
		return &Error{Code: AuthMethodNotSupported, Diagnostic: r.Mechanism}
	case r.Name == "" && r.Password == "":
		return nil // anonymous
	case r.Name == adminDN && r.Password == adminPw:
		return nil
	default:
		return &Error{Code: InvalidCredentials, Diagnostic: "bad credentials"}
	}
}

func (h *testHandler) Search(ctx context.Context, r *SearchRequest, w *SearchResponse) error {
	if h.search != nil {
		return h.search(ctx, r, w)
	}
	return w.Entry(baseDN, map[string][]any{
		"objectClass": {"top", "domain"},
		"dc":          {"example"},
	})
}

func (h *testHandler) WhoAmI(_ context.Context, r *WhoAmIRequest) (string, error) {
	if h.whoami != nil {
		return h.whoami(r)
	}
	if r.Conn.BindDN == "" {
		return "", nil
	}
	return "dn:" + r.Conn.BindDN, nil
}

// serveTest runs each of the given serve calls on its own goroutine, as the
// http.Server model intends, and shuts the server down when the test finishes.
// Callers make their own listeners, so addresses are known without the server
// having to report them.
func serveTest(t *testing.T, srv *Server, serves ...func() error) {
	t.Helper()

	if srv.Logger == nil {
		srv.Logger = slog.New(slog.DiscardHandler)
	}

	done := make(chan error, len(serves))
	for _, serve := range serves {
		go func() { done <- serve() }()
	}

	t.Cleanup(func() {
		// Not t.Context(): it is cancelled before cleanup runs, which
		// would leave the shutdown no grace period at all.
		ctx, cancel := context.WithTimeout(context.Background(), testWait)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown returned %v", err)
		}
		for range serves {
			select {
			case err := <-done:
				// Every Serve must report the shutdown as such.
				if !errors.Is(err, ErrServerClosed) {
					t.Errorf("Serve returned %v, want ErrServerClosed", err)
				}
			case <-time.After(testWait):
				t.Error("Serve did not return after Shutdown")
			}
		}
	})
}

// listen opens a loopback listener on an unused port.
func listen(t *testing.T) net.Listener {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// A server that serves it closes it itself. This is for the tests whose
	// server returns before it gets that far.
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// startPlain runs a server on a plain loopback port and returns its address.
func startPlain(t *testing.T, h Handler) string {
	t.Helper()
	srv := &Server{Handler: h}
	ln := listen(t)
	serveTest(t, srv, func() error { return srv.Serve(ln) })
	return ln.Addr().String()
}

// dial connects a go-ldap client to addr.
func dial(t *testing.T, addr string) *goldap.Conn {
	t.Helper()
	c, err := goldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestBind(t *testing.T) {
	addr := startPlain(t, &testHandler{})

	t.Run("simple", func(t *testing.T) {
		is := is.New(t)
		is.NoErr(dial(t, addr).Bind(adminDN, adminPw))
	})

	t.Run("anonymous", func(t *testing.T) {
		is := is.New(t)
		is.NoErr(dial(t, addr).UnauthenticatedBind(""))
	})

	t.Run("bad credentials", func(t *testing.T) {
		is := is.New(t)
		err := dial(t, addr).Bind(adminDN, "wrong")
		is.True(err != nil) // bad password must fail
		is.Equal(resultCode(err), uint16(InvalidCredentials))
	})
}

func TestSearch(t *testing.T) {
	is := is.New(t)
	addr := startPlain(t, &testHandler{})
	c := dial(t, addr)
	is.NoErr(c.Bind(adminDN, adminPw))

	res, err := c.Search(goldap.NewSearchRequest(
		baseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil))
	is.NoErr(err)
	is.Equal(len(res.Entries), 1)
	is.Equal(res.Entries[0].DN, baseDN)
	is.Equal(res.Entries[0].GetAttributeValues("objectClass"), []string{"top", "domain"})
	is.Equal(res.Entries[0].GetAttributeValue("dc"), "example")
}

// TestSearchValues checks that non-string attribute values reach the client in
// their RFC 4517 form.
func TestSearchValues(t *testing.T) {
	is := is.New(t)

	when := time.Date(2026, 8, 5, 12, 30, 0, 0, time.UTC)
	h := &testHandler{search: func(_ context.Context, _ *SearchRequest, w *SearchResponse) error {
		return w.Entry("uid=foo,"+baseDN, map[string][]any{
			"uidNumber":       {1000},
			"gidNumber":       {float64(1000)}, // as JSON and jsonnet deliver it
			"enabled":         {true},
			"createTimestamp": {when},
			"cn":              {"foo"},
		})
	}}

	c := dial(t, startPlain(t, h))
	res, err := c.Search(goldap.NewSearchRequest(
		baseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil))
	is.NoErr(err)
	is.Equal(len(res.Entries), 1)

	e := res.Entries[0]
	is.Equal(e.GetAttributeValue("uidNumber"), "1000")
	is.Equal(e.GetAttributeValue("gidNumber"), "1000") // not 1000.0 or 1e+03
	is.Equal(e.GetAttributeValue("enabled"), "TRUE")
	is.Equal(e.GetAttributeValue("createTimestamp"), "20260805123000Z")
	is.Equal(e.GetAttributeValue("cn"), "foo")
}

// TestSearchTypesOnly checks that the package strips values when the request
// asks for attribute types alone, without the handler having to.
func TestSearchTypesOnly(t *testing.T) {
	is := is.New(t)

	h := &testHandler{search: func(_ context.Context, _ *SearchRequest, w *SearchResponse) error {
		return w.Entry(baseDN, map[string][]any{"cn": {"foo"}, "uidNumber": {1000}})
	}}

	c := dial(t, startPlain(t, h))
	res, err := c.Search(goldap.NewSearchRequest(
		baseDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0, true,
		"(objectClass=*)", nil, nil))
	is.NoErr(err)
	is.Equal(len(res.Entries), 1)
	is.Equal(len(res.Entries[0].Attributes), 2)
	for _, a := range res.Entries[0].Attributes {
		is.Equal(len(a.Values), 0) // typesOnly must omit values
	}
}

// TestSearchRequestDecoding checks the request reaches the handler intact.
func TestSearchRequestDecoding(t *testing.T) {
	is := is.New(t)

	got := make(chan *SearchRequest, 1)
	h := &testHandler{search: func(_ context.Context, r *SearchRequest, _ *SearchResponse) error {
		got <- r
		return nil
	}}

	c := dial(t, startPlain(t, h))
	_, err := c.Search(goldap.NewSearchRequest(
		baseDN, goldap.ScopeSingleLevel, goldap.NeverDerefAliases, 42, 17, false,
		"(&(objectClass=posixAccount)(uid=foo))", []string{"cn", "uidNumber"}, nil))
	is.NoErr(err)

	r := <-got
	is.Equal(r.BaseDN, baseDN)
	is.Equal(r.Scope, SingleLevel)
	is.Equal(r.SizeLimit, 42)
	is.Equal(r.TimeLimit, 17)
	is.Equal(r.TypesOnly, false)
	is.Equal(r.Attributes, []string{"cn", "uidNumber"})
	is.Equal(r.Filter.String(), "(&(objectClass=posixAccount)(uid=foo))")
	is.True(r.Conn.TLS == nil)      // a plain connection has no TLS state
	is.Equal(r.MessageID, int32(1)) // first message on the connection
}

// TestSearchError checks a handler's Error becomes the client's result code.
func TestSearchError(t *testing.T) {
	is := is.New(t)

	h := &testHandler{search: func(_ context.Context, _ *SearchRequest, _ *SearchResponse) error {
		return &Error{Code: NoSuchObject, Diagnostic: "no such base"}
	}}

	c := dial(t, startPlain(t, h))
	_, err := c.Search(goldap.NewSearchRequest(
		"dc=nope", goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil))
	is.True(err != nil) // handler error must reach the client
	is.Equal(resultCode(err), uint16(NoSuchObject))
}

// TestSearchInternalError checks that an error which is not an ldap.Error is
// reported generically rather than leaking its text to the client.
func TestSearchInternalError(t *testing.T) {
	is := is.New(t)

	h := &testHandler{search: func(_ context.Context, _ *SearchRequest, _ *SearchResponse) error {
		return io.ErrUnexpectedEOF // stands in for a handler bug
	}}

	c := dial(t, startPlain(t, h))
	_, err := c.Search(goldap.NewSearchRequest(
		baseDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil))
	is.True(err != nil)
	is.Equal(resultCode(err), uint16(OperationsError))
	var lerr *goldap.Error
	is.True(errors.As(err, &lerr))
	is.Equal(lerr.Err.Error(), "internal error") // not the underlying text
}

// TestCompare checks that both answers to a compare reach the client. RFC 4511
// section 4.10 carries them as result codes rather than as a value, so the
// package is what maps the handler's bool onto compareTrue and compareFalse.
func TestCompare(t *testing.T) {
	addr := startPlain(t, &testHandler{compare: func(r *CompareRequest) (bool, error) {
		if r.Attribute == "broken" {
			return true, &Error{Code: NoSuchAttribute}
		}
		return r.Value == "example", nil
	}})

	t.Run("true", func(t *testing.T) {
		is := is.New(t)
		match, err := dial(t, addr).Compare(baseDN, "cn", "example")
		is.NoErr(err)
		is.True(match)
	})

	t.Run("false", func(t *testing.T) {
		is := is.New(t)
		match, err := dial(t, addr).Compare(baseDN, "cn", "other")
		is.NoErr(err)
		is.True(!match)
	})

	// An error is the result instead, and the bool is ignored.
	t.Run("error", func(t *testing.T) {
		is := is.New(t)
		_, err := dial(t, addr).Compare(baseDN, "broken", "example")
		is.True(err != nil)
		is.Equal(resultCode(err), uint16(NoSuchAttribute))
	})
}

// TestUnsupportedOperations checks the operations a handler embedding
// Unsupported declines.
//
// The defaults need a server of their own: testHandler overrides bind, search
// and WhoAmI, so a handler embedding Unsupported is the only way those
// implementations run.
func TestUnsupportedOperations(t *testing.T) {
	t.Run("compare", func(t *testing.T) {
		is := is.New(t)
		addr := startPlain(t, &testHandler{})
		_, err := dial(t, addr).Compare(baseDN, "cn", "example")
		is.True(err != nil)
		is.Equal(resultCode(err), uint16(UnwillingToPerform))
	})

	addr := startPlain(t, Unsupported{})

	t.Run("simple bind", func(t *testing.T) {
		is := is.New(t)
		// Declined even for an anonymous bind, which is what makes
		// Unsupported safe to embed.
		err := dial(t, addr).UnauthenticatedBind("")
		is.True(err != nil)
		is.Equal(resultCode(err), uint16(UnwillingToPerform))
	})

	t.Run("sasl bind", func(t *testing.T) {
		is := is.New(t)
		// authMethodNotSupported, not unwillingToPerform: the client
		// learns the mechanism was the problem, not its credentials.
		err := dial(t, addr).ExternalBind()
		is.True(err != nil)
		is.Equal(resultCode(err), uint16(AuthMethodNotSupported))
	})

	t.Run("search", func(t *testing.T) {
		is := is.New(t)
		_, err := dial(t, addr).Search(goldap.NewSearchRequest(
			baseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", nil, nil))
		is.True(err != nil)
		is.Equal(resultCode(err), uint16(UnwillingToPerform))
	})

	t.Run("whoami", func(t *testing.T) {
		is := is.New(t)
		_, err := dial(t, addr).WhoAmI(nil)
		is.True(err != nil)
		is.Equal(resultCode(err), uint16(UnwillingToPerform))
	})

	// Unbind has no subtest: it takes no response, so a client can only
	// report its own write, and nothing the server does could fail it.
	// TestUnbind covers the handler being reached and the connection
	// closing.
}

// TestUndecodedOperations checks that the write operations whose changes are
// not decoded are refused by the server without reaching the handler. There is
// no Handler method for them to reach.
func TestUndecodedOperations(t *testing.T) {
	// A handler that fails the test if any operation reaches it. Add,
	// Modify and ModifyDN are not on the interface, so the only way one
	// could arrive is through Search or another method being called for it.
	reached := make(chan string, 4)
	h := &testHandler{search: func(_ context.Context, _ *SearchRequest, _ *SearchResponse) error {
		reached <- "search"
		return nil
	}}
	addr := startPlain(t, h)

	add := goldap.NewAddRequest("cn=new,"+baseDN, nil)
	add.Attribute("objectClass", []string{"top"})

	modify := goldap.NewModifyRequest("cn=x,"+baseDN, nil)
	modify.Replace("cn", []string{"y"})

	tests := map[string]func(*goldap.Conn) error{
		"add":    func(c *goldap.Conn) error { return c.Add(add) },
		"modify": func(c *goldap.Conn) error { return c.Modify(modify) },
		"modifyDN": func(c *goldap.Conn) error {
			return c.ModifyDN(goldap.NewModifyDNRequest("cn=x,"+baseDN, "cn=y", true, ""))
		},
	}

	for name, op := range tests {
		t.Run(name, func(t *testing.T) {
			is := is.New(t)
			err := op(dial(t, addr))
			is.True(err != nil)
			is.Equal(resultCode(err), uint16(UnwillingToPerform))
		})
	}

	select {
	case op := <-reached:
		t.Fatalf("%s reached the handler", op)
	default:
	}
}

func TestWhoAmI(t *testing.T) {
	addr := startPlain(t, &testHandler{})

	t.Run("bound", func(t *testing.T) {
		is := is.New(t)
		c := dial(t, addr)
		is.NoErr(c.Bind(adminDN, adminPw))
		res, err := c.WhoAmI(nil)
		is.NoErr(err)
		is.Equal(res.AuthzID, "dn:"+adminDN)
	})

	t.Run("anonymous", func(t *testing.T) {
		is := is.New(t)
		res, err := dial(t, addr).WhoAmI(nil)
		is.NoErr(err)
		is.Equal(res.AuthzID, "")
	})
}

// TestCriticalControl checks that an unrecognised critical control is refused
// before the handler runs, per RFC 4511 section 4.1.11.
func TestCriticalControl(t *testing.T) {
	is := is.New(t)

	called := false
	h := &testHandler{search: func(_ context.Context, _ *SearchRequest, _ *SearchResponse) error {
		called = true
		return nil
	}}

	c := dial(t, startPlain(t, h))
	req := goldap.NewSearchRequest(baseDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", nil,
		[]goldap.Control{&goldap.ControlManageDsaIT{Criticality: true}})
	_, err := c.Search(req)
	is.True(err != nil)
	is.Equal(resultCode(err), uint16(UnavailableCriticalExtension))
	is.Equal(called, false) // handler must not run
}

// TestNonCriticalControl checks that a control which is not critical is
// ignored rather than refused.
func TestNonCriticalControl(t *testing.T) {
	is := is.New(t)

	got := make(chan []Control, 1)
	h := &testHandler{search: func(_ context.Context, r *SearchRequest, _ *SearchResponse) error {
		got <- r.Controls
		return nil
	}}

	c := dial(t, startPlain(t, h))
	req := goldap.NewSearchRequest(baseDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", nil,
		[]goldap.Control{&goldap.ControlManageDsaIT{Criticality: false}})
	_, err := c.Search(req)
	is.NoErr(err)

	controls := <-got
	is.Equal(len(controls), 1)
	is.Equal(controls[0].OID, goldap.ControlTypeManageDsaIT)
	is.Equal(controls[0].Criticality, false)
}

func TestLDAPS(t *testing.T) {
	is := is.New(t)

	tlsConf, pool := testTLS(t)
	srv := &Server{Handler: &testHandler{}, TLSConfig: tlsConf}
	ln := listen(t)
	serveTest(t, srv, func() error { return srv.ServeTLS(ln) })

	c, err := goldap.DialURL("ldaps://"+ln.Addr().String(),
		goldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}))
	is.NoErr(err)
	defer func() { _ = c.Close() }()
	is.NoErr(c.Bind(adminDN, adminPw))
}

func TestStartTLS(t *testing.T) {
	is := is.New(t)

	tlsConf, pool := testTLS(t)
	got := make(chan *SearchRequest, 1)
	h := &testHandler{search: func(_ context.Context, r *SearchRequest, _ *SearchResponse) error {
		got <- r
		return nil
	}}
	srv := &Server{Handler: h, TLSConfig: tlsConf}
	ln := listen(t)
	serveTest(t, srv, func() error { return srv.Serve(ln) })

	c := dial(t, ln.Addr().String())
	is.NoErr(c.StartTLS(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}))

	_, ok := c.TLSConnectionState()
	is.True(ok) // connection must be TLS after StartTLS

	is.NoErr(c.Bind(adminDN, adminPw))
	_, err := c.Search(goldap.NewSearchRequest(baseDN, goldap.ScopeBaseObject,
		goldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
	is.NoErr(err)
	is.True((<-got).Conn.TLS != nil) // and the handler must see that
}

// TestStartTLSTwice checks the second attempt is refused, per RFC 4513
// section 3.1.1.
//
// Driven over the wire because go-ldap refuses a second StartTLS itself, with
// "ldap: already encrypted", so the server never sees one and the branch under
// test never runs.
func TestStartTLSTwice(t *testing.T) {
	is := is.New(t)

	tlsConf, pool := testTLS(t)
	srv := &Server{Handler: &testHandler{}, TLSConfig: tlsConf}
	ln := listen(t)
	serveTest(t, srv, func() error { return srv.Serve(ln) })

	w := dialWire(t, ln.Addr().String())
	w.send(1, extendedOp(oidStartTLS))
	is.Equal(w.recv().resultCode(t), Success)
	w.upgrade(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})

	w.send(2, extendedOp(oidStartTLS))
	m := w.recv()
	is.Equal(m.id, int32(2))
	is.Equal(m.resultCode(t), OperationsError)

	// The connection survives the refusal, which is what makes it a
	// refusal rather than a disconnection.
	w.send(3, adminBindOp())
	is.Equal(w.recv().resultCode(t), Success)
}

// TestStartTLSWithoutConfig checks a plain server refuses StartTLS rather than
// failing in some less legible way.
func TestStartTLSWithoutConfig(t *testing.T) {
	is := is.New(t)

	c := dial(t, startPlain(t, &testHandler{}))
	err := c.StartTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test client
	is.True(err != nil)
	is.Equal(resultCode(err), uint16(ProtocolError))
}

// TestBothListeners checks one server serving LDAP and LDAPS at once.
func TestBothListeners(t *testing.T) {
	is := is.New(t)

	tlsConf, pool := testTLS(t)
	srv := &Server{Handler: &testHandler{}, TLSConfig: tlsConf}
	plainLn, tlsLn := listen(t), listen(t)
	serveTest(t, srv,
		func() error { return srv.Serve(plainLn) },
		func() error { return srv.ServeTLS(tlsLn) })

	plain := dial(t, plainLn.Addr().String())
	is.NoErr(plain.Bind(adminDN, adminPw))

	secure, err := goldap.DialURL("ldaps://"+tlsLn.Addr().String(),
		goldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}))
	is.NoErr(err)
	defer func() { _ = secure.Close() }()
	is.NoErr(secure.Bind(adminDN, adminPw))
}

func TestServeErrors(t *testing.T) {
	is := is.New(t)

	// A server with no handler cannot serve.
	is.True(errors.Is((&Server{}).Serve(listen(t)), ErrNoHandler))

	// LDAPS needs a TLS configuration.
	is.True(errors.Is((&Server{Handler: &testHandler{}}).ServeTLS(listen(t)), ErrNoTLSConfig))
	is.True(errors.Is((&Server{Handler: &testHandler{}}).ListenAndServeTLS("127.0.0.1:0"), ErrNoTLSConfig))

	// An address that cannot be bound is reported, not panicked on.
	is.True((&Server{Handler: &testHandler{}}).ListenAndServe("256.0.0.1:0") != nil)
}

// TestServeAfterShutdown checks that a listener handed to a server that has
// already stopped is refused rather than silently accepted.
func TestServeAfterShutdown(t *testing.T) {
	is := is.New(t)

	srv := &Server{Handler: &testHandler{}, Logger: discardLogger()}
	is.NoErr(srv.Shutdown(t.Context()))

	ln := listen(t)
	is.True(errors.Is(srv.Serve(ln), ErrServerClosed))

	// The refused listener must be closed, not leaked.
	_, err := ln.Accept()
	is.True(err != nil)
}

// TestShutdownWaitsForOperations checks the graceful path: an operation still
// running holds shutdown open, and finishes normally.
func TestShutdownWaitsForOperations(t *testing.T) {
	is := is.New(t)

	started := make(chan struct{})
	release := make(chan struct{})
	h := &testHandler{search: func(_ context.Context, _ *SearchRequest, _ *SearchResponse) error {
		close(started)
		<-release
		return nil
	}}

	srv := &Server{Handler: h, Logger: discardLogger()}
	ln := listen(t)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	c := dial(t, ln.Addr().String())
	searched := make(chan error, 1)
	go func() {
		_, err := c.Search(goldap.NewSearchRequest(baseDN, goldap.ScopeBaseObject,
			goldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
		searched <- err
	}()

	<-started

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), testWait)
		defer cancel()
		done <- srv.Shutdown(ctx)
	}()

	// Shutdown must not complete while the search is in flight.
	select {
	case err := <-done:
		t.Fatalf("Shutdown returned %v while an operation was running", err)
	case <-time.After(300 * time.Millisecond):
	}

	close(release)
	is.NoErr(<-done)     // shutdown completes once the operation finishes
	is.NoErr(<-searched) // and the client still got its result
	is.True(errors.Is(<-served, ErrServerClosed))
}

// TestShutdownRefusesNewRequests checks that a connection which never falls
// idle still lets the server shut down.
//
// Polling for an idle connection is not enough on its own: one long operation,
// or overlapping ones, keeps a connection busy for as long as the client cares
// to. Requests arriving after Shutdown are refused with unavailable, so such a
// connection drains rather than being dropped when the deadline expires.
func TestShutdownRefusesNewRequests(t *testing.T) {
	is := is.New(t)

	started := make(chan struct{})
	release := make(chan struct{})
	h := &testHandler{search: func(_ context.Context, r *SearchRequest, w *SearchResponse) error {
		// Only the held search blocks. Anything else must not reach the
		// handler at all once the shutdown has begun.
		if r.BaseDN == baseDN {
			close(started)
			<-release
		}
		return w.Entry(r.BaseDN, map[string][]any{"cn": {"x"}})
	}}

	srv := &Server{Handler: h, Logger: discardLogger()}
	ln := listen(t)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	c := dial(t, ln.Addr().String())
	search := func(base string) error {
		_, err := c.Search(goldap.NewSearchRequest(base, goldap.ScopeBaseObject,
			goldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
		return err
	}

	// Hold one operation open for the whole shutdown, so the connection is
	// never found idle. A search is used rather than a bind to probe with:
	// a bind waits for outstanding operations to drain, so it would block
	// on the held search rather than be answered.
	go func() { _ = search(baseDN) }()
	<-started

	shutdown := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), testWait)
		defer cancel()
		shutdown <- srv.Shutdown(ctx)
	}()

	// Retried because Shutdown reaches this connection a moment after it is
	// called, so the first probe or two may still be served.
	var err error
	for range 100 {
		if err = search("dc=other"); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	is.True(err != nil) // requests must stop being served
	is.Equal(resultCode(err), uint16(Unavailable))

	// Releasing the held operation is what lets the connection close, and
	// so what completes the shutdown - without reaching the deadline.
	close(release)
	is.NoErr(<-shutdown)
	is.True(errors.Is(<-served, ErrServerClosed))
}

// TestShutdownDuringBlockedBind checks the handler is not called for a bind
// whose connection went away while it waited.
//
// A bind waits for outstanding operations to drain (RFC 4511 4.2.1). If a
// shutdown begins during that wait, the last of those operations closes the
// connection, and the bind is left holding a request there is no longer anyone
// to answer.
func TestShutdownDuringBlockedBind(t *testing.T) {
	is := is.New(t)

	started := make(chan struct{})
	release := make(chan struct{})
	bound := make(chan struct{}, 1)

	// Signals that a bind has reached the wait for outstanding operations,
	// which is the state this test needs and which nothing else marks.
	waiting := make(chan struct{}, 1)
	beforeBindWait = func() { waiting <- struct{}{} }
	t.Cleanup(func() { beforeBindWait = nil })

	h := &testHandler{
		search: func(_ context.Context, _ *SearchRequest, _ *SearchResponse) error {
			close(started)
			<-release
			return nil
		},
		bind: func(*BindRequest) error {
			bound <- struct{}{}
			return nil
		},
	}

	srv := &Server{Handler: h, Logger: discardLogger()}
	ln := listen(t)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	c := dial(t, ln.Addr().String())
	go func() {
		_, _ = c.Search(goldap.NewSearchRequest(baseDN, goldap.ScopeBaseObject,
			goldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
	}()
	<-started

	// This bind blocks in the server until the search drains.
	go func() { _ = c.Bind(adminDN, adminPw) }()
	select {
	case <-waiting:
	case <-time.After(testWait):
		t.Fatal("bind did not reach the wait for outstanding operations")
	}

	// Drained before Shutdown is called, so the connection is in the state
	// under test rather than whenever Shutdown's own goroutine gets to it.
	drain(srv)

	shutdown := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), testWait)
		defer cancel()
		shutdown <- srv.Shutdown(ctx)
	}()

	// Releasing the search closes the connection, which is what the
	// waiting bind must notice.
	close(release)
	is.NoErr(<-shutdown)
	is.True(errors.Is(<-served, ErrServerClosed))

	select {
	case <-bound:
		t.Fatal("bind handler ran for a connection that had already closed")
	default:
	}
}

// TestShutdownDeadline checks that an operation which outlasts the deadline
// makes Shutdown report it rather than waiting forever.
func TestShutdownDeadline(t *testing.T) {
	is := is.New(t)

	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	h := &testHandler{search: func(_ context.Context, _ *SearchRequest, _ *SearchResponse) error {
		close(started)
		<-release
		return nil
	}}

	srv := &Server{Handler: h, Logger: discardLogger()}
	ln := listen(t)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	c := dial(t, ln.Addr().String())
	go func() {
		_, _ = c.Search(goldap.NewSearchRequest(baseDN, goldap.ScopeBaseObject,
			goldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
	}()
	<-started

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	is.True(errors.Is(srv.Shutdown(ctx), context.DeadlineExceeded))

	// The listener is closed regardless, so Serve has still returned.
	is.True(errors.Is(<-served, ErrServerClosed))

	// Close drops what Shutdown would not.
	is.NoErr(srv.Close())
}

// TestCloseCancelsOperations checks that Close cancels in-flight operations
// rather than waiting for them.
func TestCloseCancelsOperations(t *testing.T) {
	is := is.New(t)

	started := make(chan struct{})
	cancelled := make(chan error, 1)
	h := &testHandler{search: func(ctx context.Context, _ *SearchRequest, _ *SearchResponse) error {
		close(started)
		<-ctx.Done()
		cancelled <- ctx.Err()
		return ctx.Err()
	}}

	srv := &Server{Handler: h, Logger: discardLogger()}
	ln := listen(t)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	c := dial(t, ln.Addr().String())
	go func() {
		_, _ = c.Search(goldap.NewSearchRequest(baseDN, goldap.ScopeBaseObject,
			goldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
	}()
	<-started

	is.NoErr(srv.Close())

	select {
	case err := <-cancelled:
		is.True(errors.Is(err, context.Canceled))
	case <-time.After(testWait):
		t.Fatal("Close did not cancel the running operation")
	}
	is.True(errors.Is(<-served, ErrServerClosed))
}

// TestServeWrappedTLSListener checks that a listener the caller wrapped in TLS
// and passed to Serve, rather than ServeTLS, is still recognised as secure.
func TestServeWrappedTLSListener(t *testing.T) {
	is := is.New(t)

	tlsConf, pool := testTLS(t)
	got := make(chan *SearchRequest, 1)
	h := &testHandler{search: func(_ context.Context, r *SearchRequest, _ *SearchResponse) error {
		got <- r
		return nil
	}}

	srv := &Server{Handler: h, Logger: discardLogger()}
	ln := tls.NewListener(listen(t), tlsConf)
	serveTest(t, srv, func() error { return srv.Serve(ln) })

	c, err := goldap.DialURL("ldaps://"+ln.Addr().String(),
		goldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}))
	is.NoErr(err)
	defer func() { _ = c.Close() }()

	_, err = c.Search(goldap.NewSearchRequest(baseDN, goldap.ScopeBaseObject,
		goldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
	is.NoErr(err)
	is.True((<-got).Conn.TLS != nil) // must not look like a plain connection
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// TestMutualTLS checks the path that motivated exposing the TLS state: a
// client certificate reaching a handler, which authenticates a SASL EXTERNAL
// bind against it.
func TestMutualTLS(t *testing.T) {
	is := is.New(t)

	tlsConf, pool := testTLS(t)
	// Ask for a client certificate but let the handler decide what to make
	// of it, rather than failing the handshake.
	tlsConf.ClientAuth = tls.RequestClientCert

	bound := make(chan *BindRequest, 1)
	h := &testHandler{bind: func(r *BindRequest) error {
		bound <- r
		if !r.SASL() || r.Mechanism != "EXTERNAL" {
			return &Error{Code: AuthMethodNotSupported}
		}
		if r.Conn.TLS == nil || len(r.Conn.TLS.PeerCertificates) == 0 {
			return &Error{Code: InvalidCredentials, Diagnostic: "no client certificate"}
		}
		// Authenticate as the certificate's subject.
		r.Name = "cn=" + r.Conn.TLS.PeerCertificates[0].Subject.CommonName
		return nil
	}}

	srv := &Server{Handler: h, TLSConfig: tlsConf, Logger: discardLogger()}
	ln := listen(t)
	serveTest(t, srv, func() error { return srv.ServeTLS(ln) })

	clientCert := testClientCert(t)
	c, err := goldap.DialURL("ldaps://"+ln.Addr().String(), goldap.DialWithTLSConfig(&tls.Config{
		RootCAs:      pool,
		ServerName:   "127.0.0.1",
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
	}))
	is.NoErr(err)
	defer func() { _ = c.Close() }()

	is.NoErr(c.ExternalBind()) // SASL EXTERNAL over the client certificate

	r := <-bound
	is.Equal(r.Mechanism, "EXTERNAL")
	is.True(r.Conn.TLS != nil)
	is.Equal(len(r.Conn.TLS.PeerCertificates), 1)
	is.Equal(r.Conn.TLS.PeerCertificates[0].Subject.CommonName, "flapjak client")

	// The DN the handler settled on is what the connection is bound as.
	who, err := c.WhoAmI(nil)
	is.NoErr(err)
	is.Equal(who.AuthzID, "dn:cn=flapjak client")
}

// TestTLSStateIsExposed checks that a handler can see how a connection is
// protected, not merely that it is.
func TestTLSStateIsExposed(t *testing.T) {
	is := is.New(t)

	tlsConf, pool := testTLS(t)
	got := make(chan *SearchRequest, 1)
	h := &testHandler{search: func(_ context.Context, r *SearchRequest, _ *SearchResponse) error {
		got <- r
		return nil
	}}

	srv := &Server{Handler: h, TLSConfig: tlsConf, Logger: discardLogger()}
	ln := listen(t)
	serveTest(t, srv, func() error { return srv.ServeTLS(ln) })

	c, err := goldap.DialURL("ldaps://"+ln.Addr().String(),
		goldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}))
	is.NoErr(err)
	defer func() { _ = c.Close() }()

	_, err = c.Search(goldap.NewSearchRequest(baseDN, goldap.ScopeBaseObject,
		goldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
	is.NoErr(err)

	state := (<-got).Conn.TLS
	is.True(state != nil)
	is.Equal(state.Version, uint16(tls.VersionTLS13)) // handshake is complete before dispatch
	is.True(state.CipherSuite != 0)
	is.Equal(len(state.PeerCertificates), 0) // none requested
}

// testClientCert returns a certificate a client can present, signed by itself;
// the test server requests but does not verify client certificates.
func testClientCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "flapjak client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// testTLS returns a server TLS configuration using a freshly generated
// self-signed certificate for 127.0.0.1, and a pool that trusts it.
func testTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "flapjak test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}},
		MinVersion:   tls.VersionTLS12,
	}, pool
}

// resultCode extracts the LDAP result code from a go-ldap client error.
func resultCode(err error) uint16 {
	if lerr, ok := errors.AsType[*goldap.Error](err); ok {
		return lerr.ResultCode
	}
	return 0
}
