package main

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"slices"
	"time"

	"foxygo.at/flapjak/ldap"
)

// shutdownGrace is how long open connections are given to finish once a
// shutdown signal arrives. It is a variable so that a test need not wait it
// out.
var shutdownGrace = 5 * time.Second

// Connection timeouts. Without them a client that connects and goes quiet, or
// that stops reading part way through a response, holds a goroutine and a file
// descriptor for the life of the process.
//
// Clients that keep a connection between lookups, nslcd among them, re-dial
// when the server closes an idle one, so idleTimeout costs them a reconnect
// rather than a failed lookup.
const (
	idleTimeout  = 5 * time.Minute
	writeTimeout = 30 * time.Second
)

// Server serves a DB over LDAP.
type Server struct {
	ldap *ldap.Server
}

// NewServer returns a Server serving db.
func NewServer(db *DB) *Server {
	return &Server{ldap: &ldap.Server{
		Handler:      &Handler{db: db},
		IdleTimeout:  idleTimeout,
		WriteTimeout: writeTimeout,
	}}
}

// Run serves LDAP on listen until ctx is cancelled, or until the listener
// fails on its own. On cancellation, open connections are given shutdownGrace
// to finish what they are doing before they are dropped.
func (s *Server) Run(ctx context.Context, listen string) error {
	// The listener takes no context: a server is stopped by Shutdown or
	// Close, which distinguish a graceful stop from an immediate one where
	// a cancelled context could not.
	served := make(chan error, 1)
	go func() { served <- s.ldap.ListenAndServe(listen) }() //nolint:contextcheck // see above

	select {
	case <-ctx.Done():
	case err := <-served:
		// Stopping by itself is always a failure; a deliberate stop
		// only comes from the Shutdown below.
		return err
	}
	slog.Info("Shutting down", "grace", shutdownGrace)

	// Not derived from ctx, which the shutdown signal has already
	// cancelled: inheriting it would give the grace period a deadline that
	// has already passed.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	var err error
	if serr := s.ldap.Shutdown(shutdownCtx); serr != nil { //nolint:contextcheck // see above
		// Either the grace period expired with operations still
		// running or a listener would not close. Close drops whatever
		// Shutdown could not, and both are reported: a shutdown that
		// killed live operations is worth a non-zero exit rather than
		// only a log line. The wrap is deliberately neutral, since the
		// cause is usually a bare context.DeadlineExceeded.
		slog.Warn("Shutdown incomplete, closing connections", "error", serr)
		err = errors.Join(fmt.Errorf("graceful shutdown: %w", serr), s.ldap.Close())
	}
	if lerr := <-served; !errors.Is(lerr, ldap.ErrServerClosed) {
		err = errors.Join(err, lerr)
	}
	return err
}

// errNoSuchEntry is the cause recorded when a bind names a DN the directory
// does not hold. It never reaches the client, which cannot be told an unknown
// DN from a bad password.
var errNoSuchEntry = errors.New("no such entry")

// Handler serves flapjak's static directory. It implements [ldap.Handler],
// embedding ldap.Unsupported so that only the read-only operations flapjak
// implements need to be defined here: everything else is declined with
// unwillingToPerform.
type Handler struct {
	ldap.Unsupported
	db *DB
}

// Bind authenticates against the password held in the entry named by the bind
// DN. An empty name and password is an anonymous bind, which is allowed.
func (h *Handler) Bind(_ context.Context, r *ldap.BindRequest) error {
	switch {
	case r.SASL():
		// flapjak authenticates against the password in an entry, so it
		// implements no SASL mechanism. This case must come first: a
		// SASL bind also has an empty Name and Password, and would
		// otherwise be mistaken for an anonymous one and succeed.
		return &ldap.Error{
			Code:       ldap.AuthMethodNotSupported,
			Diagnostic: r.Mechanism + " is not supported",
		}
	case r.Name == "" && r.Password == "":
		return nil // anonymous
	case r.Name == "":
		return &ldap.Error{Code: ldap.InvalidCredentials, Diagnostic: "missing username"}
	case r.Password == "":
		return &ldap.Error{Code: ldap.InvalidCredentials, Diagnostic: "missing password"}
	}

	bindDN, err := NewDN(r.Name)
	if err != nil {
		return fmt.Errorf("%w: %w",
			&ldap.Error{Code: ldap.InvalidDNSyntax, Diagnostic: "malformed bind DN"}, err)
	}

	node := h.db.DIT.Find(bindDN)
	if node == nil {
		// Do not distinguish an unknown DN from a bad password. The
		// cause rides behind the result so that the log can, since the
		// client is told only the result code.
		return fmt.Errorf("%w: %w", &ldap.Error{Code: ldap.InvalidCredentials}, errNoSuchEntry)
	}
	if err := node.Entry.Authenticate(r.Password); err != nil {
		return fmt.Errorf("%w: %w", &ldap.Error{Code: ldap.InvalidCredentials}, err)
	}
	return nil
}

// Search walks the directory information tree from the request's base DN and
// writes every entry matching the filter.
func (h *Handler) Search(ctx context.Context, r *ldap.SearchRequest, w *ldap.SearchResponse) error {
	baseDN, err := NewDN(r.BaseDN)
	if err != nil {
		return &ldap.Error{Code: ldap.InvalidDNSyntax, Diagnostic: "malformed base DN"}
	}

	base := h.db.DIT.Find(baseDN)
	if base == nil || (baseDN.IsEmpty() && r.Scope != ldap.BaseObject) {
		return &ldap.Error{Code: ldap.NoSuchObject, Diagnostic: "no such base object"}
	}

	// Refused rather than matched: see [HasExtensibleMatch].
	if HasExtensibleMatch(r.Filter) {
		return &ldap.Error{
			Code:       ldap.InappropriateMatching,
			Diagnostic: "extensible match requires a schema",
		}
	}

	var nodes iter.Seq[*DITNode]
	switch r.Scope {
	case ldap.BaseObject:
		nodes = base.Self()
	case ldap.SingleLevel:
		nodes = base.Children()
	case ldap.WholeSubtree:
		nodes = base.All()
	default:
		return &ldap.Error{Code: ldap.ProtocolError, Diagnostic: "unsupported search scope"}
	}

	// Each entry is a separate search response.
	// https://ldap.com/ldapv3-wire-protocol-reference-search/
	for node := range nodes {
		// Stop promptly if the search has been abandoned.
		if err := ctx.Err(); err != nil {
			return err
		}
		e := node.Entry
		view := e.View(r.Conn.BindDN)
		if !Match(r.Filter, view) {
			continue
		}

		if err := w.Entry(e.DN.String(), selectAttrs(view, r.Attributes)); err != nil {
			return err
		}
	}
	return nil
}

// WhoAmI reports the authorization identity of the connection, which for
// flapjak is simply the DN that was bound, if any.
func (h *Handler) WhoAmI(_ context.Context, r *ldap.WhoAmIRequest) (string, error) {
	if r.Conn.BindDN == "" {
		return "", nil // anonymous
	}
	return "dn:" + r.Conn.BindDN, nil
}

// selectAttrs returns the attributes of view that the request asked for. An
// empty request, or one asking for "*", returns every attribute the view
// allows; it withholds the sensitive ones.
//
// Values are returned with the types they hold; the ldap package encodes them.
// There is no need to handle the request's TypesOnly flag here, as the package
// strips values when it is set.
func selectAttrs(view EntryView, requested []string) map[string][]any {
	names := view.Names()
	if len(requested) > 0 && requested[0] != "*" {
		names = slices.Values(requested)
	}

	attrs := map[string][]any{}
	for name := range names {
		if a, ok := view.GetAttr(name); ok {
			attrs[a.Name] = a.Vals
		}
	}
	return attrs
}
