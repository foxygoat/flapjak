package main

import (
	"crypto/tls"
	"iter"
	"log/slog"
	"maps"
	"slices"

	"github.com/jimlambrt/gldap"
)

// Server is a flapjak server that serves LDAP requests using a database. It
// can serve the LDAP bind and search operations only, operating as a read-only
// LDAP server,
type Server struct {
	ldap      *gldap.Server
	db        *DB
	tlsConfig *tls.Config
}

// Option is a functional option that may be passed to NewServer to configure
// optional features of the server.
type Option func(*Server)

// NewServer returns a Server ready to serve db.
func NewServer(db *DB, options ...Option) *Server {
	ls, _ := gldap.NewServer() //nolint:errcheck,gosec // cannot error
	s := &Server{
		ldap: ls,
		db:   db,
	}

	for _, fnopt := range options {
		fnopt(s)
	}

	m, _ := gldap.NewMux()   //nolint:errcheck,gosec // cannot error
	m.Bind(s.handleBind)     //nolint:errcheck,gosec // cannot error
	m.Search(s.handleSearch) //nolint:errcheck,gosec // cannot error
	if s.tlsConfig != nil {
		m.ExtendedOperation(s.handleStartTLS, gldap.ExtendedOperationStartTLS)
	}

	ls.Router(m) //nolint:errcheck,gosec // cannot error

	return s
}

// WithTLSConfig is a functional option to configure TLS parameters for the
// server connection. It is safe to pass a nil pointer as the config, which
// will disable TLS. The TLS config may configure client and server TLS.
func WithTLSConfig(c *tls.Config) Option {
	return func(s *Server) {
		s.tlsConfig = c
	}
}

// Run starts the server listening on the given listen address
func (s *Server) Run(listen string) error {
	slog.Info("Server listening", "address", listen, "tls", s.tlsConfig != nil)
	return s.ldap.Run(listen, gldap.WithTLSConfig(s.tlsConfig))
}

func (s *Server) handleStartTLS(w *gldap.ResponseWriter, r *gldap.Request) {
	slog.Info("handleStartTLS", "tls", s.tlsConfig != nil)
	if s.tlsConfig != nil {
		r.StartTLS(s.tlsConfig)
	}
}

func (s *Server) handleBind(w *gldap.ResponseWriter, r *gldap.Request) {
	// Set the default response to InvalidCredentials, so we only
	// return success if explicitly overridden.
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer w.Write(resp) //nolint:errcheck // not much to do if it fails

	m, err := r.GetSimpleBindMessage()
	if err != nil {
		slog.Error("Bind with non-bind message", "error", err.Error())
		return
	}

	switch {
	case m.UserName == "" && m.Password == "":
		slog.Info("anonymous bind")
	case m.UserName != "" && m.Password != "":
		bindDN, err := NewDN(m.UserName)
		if err != nil {
			slog.Error("bind with invalid DN", "error", err.Error(), "username", m.UserName)
			return
		}
		node := s.db.DIT.Find(bindDN)
		if node == nil {
			slog.Error("bind with unknown DN", "username", m.UserName)
			return
		}
		err = node.Entry.Authenticate(string(m.Password))
		if err != nil {
			slog.Error("bind failed", "username", m.UserName, "error", err)
			return
		}
		slog.Info("simple bind", "username", m.UserName)
	case m.UserName == "":
		slog.Error("invalid bind: missing username")
		return
	case m.Password == "":
		slog.Error("invalid bind: missing password")
		return
	}
	// Override InvalidCredentials set above.
	resp.SetResultCode(gldap.ResultSuccess)
}

func (s *Server) handleSearch(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewSearchDoneResponse()
	defer w.Write(resp) //nolint:errcheck // not much to do if it fails

	req, err := r.GetSearchMessage()
	if err != nil {
		slog.Error("Search with non-search message", "error", err.Error())
		return
	}
	slog.Info("Search request", "baseDN", req.BaseDN, "scope", req.Scope, "filter", req.Filter)

	baseDN, err := NewDN(req.BaseDN)
	if err != nil {
		slog.Error("Search with invalid DN", "error", err.Error(), "dn", req.BaseDN)
		resp.SetResultCode(gldap.ResultInvalidDNSyntax)
		return
	}
	base := s.db.DIT.Find(baseDN)
	if base == nil || (baseDN.IsEmpty() && req.Scope != gldap.BaseObject) {
		slog.Error("basedn not found", "method", "search", "basedn", baseDN.String())
		resp.SetResultCode(gldap.ResultNoSuchObject)
		return
	}

	f, err := Parse(req.Filter)
	if err != nil {
		slog.Error("invalid filter", "filter", req.Filter, "error", err)
		resp.SetResultCode(gldap.ResultFilterError)
		return
	}

	var nodeIter iter.Seq[*DITNode]

	switch req.Scope {
	case gldap.BaseObject:
		nodeIter = base.Self()
	case gldap.SingleLevel:
		nodeIter = base.Children()
	case gldap.WholeSubtree:
		nodeIter = base.All()
	default:
		slog.Error("unsupported scope", "scope", req.Scope)
		resp.SetResultCode(gldap.ResultNotSupported)
		return
	}

	// Each entry is a separate search response
	// https://ldap.com/ldapv3-wire-protocol-reference-search/
	for node := range nodeIter {
		e := node.Entry
		if !f.Match(e) {
			continue
		}
		// TODO: filter entries, attributes and values based on permissions.

		attrs := maps.Keys(e.Attrs)
		if len(req.Attributes) > 0 && req.Attributes[0] != "*" {
			attrs = slices.Values(req.Attributes)
		}
		attrMap := map[string][]string{}
		for attrName := range attrs {
			if a, ok := e.GetAttr(attrName); ok {
				if !a.IsSensitive() {
					attrMap[a.Name] = If(req.TypesOnly, nil, a.Vals)
				}
			}
		}

		re := r.NewSearchResponseEntry(e.DN.String(), gldap.WithAttributes(attrMap))
		if err := w.Write(re); err != nil {
			slog.Error("Failed to write search response", "error", err.Error())
			return
		}
	}

	resp.SetResultCode(gldap.ResultSuccess)
}

// If is a simple ternary operator function that returns ifTrue if cond is true
// and ifFalse if it is not. It is intended to be used only with values that
// have no side-effects as both ifTrue and ifFalse are evaluated before being
// passed to this function. It should really only be used to select between
// two variables or values.
func If[T any](cond bool, ifTrue T, ifFalse T) T {
	if cond {
		return ifTrue
	}
	return ifFalse
}
