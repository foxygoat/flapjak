package main

import (
	"fmt"
	"iter"
	"log/slog"

	"github.com/jimlambrt/gldap"
)

type Server struct {
	ldap *gldap.Server
	db   *DB
}

func NewServer(db *DB) (*Server, error) {
	ls, err := gldap.NewServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create server: %w", err)
	}

	m, err := gldap.NewMux()
	if err != nil {
		return nil, fmt.Errorf("failed to create mux: %w", err)
	}

	s := &Server{
		ldap: ls,
		db:   db,
	}

	m.Bind(s.handleBind)     //nolint:errcheck,gosec // cannot error
	m.Search(s.handleSearch) //nolint:errcheck,gosec // cannot error
	ls.Router(m)             //nolint:errcheck,gosec // cannot error

	return s, nil
}

func (s *Server) Run(listen string) error {
	slog.Info("Server listening", "address", listen)
	return s.ldap.Run(listen)
}

func (s *Server) handleBind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer w.Write(resp) //nolint:errcheck // not much to do if it fails

	m, err := r.GetSimpleBindMessage()
	if err != nil {
		slog.Error("Bind with non-bind message", "error", err.Error())
		return
	}

	if m.UserName == "" && m.Password == "" {
		slog.Info("anonymous bind")
	} else if m.UserName != "" && m.Password != "" {
		slog.Info("simple bind", "username", m.UserName, "password", m.Password)
	} else {
		slog.Error("invalid bind")
		return
	}
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

	baseDN := NewDN(req.BaseDN)
	base := s.db.DIT.Find(baseDN)
	if base == nil || (base.Entry.DN.IsRoot() && req.Scope != gldap.BaseObject) {
		slog.Error("basedn not found", "method", "search", "basedn", baseDN.String())
		resp.SetResultCode(gldap.ResultNoSuchObject)
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
	}

	// Each entry is a separate search response
	// https://ldap.com/ldapv3-wire-protocol-reference-search/
	for node := range nodeIter {
		e := node.Entry
		if !filterMatches(req.Filter, e) {
			continue
		}
		// TODO: filter attributes based in req.Attributes,
		// filter attribute values based on req.TypesOnly,
		// filter entrires, attributes and values based on permissions.

		re := r.NewSearchResponseEntry(e.DN.String(), gldap.WithAttributes(e.Attrs))
		if err := w.Write(re); err != nil {
			slog.Error("Failed to write search response", "error", err.Error())
			return
		}
	}

	resp.SetResultCode(gldap.ResultSuccess)
}

func filterMatches(filter string, entry *Entry) bool {
	return true
}
