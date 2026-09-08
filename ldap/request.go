package ldap

import (
	"crypto/tls"
	"fmt"
	"math"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Scope is the scope of a search, from RFC 4511 section 4.5.1.2.
type Scope int

// Search scopes.
const (
	BaseObject   Scope = 0
	SingleLevel  Scope = 1
	WholeSubtree Scope = 2
)

// String returns the RFC 4511 name of the scope.
func (s Scope) String() string {
	switch s {
	case BaseObject:
		return "baseObject"
	case SingleLevel:
		return "singleLevel"
	case WholeSubtree:
		return "wholeSubtree"
	default:
		return fmt.Sprintf("Scope(%d)", int(s))
	}
}

// Deref says how aliases are dereferenced during a search, from RFC 4511
// section 4.5.1.3. This package does not dereference aliases; the value is
// reported so that a handler may act on it.
type Deref int

// Alias dereferencing options.
const (
	NeverDerefAliases   Deref = 0
	DerefInSearching    Deref = 1
	DerefFindingBaseObj Deref = 2
	DerefAlways         Deref = 3
)

// ConnInfo describes the connection a request arrived on. It is a snapshot
// taken when the request is dispatched, so it is safe to retain.
type ConnInfo struct {
	// RemoteAddr is the client address.
	RemoteAddr net.Addr
	// LocalAddr is the server address the client connected to.
	LocalAddr net.Addr
	// TLS is the state of the connection's TLS session, or nil if the
	// connection is not encrypted. Being nil is what "not a TLS
	// connection" means; there is no separate flag to disagree with it.
	//
	// It is set for both implicit LDAPS and a completed StartTLS, and the
	// handshake is finished before any request is dispatched, so
	// PeerCertificates is populated whenever the server asked for a client
	// certificate. That is what a handler needs to authenticate a SASL
	// EXTERNAL bind.
	TLS *tls.ConnectionState
	// BindDN is the DN of the last successful non-anonymous bind on this
	// connection, or empty if the connection is anonymous. For a SASL bind
	// it is the identity the handler recorded in [BindRequest.Name].
	BindDN string
}

// Request holds the fields common to every LDAP request.
type Request struct {
	// MessageID is the message ID the client used, which the response
	// must echo. It is handled by the package and is present for logging.
	MessageID int32
	// Controls are the controls attached to the request. Any control
	// marked critical is rejected before the handler is reached, so every
	// control here is non-critical and may be ignored.
	Controls []Control
	// Conn describes the connection the request arrived on.
	Conn ConnInfo
}

// BindRequest is a request to authenticate, from RFC 4511 section 4.2.
//
// Both authentication choices are decoded and it is left to the handler to
// decide what it accepts, as with every other operation. Mechanism selects
// which: it is empty for a simple bind, and otherwise names a SASL mechanism.
//
// A simple bind with an empty Name and Password is an anonymous bind.
//
// The mechanism worth implementing is EXTERNAL (RFC 4422 appendix A), which
// asks the server to authenticate the client by something the connection
// already established rather than by anything in the request. In practice that
// means a client certificate, which a handler reads from
// r.Conn.TLS.PeerCertificates. This is what "ldapsearch -Y EXTERNAL" sends.
//
// Multi-step SASL exchanges are not supported: a handler cannot return
// SASLBindInProgress usefully, because there is nowhere to put the server's
// challenge. EXTERNAL needs no exchange, so this does not limit it.
type BindRequest struct {
	Request
	// Version is the LDAP protocol version, which is 3 in practice.
	Version int
	// Name is the DN to authenticate as. A SASL bind carries no DN, so it
	// arrives empty; a handler that accepts one sets Name to the identity
	// it established, which becomes the connection's bound DN.
	Name string
	// Password is the simple-authentication password. It is empty unless
	// Mechanism is empty.
	Password string
	// Mechanism is the SASL mechanism, or empty for a simple bind.
	Mechanism string
	// Credentials is the mechanism-specific payload, which is absent for
	// EXTERNAL unless the client is requesting a specific authorization
	// identity.
	Credentials []byte
}

// SASL reports whether the bind uses SASL rather than simple authentication.
func (r *BindRequest) SASL() bool { return r.Mechanism != "" }

// UnbindRequest is a request to close the connection, from RFC 4511 section
// 4.3. It has no response; the server closes the connection after the handler
// returns.
type UnbindRequest struct {
	Request
}

// SearchRequest is a request to search the directory, from RFC 4511 section
// 4.5.1.
type SearchRequest struct {
	Request
	// BaseDN is the entry at which the search starts.
	BaseDN string
	// Scope is the portion of the tree to search relative to BaseDN.
	Scope Scope
	// DerefAliases says how aliases should be dereferenced.
	DerefAliases Deref
	// SizeLimit is the maximum number of entries to return, or 0 for no
	// limit. The package enforces it: [SearchResponse.Entry] refuses to
	// write past it.
	SizeLimit int
	// TimeLimit is the maximum duration of the search in seconds, or 0 for
	// no limit. The package enforces it by cancelling the context the
	// handler is given.
	TimeLimit int
	// TypesOnly requests attribute descriptions without values.
	TypesOnly bool
	// Filter is the decoded search filter.
	Filter Filter
	// Attributes is the list of attributes to return. Empty, or the single
	// entry "*", requests all user attributes.
	Attributes []string
}

// CompareRequest is a request to test whether an entry holds an attribute
// value, from RFC 4511 section 4.10.
type CompareRequest struct {
	Request
	// DN is the entry to compare against.
	DN string
	// Attribute and Value are the assertion to test.
	Attribute string
	Value     string
}

// WhoAmIRequest is a request for the authorization identity associated with
// the connection, from RFC 4532. It is carried as an extended operation on the
// wire; this package decodes the envelope and dispatches it as its own
// operation.
type WhoAmIRequest struct {
	Request
}

// decodeBind decodes a BindRequest.
func decodeBind(op *ber.Packet, req Request) (*BindRequest, error) {
	if len(op.Children) != 3 {
		return nil, fmt.Errorf("%w: bind has %d children", ErrMalformed, len(op.Children))
	}

	version, ok := op.Children[0].Value.(int64)
	if !ok {
		return nil, fmt.Errorf("%w: bind version is not an integer", ErrMalformed)
	}

	r := &BindRequest{
		Request: req,
		Version: int(version),
		Name:    content(op.Children[1]),
	}

	// AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
	//                                   sasl [3] SaslCredentials }
	auth := op.Children[2]
	if auth.ClassType != ber.ClassContext {
		return nil, fmt.Errorf("%w: bind authentication is not a choice", ErrMalformed)
	}
	switch auth.Tag {
	case tagAuthSimple:
		r.Password = content(auth)
	case tagAuthSASL:
		// SaslCredentials ::= SEQUENCE { mechanism LDAPString,
		//                                credentials OCTET STRING OPTIONAL }
		if len(auth.Children) == 0 {
			return nil, fmt.Errorf("%w: SASL credentials have no mechanism", ErrMalformed)
		}
		r.Mechanism = content(auth.Children[0])
		if r.Mechanism == "" {
			return nil, fmt.Errorf("%w: SASL mechanism is empty", ErrMalformed)
		}
		if len(auth.Children) > 1 {
			r.Credentials = []byte(content(auth.Children[1]))
		}
	default:
		return nil, fmt.Errorf("%w: bind authentication choice %d", ErrMalformed, auth.Tag)
	}

	return r, nil
}

// decodeSearch decodes a SearchRequest.
func decodeSearch(op *ber.Packet, req Request) (*SearchRequest, error) {
	const nfields = 8
	if len(op.Children) != nfields {
		return nil, fmt.Errorf("%w: search has %d children", ErrMalformed, len(op.Children))
	}

	scope, err := integer(op.Children[1], "scope")
	if err != nil {
		return nil, err
	}
	deref, err := integer(op.Children[2], "derefAliases")
	if err != nil {
		return nil, err
	}
	sizeLimit, err := limit(op.Children[3], "sizeLimit")
	if err != nil {
		return nil, err
	}
	timeLimit, err := limit(op.Children[4], "timeLimit")
	if err != nil {
		return nil, err
	}
	typesOnly, ok := op.Children[5].Value.(bool)
	if !ok {
		return nil, fmt.Errorf("%w: typesOnly is not a boolean", ErrMalformed)
	}
	filter, err := decodeFilter(op.Children[6])
	if err != nil {
		return nil, err
	}

	attrs := make([]string, 0, len(op.Children[7].Children))
	for _, a := range op.Children[7].Children {
		attrs = append(attrs, content(a))
	}

	return &SearchRequest{
		Request:      req,
		BaseDN:       content(op.Children[0]),
		Scope:        Scope(scope),
		DerefAliases: Deref(deref),
		SizeLimit:    sizeLimit,
		TimeLimit:    timeLimit,
		TypesOnly:    typesOnly,
		Filter:       filter,
		Attributes:   attrs,
	}, nil
}

// decodeCompare decodes a CompareRequest.
func decodeCompare(op *ber.Packet, req Request) (*CompareRequest, error) {
	if len(op.Children) != 2 {
		return nil, fmt.Errorf("%w: compare has %d children", ErrMalformed, len(op.Children))
	}
	attr, val, err := decodeAssertion(op.Children[1])
	if err != nil {
		return nil, err
	}
	return &CompareRequest{
		Request:   req,
		DN:        content(op.Children[0]),
		Attribute: attr,
		Value:     val,
	}, nil
}

// decodeAbandon decodes the message ID an AbandonRequest names.
//
// AbandonRequest is [APPLICATION 16] MessageID: a primitive application-class
// integer rather than a sequence, so go-asn1-ber does not parse its value and
// the integer must be read out of the content octets.
func decodeAbandon(op *ber.Packet) (int32, error) {
	id, err := ber.ParseInt64(op.Data.Bytes())
	if err != nil {
		return 0, fmt.Errorf("%w: abandon message ID: %w", ErrMalformed, err)
	}
	if id < 0 || id > math.MaxInt32 {
		return 0, fmt.Errorf("%w: abandon message ID %d out of range", ErrMalformed, id)
	}
	return int32(id), nil
}

// extendedRequest is the decoded ExtendedRequest envelope. The OID selects the
// operation; the value is interpreted per extension.
type extendedRequest struct {
	oid   string
	value []byte
}

// decodeExtended decodes an ExtendedRequest envelope.
func decodeExtended(op *ber.Packet) (extendedRequest, error) {
	var e extendedRequest
	if len(op.Children) == 0 {
		return e, fmt.Errorf("%w: extended request is empty", ErrMalformed)
	}
	for _, child := range op.Children {
		switch child.Tag {
		case tagRequestName:
			e.oid = content(child)
		case tagRequestValue:
			e.value = []byte(content(child))
		}
	}
	if e.oid == "" {
		return e, fmt.Errorf("%w: extended request has no name", ErrMalformed)
	}
	return e, nil
}

// integer reads a universal INTEGER or ENUMERATED value.
func integer(p *ber.Packet, name string) (int64, error) {
	v, ok := p.Value.(int64)
	if !ok {
		return 0, fmt.Errorf("%w: %s is not an integer", ErrMalformed, name)
	}
	return v, nil
}

// limit decodes a search limit, which RFC 4511 section 4.5.1 bounds to
// 0..maxInt. The bound is worth enforcing rather than clamping: a time limit
// past it overflows the duration it becomes, leaving the search with a context
// that has already expired, and a negative size limit reads as no limit at
// all.
func limit(p *ber.Packet, name string) (int, error) {
	v, err := integer(p, name)
	if err != nil {
		return 0, err
	}
	if v < 0 || v > math.MaxInt32 {
		return 0, fmt.Errorf("%w: %s %d out of range", ErrMalformed, name, v)
	}
	return int(v), nil
}
