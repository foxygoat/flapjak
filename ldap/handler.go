package ldap

import "context"

// Handler serves LDAP operations. There is one method per protocol operation,
// each taking the request type for that operation.
//
// The returned error is the result sent to the client. Returning nil means
// success. Returning an [Error], or an error wrapping one, sends that result
// code and diagnostic. Any other error is logged in full and reported to the
// client as OperationsError with a generic diagnostic, so that internal detail
// is not disclosed.
//
// Embed [Unsupported] to decline the operations you do not implement.
//
// Abandon is absent: it is handled by the package, which cancels the context
// of the operation being abandoned. Handlers observe an abandon through that
// context, and no response is sent for an abandoned operation.
//
// StartTLS is absent for the same reason: it is a property of the connection
// rather than of the directory.
//
// The write operations - Add, Delete, Modify and ModifyDN - are absent because
// this package does not decode them. The server answers all four with
// unwillingToPerform.
//
// One Handler serves every connection, and Search and Compare each run on their
// own goroutine, so a Handler must be safe for concurrent use.
//
// Bind, Unbind and WhoAmI instead run on the connection's read loop, because
// each of them reads or changes the state of that connection. They are not
// abandonable, and while one is running no further message on that connection
// is read, so a slow implementation stalls the client it belongs to. Keep them
// quick, or do the slow part before the handler is reached.
type Handler interface {
	// Bind authenticates the connection. A simple bind with an empty Name
	// and Password is an anonymous bind. Returning nil records the bind as
	// successful and associates r.Name with the connection.
	//
	// SASL binds arrive here too, with r.Mechanism naming the mechanism, so
	// that a handler can authenticate a client by its certificate. Decline
	// the mechanisms you do not implement with AuthMethodNotSupported.
	//
	// A SASL bind carries no DN, so a handler that accepts one sets r.Name
	// to the identity it established; otherwise the connection stays
	// anonymous.
	Bind(ctx context.Context, r *BindRequest) error

	// Unbind notifies the handler that the client is disconnecting. It has
	// no response; the connection is closed once it returns.
	//
	// Searches and compares already running are still running. They are
	// cancelled by the connection closing, which happens after this
	// returns, and Unbind does not wait for them to drain the way Bind
	// does. A handler that releases per-connection resources here must
	// expect its own Search to still be holding them.
	Unbind(ctx context.Context, r *UnbindRequest)

	// Search searches the directory, writing matching entries to w. The
	// returned error becomes the search result, so returning nil after
	// writing entries completes the search successfully.
	//
	// The request's size and time limits are enforced by the package, but
	// only a handler can stop the work: return the error w gives you rather
	// than continuing past it, and watch ctx while searching.
	Search(ctx context.Context, r *SearchRequest, w *SearchResponse) error

	// Compare reports whether the entry r.DN holds the attribute value
	// r.Value. The package turns the answer into the result code the
	// client is owed. A non-nil error is the result instead, and the bool
	// is then ignored.
	Compare(ctx context.Context, r *CompareRequest) (bool, error)

	// WhoAmI returns the authorization identity of the connection, as
	// defined by RFC 4532. The conventional form is "dn:" followed by the
	// bound DN, or the empty string for an anonymous connection. The bound
	// DN is available as r.Conn.BindDN.
	WhoAmI(ctx context.Context, r *WhoAmIRequest) (string, error)
}

// Unsupported implements [Handler] by declining every operation with
// UnwillingToPerform. Embed it in a handler and override the operations that
// are served:
//
//	type myHandler struct {
//		ldap.Unsupported
//		db *DB
//	}
//
//	func (h *myHandler) Search(ctx context.Context, r *ldap.SearchRequest, w *ldap.SearchResponse) error {
//		...
//	}
//
// Embedding it also means a handler keeps compiling when an operation is added
// to [Handler].
type Unsupported struct{}

var _ Handler = Unsupported{}

func unsupported(op string) error {
	return &Error{Code: UnwillingToPerform, Diagnostic: op + " is not supported"}
}

// Bind declines the bind, which rejects every client including anonymous ones.
// A SASL bind is declined with AuthMethodNotSupported, which tells the client
// the mechanism is the problem rather than the credentials.
func (Unsupported) Bind(_ context.Context, r *BindRequest) error {
	if r.SASL() {
		return &Error{
			Code:       AuthMethodNotSupported,
			Diagnostic: r.Mechanism + " is not supported",
		}
	}
	return unsupported("bind")
}

// Unbind does nothing.
func (Unsupported) Unbind(context.Context, *UnbindRequest) {}

// Search declines the search.
func (Unsupported) Search(context.Context, *SearchRequest, *SearchResponse) error {
	return unsupported("search")
}

// Compare declines the comparison.
func (Unsupported) Compare(context.Context, *CompareRequest) (bool, error) {
	return false, unsupported("compare")
}

// WhoAmI declines the request.
func (Unsupported) WhoAmI(context.Context, *WhoAmIRequest) (string, error) {
	return "", unsupported("whoami")
}
