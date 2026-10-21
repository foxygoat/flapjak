package ldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

// Extended operation OIDs. StartTLS and Who Am I are the extensions this
// package understands; Notice of Disconnection is the unsolicited response it
// sends before dropping a connection it cannot continue.
const (
	oidStartTLS              = "1.3.6.1.4.1.1466.20037"
	oidWhoAmI                = "1.3.6.1.4.1.4203.1.11.3"
	oidNoticeOfDisconnection = "1.3.6.1.4.1.1466.20036"
)

// tlsHandshakeTimeout bounds a TLS handshake when [Server.IdleTimeout] is
// unset. A handshake precedes every operation on the connection, so nothing
// else bounds it: a peer that opens one and then stops speaking would hold the
// read loop for the life of the process. It is a variable so that a test need
// not wait it out.
var tlsHandshakeTimeout = 30 * time.Second

// timeLimitUnit is the unit of a search request's time limit, which RFC 4511
// expresses in whole seconds. It is a variable so that a test need not wait one
// out.
var timeLimitUnit = time.Second

// errClose asks the read loop to close the connection without reporting an
// error. It is never returned to a caller outside this file.
var errClose = errors.New("close connection")

// errTimeLimit is the cause given when a search's context is cancelled because
// the request's time limit expired, which is what tells it apart from an
// abandon.
var errTimeLimit = errors.New("search time limit exceeded")

// beforeBindWait is called just before a bind waits for the connection's
// outstanding operations, so that a test can tell when one has reached that
// point. Nothing else marks it, and the wait is where a bind meets a shutdown.
// It is nil outside tests.
var beforeBindWait func()

// transport is a connection's I/O, replaced wholesale by StartTLS so that a
// reader never sees a half-upgraded mixture. A nil state means it is plaintext.
type transport struct {
	conn  net.Conn
	rdr   *bufio.Reader
	state *tls.ConnectionState
}

// conn serves one client connection.
//
// The read loop is the only reader. Search and compare, the two that can be
// abandoned, run on their own goroutines; everything else - bind, unbind,
// abandon, StartTLS and WhoAmI - runs inline on the read loop, which is what
// keeps the locking down to opsMu and writeMu.
type conn struct {
	// The server's settings, taken when the connection was accepted so
	// that they cannot change under a connection already being served.
	handler      Handler
	tlsConfig    *tls.Config
	log          *slog.Logger
	idleTimeout  time.Duration
	writeTimeout time.Duration

	// raw is the connection as accepted. close uses it rather than the
	// transport: it is reached from the shutdown goroutine, and closing the
	// socket cannot block on a TLS close_notify.
	raw net.Conn

	remote net.Addr
	local  net.Addr

	// transport is replaced by StartTLS. Only the read loop replaces it,
	// and writeMu guards the replacement against the operation goroutines,
	// which reach it through writeLocked. See [conn.doStartTLS].
	transport *transport

	// writeMu serialises writes: message IDs interleave on the wire. It
	// also guards transport; see above.
	writeMu sync.Mutex

	// opsMu guards ops, pending and draining together, so that "is this
	// the last operation?" and "is anything outstanding?" cannot both be
	// true.
	//
	// ops holds what an Abandon can reach and what a message ID check must
	// see, so an operation leaves it before writing its response. pending
	// counts operations that have not finished writing, which is what a
	// draining connection has to wait for.
	opsMu    sync.Mutex
	ops      map[int32]context.CancelFunc
	pending  int
	draining bool

	// bindDN is the last successful non-anonymous bind.
	bindDN string

	// ctx is cancelled by close, which cancels every operation on the
	// connection with it.
	ctx    context.Context //nolint:containedctx // scoped to the connection
	cancel context.CancelFunc

	wg sync.WaitGroup
}

func newConn(ctx context.Context, srv *Server, nc net.Conn) *conn {
	ctx, cancel := context.WithCancel(ctx)
	return &conn{
		ctx:          ctx,
		cancel:       cancel,
		handler:      srv.Handler,
		tlsConfig:    srv.TLSConfig,
		log:          srv.logger().With("remote", nc.RemoteAddr().String()),
		idleTimeout:  srv.IdleTimeout,
		writeTimeout: srv.WriteTimeout,
		raw:          nc,
		remote:       nc.RemoteAddr(),
		local:        nc.LocalAddr(),
		transport:    &transport{conn: nc, rdr: bufio.NewReader(nc)},
		ops:          map[int32]context.CancelFunc{},
	}
}

// serve reads and dispatches messages until the connection ends.
func (c *conn) serve() {
	defer func() {
		// Close before waiting, so an operation blocked writing fails
		// fast rather than holding the connection open.
		c.close()
		c.wg.Wait()
	}()

	if err := c.handshake(c.ctx); err != nil {
		c.log.Warn("connection rejected", "error", err)
		return
	}

	c.log.Debug("connection opened", "tls", c.transport.state != nil)

	for {
		if c.idleTimeout > 0 {
			_ = c.transport.conn.SetReadDeadline(time.Now().Add(c.idleTimeout))
		}

		msg, err := readMessage(c.transport.rdr)
		if err != nil {
			c.readError(err)
			return
		}

		if err := c.dispatch(c.ctx, msg); err != nil {
			if !errors.Is(err, errClose) {
				c.log.Debug("connection ending", "error", err)
			}
			return
		}
	}
}

// handshake completes the TLS handshake on a connection that arrived on a TLS
// listener, so that the peer's certificates and cipher are known before the
// first operation rather than after the first read.
//
// A caller may wrap a listener with tls.NewListener and pass it to Serve rather
// than ServeTLS, so this looks at the connection rather than at how it was
// served.
func (c *conn) handshake(ctx context.Context) error {
	tc, ok := c.transport.conn.(*tls.Conn)
	if !ok {
		return nil // not encrypted
	}

	ctx, cancel := c.handshakeContext(ctx)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}

	state := tc.ConnectionState()
	c.transport = &transport{conn: c.transport.conn, rdr: c.transport.rdr, state: &state}
	return nil
}

// handshakeContext bounds a TLS handshake. IdleTimeout is what a caller has to
// say how long a quiet peer may hold a connection, so it applies here too; with
// none set the handshake still gets a bound of its own.
func (c *conn) handshakeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := c.idleTimeout
	if timeout <= 0 {
		timeout = tlsHandshakeTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

// readError logs why the read loop stopped and tells the client when the fault
// was theirs.
func (c *conn) readError(err error) {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		c.log.Debug("connection closed by peer")
	case errors.Is(err, net.ErrClosed), c.ctx.Err() != nil:
		c.log.Debug("connection closed by server")
	case errors.Is(err, os.ErrDeadlineExceeded):
		c.log.Debug("connection idle timeout")
	default:
		c.log.Warn("malformed message", "error", err)
		c.disconnect(ProtocolError, "malformed message")
	}
}

// disconnect sends an unsolicited Notice of Disconnection, which tells the
// client why the connection is about to go away. Errors are ignored: the
// connection is being closed regardless.
func (c *conn) disconnect(code Code, diagnostic string) {
	msg := encodeMessage(0, encodeExtendedResponse(code, diagnostic, oidNoticeOfDisconnection, nil))
	_ = c.write(msg)
}

// dispatch handles one message. A non-nil return ends the connection.
func (c *conn) dispatch(ctx context.Context, msg *message) error {
	// Unbind and Abandon take no response, so they run before the checks
	// that could reject them: there would be no way to report a rejection.
	// Neither reads the envelope's message ID either, so the rules on it
	// below cost them nothing - an Abandon refused over its own ID would
	// simply lose its effect.
	switch msg.op.Tag {
	case tagUnbindRequest:
		_ = c.callHandler("unbind", func() error {
			c.handler.Unbind(ctx, &UnbindRequest{Request: c.request(msg)})
			return nil
		})
		return errClose
	case tagAbandonRequest:
		c.doAbandon(msg)
		return nil
	}

	// RFC 4511 section 4.1.1.1 governs a request's message ID. Both of its
	// rules are checked only for operations that take a response, because
	// both exist to keep responses unambiguous; an unknown tag is dealt
	// with by the switch below.
	//
	// ID 0 is the unsolicited notification's, so it cannot be refused in a
	// response - one echoing it would read as a notification - which
	// leaves the Notice of Disconnection of section 4.1.1.
	//
	// This comes before every other check, draining included: a response
	// is how the rest of them report, and an ID that cannot carry one
	// makes any of those responses unreadable.
	if _, hasResponse := responseTags[msg.op.Tag]; hasResponse {
		switch {
		case msg.id == 0:
			c.log.Warn("request with reserved message ID 0", "op", msg.opName())
			c.disconnect(ProtocolError, "message ID 0 is reserved")
			return errClose
		case c.inProgress(msg.id):
			c.log.Warn("message ID already in progress", "id", msg.id, "op", msg.opName())
			return c.respond(msg, &Error{
				Code:       ProtocolError,
				Diagnostic: "message ID already in progress",
			})
		}
	}

	if c.isDraining() {
		return c.respond(msg, &Error{Code: Unavailable, Diagnostic: "server is shutting down"})
	}

	if err := checkControls(msg.controls); err != nil {
		return c.respond(msg, err)
	}

	switch msg.op.Tag {
	case tagBindRequest:
		return c.doBind(ctx, msg)
	case tagExtendedRequest:
		return c.doExtended(ctx, msg)
	case tagSearchRequest, tagCompareRequest:
		return c.start(ctx, msg)
	case tagAddRequest, tagDelRequest, tagModifyRequest, tagModifyDNRequest:
		// Write operations are not decoded, so there is nothing a
		// handler could act on. See [Handler].
		return c.respond(msg, &Error{
			Code:       UnwillingToPerform,
			Diagnostic: "operation not supported",
		})
	default:
		c.log.Warn("unknown protocol operation", "tag", uint64(msg.op.Tag))
		c.disconnect(ProtocolError, "unknown protocol operation")
		return errClose
	}
}

// start runs an abandonable operation on its own goroutine, registering its
// cancellation against the message ID so that an Abandon can reach it.
//
// The ID is free: [conn.dispatch] refuses a request carrying one already in
// progress, and the read loop both checks and records, so nothing can claim
// the ID in between. The registry depends on that, since a second operation
// under a live ID would displace the first, leaving it unabandonable and its
// entry to be removed by whichever finished first.
func (c *conn) start(ctx context.Context, msg *message) error {
	// The request snapshot is taken here, on the read loop, so that the
	// operation goroutine does not read connection state concurrently.
	req := c.request(msg)

	opCtx, cancel := context.WithCancel(ctx)
	c.opsMu.Lock()
	c.ops[msg.id] = cancel
	c.pending++
	c.opsMu.Unlock()

	c.wg.Go(func() {
		defer cancel()
		err := c.invoke(opCtx, msg, req)
		c.finish(opCtx, msg, err)
	})
	return nil
}

// finish concludes an abandonable operation: it releases the message ID and
// sends the result the client is owed.
//
// The ID is released first, because the client may reuse it the moment the
// response reaches it. RFC 4511 section 4.1.1.1 allows that as soon as the
// operation using the ID has completed, so releasing it after the write would
// leave a window - the write reaching the client, but the entry not yet gone -
// in which a legal reuse is refused as already in progress.
//
// Nothing else waits on the entry: an Abandon that misses it by this much has
// nothing left to cancel, and the transport is guarded by writeMu rather than
// by the registry. See [conn.doStartTLS].
//
// pending is what a draining connection waits for, and it is released after
// the write rather than with the ID. Releasing both together would let a
// shutdown find the connection idle while this response is still in flight,
// close it, and leave the client with no result at all.
func (c *conn) finish(ctx context.Context, msg *message, err error) {
	c.opsMu.Lock()
	delete(c.ops, msg.id)
	c.opsMu.Unlock()

	// An abandoned operation gets no response at all. Encoded before the
	// write, so that building it and logging its cause stay outside
	// writeMu.
	var response []byte
	if ctx.Err() != nil {
		c.log.Debug("operation abandoned", "op", msg.opName(), "id", msg.id)
	} else {
		response = c.encodeResponse(msg, err)
	}

	c.writeAndRelease(response)
	c.closeIfDrained()
}

// writeAndRelease writes an operation's response, if it has one, and releases
// its hold on pending.
//
// Both happen under one hold of writeMu, which is what makes the release
// simultaneous with the write as far as any other goroutine can tell. Doing
// them separately let a StartTLS, which holds writeMu across its own check,
// observe a response that had already reached the client while it was still
// counted, and refuse the upgrade as having operations outstanding.
func (c *conn) writeAndRelease(response []byte) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if response != nil {
		if err := c.writeLocked(response); err != nil {
			c.log.Debug("failed to write response", "error", err)
		}
	}

	c.opsMu.Lock()
	defer c.opsMu.Unlock()
	c.pending--
}

// closeIfDrained closes the connection once it is draining with nothing left
// in flight. It is the only place that decides a draining connection is done:
// a shutdown reaches it having found the connection already quiet, and an
// operation reaches it having been the last one holding it open.
func (c *conn) closeIfDrained() {
	c.opsMu.Lock()
	drained := c.draining && c.pending == 0
	c.opsMu.Unlock()

	if drained {
		c.close()
	}
}

// errHandlerPanic is what a recovered panic becomes. It carries no detail of
// its own: [result] reports it as operationsError with a generic diagnostic,
// and the panic is logged where an operator can see it.
var errHandlerPanic = errors.New("handler panicked")

// callHandler calls fn, turning a panic into an error rather than letting it
// take the process down. A handler is code this package does not own, and one
// bad entry should cost a client its operation rather than cost every client
// the server; net/http takes the same view of its own handlers.
//
// Only the handler call is covered. A panic anywhere else in this package is a
// bug in it, and the state of the connection after one is not knowable.
func (c *conn) callHandler(op string, fn func() error) (err error) {
	defer func() {
		p := recover()
		if p == nil {
			return
		}
		c.log.Error("handler panicked", "op", op, "panic", p, "stack", string(debug.Stack()))
		err = errHandlerPanic
	}()
	return fn()
}

// invoke decodes an operation and calls the handler.
func (c *conn) invoke(ctx context.Context, msg *message, req Request) error {
	switch msg.op.Tag {
	case tagSearchRequest:
		r, err := decodeSearch(msg.op, req)
		if err != nil {
			return err
		}
		c.log.Info("search",
			"base", r.BaseDN, "scope", r.Scope, "filter", r.Filter, "attrs", r.Attributes)

		// The time limit cancels the context the handler is given, and
		// with it the one w refuses to write on. Its cause is what
		// tells the expiry apart from an abandon, which ends the
		// operation with no response at all.
		if r.TimeLimit > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeoutCause(ctx,
				time.Duration(r.TimeLimit)*timeLimitUnit, errTimeLimit)
			defer cancel()
		}

		w := &SearchResponse{conn: c, ctx: ctx, id: msg.id, typesOnly: r.TypesOnly, sizeLimit: r.SizeLimit}
		return searchResult(ctx, c.callHandler("search", func() error {
			return c.handler.Search(ctx, r, w)
		}))

	case tagCompareRequest:
		r, err := decodeCompare(msg.op, req)
		if err != nil {
			return err
		}
		var match bool
		err = c.callHandler("compare", func() error {
			var err error
			match, err = c.handler.Compare(ctx, r)
			return err
		})
		if err != nil {
			return err
		}
		// RFC 4511 section 4.10 carries both answers as result codes.
		if match {
			return &Error{Code: compareTrue}
		}
		return &Error{Code: compareFalse}

	default:
		return fmt.Errorf("%w: tag %d", ErrUnknownOp, msg.op.Tag)
	}
}

// searchResult turns what a search handler returned into the result the client
// is owed, reporting a limit the package enforced rather than the refusal it
// surfaced as. A handler that returns nil despite an expired limit finishes
// successfully: the entries were all written, so the search did complete.
func searchResult(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, errSizeLimit):
		return &Error{Code: SizeLimitExceeded}
	case err != nil && errors.Is(context.Cause(ctx), errTimeLimit):
		return &Error{Code: TimeLimitExceeded}
	}
	return err
}

// doBind authenticates the connection.
//
// RFC 4511 section 4.2.1 requires that outstanding operations complete before
// a bind is processed, since a bind changes the authorization state that those
// operations were started under. Waiting here is safe because only the read
// loop adds operations, and the read loop is what is waiting.
func (c *conn) doBind(ctx context.Context, msg *message) error {
	if beforeBindWait != nil {
		beforeBindWait()
	}
	c.wg.Wait()

	// The wait may have outlasted the connection: a shutdown that began
	// while those operations ran closes it as the last one finishes.
	if c.ctx.Err() != nil {
		return errClose
	}

	r, err := decodeBind(msg.op, c.request(msg))
	if err != nil {
		return c.respond(msg, err)
	}

	err = c.callHandler("bind", func() error { return c.handler.Bind(ctx, r) })
	if err != nil {
		// A failed bind leaves the connection anonymous, per RFC 4511
		// section 4.2.1.
		c.bindDN = ""
		c.log.Info("bind failed", "dn", r.Name, "error", err)
		return c.respond(msg, err)
	}

	// A SASL bind carries no DN in the request, so the identity it
	// established is whatever the handler recorded.
	c.bindDN = r.Name
	c.log.Info("bind", "dn", r.Name, "mechanism", r.Mechanism, "anonymous", r.Name == "" && !r.SASL())
	return c.respond(msg, nil)
}

// doAbandon cancels the operation the request names. Abandon has no response
// in either the success or the failure case, so errors are only logged.
func (c *conn) doAbandon(msg *message) {
	id, err := decodeAbandon(msg.op)
	if err != nil {
		c.log.Debug("malformed abandon request", "error", err)
		return
	}

	c.opsMu.Lock()
	cancel, ok := c.ops[id]
	c.opsMu.Unlock()

	if !ok {
		// The operation has already finished, which is not an error:
		// the client could not have known.
		c.log.Debug("abandon for unknown operation", "id", id)
		return
	}
	c.log.Debug("abandon", "id", id)
	cancel()
}

// doExtended dispatches an extended operation on its OID.
func (c *conn) doExtended(ctx context.Context, msg *message) error {
	e, err := decodeExtended(msg.op)
	if err != nil {
		return c.respond(msg, err)
	}

	switch e.oid {
	case oidStartTLS:
		return c.doStartTLS(ctx, msg)

	case oidWhoAmI:
		var authzID string
		err := c.callHandler("whoami", func() error {
			var err error
			authzID, err = c.handler.WhoAmI(ctx, &WhoAmIRequest{Request: c.request(msg)})
			return err
		})
		if err != nil {
			return c.respond(msg, err)
		}
		return c.write(encodeMessage(msg.id, encodeExtendedResponse(Success, "", "", []byte(authzID))))

	default:
		c.log.Info("unrecognised extended operation", "oid", e.oid)
		return c.write(encodeMessage(msg.id,
			encodeExtendedResponse(ProtocolError, "unrecognised extended operation", "", nil)))
	}
}

// doStartTLS upgrades the connection to TLS in place.
//
// writeMu is held from before the success response through to the transport
// being replaced, which does two jobs. It stops an operation goroutine writing
// in between, which would drop a cleartext response into the middle of the
// client's handshake. And it is what makes replacing the transport safe:
// writeLocked is its only cross-goroutine reader, so a straggling write lands
// wholly before or wholly after the swap rather than across it.
//
// The outstanding check below cannot do that job. It is the RFC 4513 rule
// about when an upgrade is allowed, and it is read before the swap rather than
// held across it, so writeMu remains the memory guard.
func (c *conn) doStartTLS(ctx context.Context, msg *message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	reply := func(code Code, diagnostic string) error {
		return c.writeLocked(encodeMessage(msg.id,
			encodeExtendedResponse(code, diagnostic, oidStartTLS, nil)))
	}

	switch {
	case c.tlsConfig == nil:
		return reply(ProtocolError, "TLS is not configured")
	case c.transport.state != nil:
		// RFC 4513 section 3.1.1.
		return reply(OperationsError, "TLS is already established")
	case c.outstanding() > 0:
		return reply(OperationsError, "operations are outstanding")
	}

	// RFC 4511 4.14.1: the client sends nothing further until the handshake
	// completes. Anything buffered arrived early, and tls.Server reads the
	// socket rather than the reader, so it would be dropped rather than
	// protected. Pipelining is legal in general, which is why this is only
	// checked once an upgrade is certain.
	if c.transport.rdr.Buffered() > 0 {
		_ = reply(ProtocolError, "unexpected data before TLS handshake")
		return errClose
	}

	// The success response is sent in the clear; the handshake follows it
	// immediately on the same transport.
	if err := reply(Success, ""); err != nil {
		return err
	}

	tlsconn := tls.Server(c.transport.conn, c.tlsConfig)
	hsCtx, cancel := c.handshakeContext(ctx)
	defer cancel()
	if err := tlsconn.HandshakeContext(hsCtx); err != nil {
		c.log.Warn("StartTLS handshake failed", "error", err)
		return errClose
	}

	state := tlsconn.ConnectionState()
	c.transport = &transport{conn: tlsconn, rdr: bufio.NewReader(tlsconn), state: &state}

	// RFC 4513 section 3.1.1: the connection reverts to anonymous.
	c.bindDN = ""

	c.log.Debug("StartTLS established", "version", state.Version)
	return nil
}

// encodeResponse builds the result concluding an operation, returning nil for
// an operation that takes no response. It is split from [conn.respond] so that
// a caller can encode before taking writeMu and write under a hold of its own;
// see [conn.finish].
func (c *conn) encodeResponse(msg *message, err error) []byte {
	tag, ok := responseTags[msg.op.Tag]
	if !ok {
		return nil
	}

	code, diagnostic, matchedDN := result(err)
	if code == OperationsError && err != nil {
		// The generic diagnostic hides the cause from the client, so
		// record it here.
		c.log.Error("operation failed", "op", msg.opName(), "error", err)
	}
	return encodeMessage(msg.id, encodeResult(tag, code, matchedDN, diagnostic))
}

// respond sends the result concluding an operation. Operations that take no
// response are ignored.
func (c *conn) respond(msg *message, err error) error {
	b := c.encodeResponse(msg, err)
	if b == nil {
		return nil
	}
	return c.write(b)
}

// write sends an encoded message. Message IDs interleave on the wire, so
// concurrent operations must not interleave their bytes.
func (c *conn) write(b []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeLocked(b)
}

// writeLocked is [conn.write] for a caller already holding writeMu.
//
// A failed write closes the connection. A write deadline can expire partway
// through a message, and what is left on the wire is then a truncated element
// the client cannot decode; there is no recovering the stream from that. Only
// the read loop's own writes would otherwise end the connection, by returning
// the error.
func (c *conn) writeLocked(b []byte) error {
	if c.writeTimeout > 0 {
		_ = c.transport.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	if _, err := c.transport.conn.Write(b); err != nil {
		c.close()
		return err
	}
	return nil
}

// request snapshots the connection state for a request. The snapshot is a
// value so that a handler may retain it.
func (c *conn) request(msg *message) Request {
	return Request{
		MessageID: msg.id,
		Controls:  msg.controls,
		Conn: ConnInfo{
			RemoteAddr: c.remote,
			LocalAddr:  c.local,
			TLS:        c.transport.state,
			BindDN:     c.bindDN,
		},
	}
}

// shutdown puts the connection into draining and closes it if nothing is left
// in flight. [Server.Shutdown] documents what draining means for a client and
// which operations are waited for.
//
// Nothing is written from here: writes belong to the read loop and the
// operation goroutines, and a StartTLS upgrade may be in flight. The
// unavailable results a draining connection sends come from the read loop as
// each request arrives.
func (c *conn) shutdown() {
	c.opsMu.Lock()
	c.draining = true
	c.opsMu.Unlock()

	c.closeIfDrained()
}

func (c *conn) isDraining() bool {
	c.opsMu.Lock()
	defer c.opsMu.Unlock()
	return c.draining
}

// inProgress reports whether an abandonable operation is running under id.
// Only search and compare are in the registry: the rest run inline on the read
// loop, so none can be in progress while a message is being dispatched.
func (c *conn) inProgress(id int32) bool {
	c.opsMu.Lock()
	defer c.opsMu.Unlock()
	_, ok := c.ops[id]
	return ok
}

// outstanding reports how many abandonable operations have yet to finish
// writing their response. It counts pending rather than the registry, so an
// operation that has released its message ID but not yet written still counts.
func (c *conn) outstanding() int {
	c.opsMu.Lock()
	defer c.opsMu.Unlock()
	return c.pending
}

// close shuts the connection down, cancelling its operations and unblocking
// the read loop. It closes the socket as accepted rather than the current
// transport: see conn.raw. It is safe to call from any goroutine and more than
// once.
//
// Cancelling matters as much as closing: a read loop waiting in doBind is not
// blocked on the socket, so closing alone would not reach it.
func (c *conn) close() {
	c.cancel()
	_ = c.raw.Close()
}
