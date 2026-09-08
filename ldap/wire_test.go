package ldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"maps"
	"math"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/matryer/is"
)

// wireConn is a minimal LDAP client that speaks the protocol directly. The
// go-ldap client cannot send an Abandon or an arbitrary extended operation, so
// these tests build the messages themselves.
type wireConn struct {
	t  *testing.T
	nc net.Conn
	br *bufio.Reader
}

func dialWire(t *testing.T, addr string) *wireConn {
	t.Helper()
	dialer := net.Dialer{Timeout: testWait}
	nc, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	return &wireConn{t: t, nc: nc, br: bufio.NewReader(nc)}
}

// send writes a protocol operation under the given message ID.
func (w *wireConn) send(id int32, op *ber.Packet) {
	w.t.Helper()
	if _, err := w.nc.Write(encodeMessage(id, op)); err != nil {
		w.t.Fatalf("write message %d: %v", id, err)
	}
}

// sendRaw writes arbitrary bytes, for testing malformed input.
func (w *wireConn) sendRaw(b []byte) {
	w.t.Helper()
	if _, err := w.nc.Write(b); err != nil {
		w.t.Fatalf("write raw: %v", err)
	}
}

// upgrade completes the client side of a StartTLS handshake, for tests that
// need to send a further operation over the encrypted connection. The caller
// must have read the StartTLS success response first: the handshake follows it
// immediately on the same socket.
func (w *wireConn) upgrade(conf *tls.Config) {
	w.t.Helper()
	if n := w.br.Buffered(); n > 0 {
		w.t.Fatalf("%d bytes buffered before the handshake", n)
	}
	ctx, cancel := context.WithTimeout(w.t.Context(), testWait)
	defer cancel()

	tc := tls.Client(w.nc, conf)
	if err := tc.HandshakeContext(ctx); err != nil {
		w.t.Fatalf("client handshake: %v", err)
	}
	w.nc, w.br = tc, bufio.NewReader(tc)
}

// recv reads the next message, failing the test if none arrives in time.
func (w *wireConn) recv() *message {
	w.t.Helper()
	_ = w.nc.SetReadDeadline(time.Now().Add(testWait))
	m, err := readMessage(w.br)
	if err != nil {
		w.t.Fatalf("read message: %v", err)
	}
	return m
}

// quietWait is how long recvNothing listens before accepting that nothing is
// coming. Long enough that a response in flight would have arrived.
const quietWait = 300 * time.Millisecond

// recvNothing asserts that no message arrives.
func (w *wireConn) recvNothing() {
	w.t.Helper()
	_ = w.nc.SetReadDeadline(time.Now().Add(quietWait))
	m, err := readMessage(w.br)
	switch {
	case err == nil:
		w.t.Fatalf("expected no response, got message %d op %s", m.id, m.opName())
	case errors.Is(err, os.ErrDeadlineExceeded):
		return // what we wanted
	default:
		w.t.Fatalf("expected a read timeout, got %v", err)
	}
}

// resultCode reads the result code out of a response carrying an LDAPResult.
func (m *message) resultCode(t *testing.T) Code {
	t.Helper()
	if len(m.op.Children) == 0 {
		t.Fatalf("response op %d has no result code", m.op.Tag)
	}
	code, ok := m.op.Children[0].Value.(int64)
	if !ok {
		t.Fatalf("response result code is %T, not an integer", m.op.Children[0].Value)
	}
	return Code(code) //nolint:gosec // a test reading a value this package wrote
}

// adminBindOp builds a simple BindRequest for the test directory's admin, the
// only identity these tests bind as.
func adminBindOp() *ber.Packet {
	return bindOp(adminDN, adminPw)
}

// bindOp builds a simple BindRequest for an arbitrary DN and password.
func bindOp(dn, password string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tagBindRequest, nil, "BindRequest")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "version"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "name"))
	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, tagAuthSimple, nil, "simple")
	auth.Data.Write([]byte(password))
	p.AppendChild(auth)
	return p
}

// searchOp builds a SearchRequest over the whole subtree below baseDN,
// carrying the given filter and no limits. A nil filter stands for
// (objectClass=*).
func searchOp(filter *ber.Packet) *ber.Packet {
	return searchLimitOp(0, 0, filter)
}

// searchLimitOp builds a SearchRequest carrying the client's size and time
// limits, each zero for none.
func searchLimitOp(sizeLimit, timeLimit int, filter *ber.Packet) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tagSearchRequest, nil, "SearchRequest")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, baseDN, "baseObject"))
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(WholeSubtree), "scope"))
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(NeverDerefAliases), "derefAliases"))
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(sizeLimit), "sizeLimit"))
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(timeLimit), "timeLimit"))
	p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))

	if filter == nil {
		filter = ber.Encode(ber.ClassContext, ber.TypePrimitive, tagFilterPresent, nil, "present")
		filter.Data.Write([]byte("objectClass"))
	}
	p.AppendChild(filter)

	p.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))
	return p
}

// abandonOp builds an AbandonRequest, which is a primitive application-class
// integer rather than a sequence.
func abandonOp(id int32) *ber.Packet {
	n := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(id), "messageID")
	p := ber.Encode(ber.ClassApplication, ber.TypePrimitive, tagAbandonRequest, nil, "AbandonRequest")
	p.Data.Write(n.Data.Bytes())
	return p
}

// saslBindOp builds a SASL BindRequest. An empty mechanism produces the
// malformed case, which is otherwise hard to generate.
func saslBindOp(mechanism string, credentials []byte) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tagBindRequest, nil, "BindRequest")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "version"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "name"))

	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagAuthSASL, nil, "sasl")
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, mechanism, "mechanism"))
	if credentials != nil {
		sasl.AppendChild(newOctetString(credentials, "credentials"))
	}
	p.AppendChild(sasl)
	return p
}

func extendedOp(oid string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tagExtendedRequest, nil, "ExtendedRequest")
	name := ber.Encode(ber.ClassContext, ber.TypePrimitive, tagRequestName, nil, "requestName")
	name.Data.Write([]byte(oid))
	p.AppendChild(name)
	return p
}

// TestAbandon checks the whole abandon path: the handler's context is
// cancelled, no response is sent for the abandoned operation, and the
// connection remains usable afterwards.
func TestAbandon(t *testing.T) {
	is := is.New(t)

	started := make(chan struct{})
	stopped := make(chan error, 1)

	h := &testHandler{search: func(ctx context.Context, _ *SearchRequest, _ *SearchResponse) error {
		close(started)
		<-ctx.Done() // a real handler would poll this between entries
		stopped <- ctx.Err()
		return ctx.Err()
	}}

	w := dialWire(t, startPlain(t, h))
	w.send(1, searchOp(nil))

	select {
	case <-started:
	case <-time.After(testWait):
		t.Fatal("search handler did not start")
	}

	w.send(2, abandonOp(1))

	select {
	case err := <-stopped:
		is.True(errors.Is(err, context.Canceled)) // abandon must cancel the handler
	case <-time.After(testWait):
		t.Fatal("abandon did not cancel the search")
	}

	// RFC 4511 section 4.11: an abandoned operation gets no response, and
	// the abandon itself has none either. This is what nslcd was unhappy
	// about when the response was sent anyway.
	w.recvNothing()

	// The connection must still work.
	w.send(3, adminBindOp())
	m := w.recv()
	is.Equal(m.id, int32(3))
	is.Equal(m.op.Tag, tagBindResponse)
	is.Equal(m.resultCode(t), Success)
}

// TestDuplicateMessageID checks that a request reusing the ID of an operation
// already in progress is refused rather than displacing it in the registry. The
// first operation must stay abandonable, and must still count as outstanding,
// which is what keeps StartTLS from swapping the transport underneath it.
func TestDuplicateMessageID(t *testing.T) {
	is := is.New(t)

	// Both channels have room for a second search, so that admitting one
	// fails an assertion rather than wedging the handler.
	started := make(chan struct{}, 2)
	stopped := make(chan error, 2)

	h := &testHandler{search: func(ctx context.Context, _ *SearchRequest, _ *SearchResponse) error {
		started <- struct{}{}
		<-ctx.Done()
		stopped <- ctx.Err()
		return ctx.Err()
	}}

	// TLS is configured so that StartTLS reaches its outstanding-operation
	// guard rather than being refused for want of a configuration.
	tlsConf, _ := testTLS(t)
	srv := &Server{Handler: h, TLSConfig: tlsConf}
	ln := listen(t)
	serveTest(t, srv, func() error { return srv.Serve(ln) })

	w := dialWire(t, ln.Addr().String())
	w.send(1, searchOp(nil))

	select {
	case <-started:
	case <-time.After(testWait):
		t.Fatal("search handler did not start")
	}

	// The second search under the live ID is refused, and the first is
	// left running rather than abandoned in its place.
	w.send(1, searchOp(nil))
	m := w.recv()
	is.Equal(m.id, int32(1))
	is.Equal(m.op.Tag, tagSearchResultDone)
	is.Equal(m.resultCode(t), ProtocolError)

	// An operation that is not a search is refused under the live ID too:
	// the check is in dispatch, not in the search path. Without it the
	// client would get an extended response under an ID it still has a
	// search open on.
	w.send(1, extendedOp(oidWhoAmI))
	m = w.recv()
	is.Equal(m.id, int32(1))
	is.Equal(m.op.Tag, tagExtendedResponse)
	is.Equal(m.resultCode(t), ProtocolError)

	// StartTLS must still see the first search as outstanding.
	w.send(2, extendedOp(oidStartTLS))
	m = w.recv()
	is.Equal(m.op.Tag, tagExtendedResponse)
	is.Equal(m.resultCode(t), OperationsError)

	// The first search still owns the ID, so an abandon reaches it.
	w.send(3, abandonOp(1))
	select {
	case err := <-stopped:
		is.True(errors.Is(err, context.Canceled))
	case <-time.After(testWait):
		t.Fatal("abandon did not cancel the first search")
	}
}

// TestReusedMessageID checks the other half of the rule TestDuplicateMessageID
// covers: RFC 4511 section 4.1.1.1 lets a client reuse a message ID once the
// operation using it has completed, so the ID must be free by the time the
// response that completes it can be seen. An operation is taken out of the
// registry before its response is written, and this pins that ordering down.
//
// A client cannot show this: its reuse takes a round trip to arrive, which is
// far longer than the window the ordering closes, so it would pass either way.
// The response is written over a net.Pipe instead, which is unbuffered, so the
// write blocks part-read and the registry can be inspected at a moment the
// client could already be acting on what it has.
//
// The registry is what to inspect, not the pending count: pending is released
// after the write, so it says nothing about where the ID was released.
func TestReusedMessageID(t *testing.T) {
	is := is.New(t)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	srv := &Server{Handler: &testHandler{}, Logger: discardLogger()}
	c := newConn(t.Context(), srv, server)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	msg := &message{id: 2, op: searchOp(nil)}

	// Registered the way start does it, so that what the registry and the
	// pending count say can be told apart.
	c.ops[msg.id] = cancel
	c.pending++

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.finish(ctx, msg, nil)
	}()

	// One byte is enough to prove the response is on its way out, and
	// leaves the rest of it unread, so the write is still blocked here.
	_ = client.SetReadDeadline(time.Now().Add(testWait))
	var b [1]byte
	if _, err := client.Read(b[:]); err != nil {
		t.Fatalf("read first byte of response: %v", err)
	}
	is.True(!c.inProgress(msg.id)) // the ID is free before the response lands
	is.Equal(c.outstanding(), 1)   // and the operation is still counted

	// Drain the rest so the write completes and the goroutine finishes.
	go func() { _, _ = io.Copy(io.Discard, client) }()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal("finish did not complete")
	}
}

// TestResponseReleasedWithWrite checks that an operation stops being counted
// in the same breath as its response reaching the client, not a moment later.
//
// StartTLS is refused while anything is outstanding (RFC 4513 section 3.1.1)
// and reads that count while holding writeMu, so a count that outlived the
// write would let a client be refused an upgrade over an operation it had
// already seen finish. What stops that is writeMu covering both the write and
// the release.
//
// Driven by holding opsMu, which the release needs and cannot have until this
// test gives it up. So after the response has landed, the broken ordering
// leaves writeMu free while the count still stands, and the fixed one holds it
// until both are done. Neither state is timing-dependent: each persists for as
// long as opsMu is held, and the spin only has to look.
func TestResponseReleasedWithWrite(t *testing.T) {
	is := is.New(t)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	srv := &Server{Handler: &testHandler{}, Logger: discardLogger()}
	c := newConn(t.Context(), srv, server)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	msg := &message{id: 2, op: searchOp(nil)}
	c.ops[msg.id] = cancel
	c.pending++

	done := make(chan struct{})
	go func() { defer close(done); c.finish(ctx, msg, nil) }()

	// Wait until finish is inside the write, which it cannot leave: the
	// pipe is unbuffered and nothing has read it yet.
	deadline := time.Now().Add(testWait)
	for c.writeMu.TryLock() {
		c.writeMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("finish did not reach the write")
		}
		time.Sleep(time.Millisecond)
	}

	c.opsMu.Lock()
	is.Equal(c.pending, 1) // nothing has reached the client yet

	_ = client.SetReadDeadline(time.Now().Add(testWait))
	m, err := readMessage(bufio.NewReader(client))
	is.NoErr(err)
	is.Equal(m.id, int32(2)) // and now the client holds all of it

	// The response has landed and is still counted, so writeMu must stay
	// held. That is the state a StartTLS must not be able to observe.
	for range 50 {
		if c.writeMu.TryLock() {
			c.writeMu.Unlock()
			t.Fatal("writeMu was free while a landed response was still counted")
		}
		time.Sleep(time.Millisecond)
	}

	c.opsMu.Unlock()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal("finish did not complete")
	}
	is.Equal(c.outstanding(), 0)
}

// TestWriteFailureClosesConnection checks that a failed write takes the
// connection with it. A write deadline can expire partway through a message,
// leaving the client a truncated element it cannot decode, and only the read
// loop's own writes end the connection by returning the error.
//
// The response goes over an unbuffered net.Pipe that nothing reads, so the
// write blocks until the deadline expires.
func TestWriteFailureClosesConnection(t *testing.T) {
	is := is.New(t)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	srv := &Server{Handler: &testHandler{}, Logger: discardLogger(), WriteTimeout: time.Millisecond}
	c := newConn(t.Context(), srv, server)

	err := c.write(encodeMessage(1, encodeResult(tagSearchResultDone, Success, "", "")))
	is.True(err != nil)         // the write failed
	is.True(c.ctx.Err() != nil) // and the connection is closed
}

// TestShutdownWaitsForPendingResponse pins the companion rule to
// TestReusedMessageID. An operation releases its message ID before writing,
// so the registry going empty does not mean the connection is idle. A
// shutdown that treated it as idle closed the connection out from under the
// response, and the client got EOF where Server.Shutdown promises the running
// search finishes.
//
// A net.Pipe is what makes the window reachable: it is unbuffered, so with
// nothing reading, finish is parked in the write with the ID already released.
func TestShutdownWaitsForPendingResponse(t *testing.T) {
	is := is.New(t)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	srv := &Server{Handler: &testHandler{}, Logger: discardLogger()}
	c := newConn(t.Context(), srv, server)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	msg := &message{id: 2, op: searchOp(nil)}
	c.ops[msg.id] = cancel
	c.pending++

	done := make(chan struct{})
	go func() { defer close(done); c.finish(ctx, msg, nil) }()

	// Wait for the ID to be released, which is the start of the window.
	deadline := time.Now().Add(testWait)
	for c.inProgress(msg.id) {
		if time.Now().After(deadline) {
			t.Fatal("finish did not release the message ID")
		}
		time.Sleep(time.Millisecond)
	}
	is.Equal(c.outstanding(), 1) // still pending: the response has not been written

	c.shutdown() // must not close the connection here

	br := bufio.NewReader(client)
	_ = client.SetReadDeadline(time.Now().Add(testWait))
	m, err := readMessage(br)
	is.NoErr(err) // the response was delivered despite the shutdown
	is.Equal(m.id, int32(2))
	is.Equal(m.op.Tag, tagSearchResultDone)

	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal("finish did not return")
	}

	// Draining with nothing left pending, so the connection closes itself.
	is.Equal(c.outstanding(), 0)
	is.True(c.ctx.Err() != nil)
}

// TestAbandonUnknownOperation checks that abandoning an operation that has
// already finished is silently ignored rather than answered or fatal.
func TestAbandonUnknownOperation(t *testing.T) {
	is := is.New(t)

	w := dialWire(t, startPlain(t, &testHandler{}))
	w.send(1, adminBindOp())
	is.Equal(w.recv().resultCode(t), Success)

	w.send(2, abandonOp(1)) // message 1 is long gone
	w.recvNothing()

	w.send(3, abandonOp(99)) // and message 99 never existed
	w.recvNothing()

	w.send(4, adminBindOp())
	is.Equal(w.recv().id, int32(4))
}

// TestUnknownExtendedOperation checks RFC 4511 section 4.12: an unrecognised
// requestName is answered with protocolError.
func TestUnknownExtendedOperation(t *testing.T) {
	is := is.New(t)

	w := dialWire(t, startPlain(t, &testHandler{}))
	w.send(1, extendedOp("1.3.6.1.4.1.99999.1"))

	m := w.recv()
	is.Equal(m.id, int32(1))
	is.Equal(m.op.Tag, tagExtendedResponse)
	is.Equal(m.resultCode(t), ProtocolError)
}

// TestStartTLSWithPipelinedData checks that data sent before the TLS handshake
// is refused rather than silently dropped. tls.Server reads the socket, not the
// buffered reader, so anything already buffered would be discarded on upgrade -
// the hole that STARTTLS command injection exploits in other protocols.
func TestStartTLSWithPipelinedData(t *testing.T) {
	is := is.New(t)

	tlsConf, _ := testTLS(t)
	srv := &Server{Handler: &testHandler{}, TLSConfig: tlsConf, Logger: discardLogger()}
	ln := listen(t)
	serveTest(t, srv, func() error { return srv.Serve(ln) })

	w := dialWire(t, ln.Addr().String())

	// One write, so both messages land in the same read and the second is
	// sitting in the reader when the upgrade is decided.
	pipelined := append(
		encodeMessage(1, extendedOp(oidStartTLS)),
		encodeMessage(2, adminBindOp())...)
	w.sendRaw(pipelined)

	m := w.recv()
	is.Equal(m.id, int32(1))
	is.Equal(m.op.Tag, tagExtendedResponse)
	is.Equal(m.resultCode(t), ProtocolError)

	// The connection is dropped rather than left in the clear, and the
	// pipelined bind is never answered.
	_ = w.nc.SetReadDeadline(time.Now().Add(testWait))
	_, err := readMessage(w.br)
	is.True(err != nil)
	is.True(!errors.Is(err, os.ErrDeadlineExceeded)) // closed, not merely quiet
}

// TestUnbind checks that an unbind reaches the handler and closes the
// connection without a response.
func TestUnbind(t *testing.T) {
	is := is.New(t)

	unbound := make(chan struct{})
	h := &unbindHandler{unbound: unbound}

	w := dialWire(t, startPlain(t, h))
	unbind := ber.Encode(ber.ClassApplication, ber.TypePrimitive, tagUnbindRequest, nil, "UnbindRequest")
	w.send(1, unbind)

	select {
	case <-unbound:
	case <-time.After(testWait):
		t.Fatal("unbind did not reach the handler")
	}

	// The server closes the connection; no response is ever sent.
	_ = w.nc.SetReadDeadline(time.Now().Add(testWait))
	_, err := readMessage(w.br)
	is.True(err != nil) // connection must be closed
	is.True(!errors.Is(err, os.ErrDeadlineExceeded))
}

type unbindHandler struct {
	testHandler
	unbound chan struct{}
}

func (h *unbindHandler) Unbind(context.Context, *UnbindRequest) { close(h.unbound) }

// TestMalformedMessage checks that unparseable input gets an unsolicited
// Notice of Disconnection before the connection is dropped.
func TestMalformedMessage(t *testing.T) {
	is := is.New(t)

	w := dialWire(t, startPlain(t, &testHandler{}))
	// A SEQUENCE holding only an integer: a well-formed BER packet, but
	// not an LDAPMessage, which needs a protocol operation too.
	w.sendRaw([]byte{0x30, 0x03, 0x02, 0x01, 0x01})

	m := w.recv()
	is.Equal(m.id, int32(0)) // unsolicited notifications use message ID 0
	is.Equal(m.op.Tag, tagExtendedResponse)
	is.Equal(m.resultCode(t), ProtocolError)
}

// TestReservedMessageID checks RFC 4511 section 4.1.1.1: message ID 0 is the
// unsolicited notification's, so an operation that takes a response cannot
// carry it. The refusal cannot itself be a response, since one echoing ID 0
// would read as a notification, so the connection is dropped with a Notice of
// Disconnection instead.
func TestReservedMessageID(t *testing.T) {
	is := is.New(t)

	w := dialWire(t, startPlain(t, &testHandler{}))
	w.send(0, searchOp(nil))

	m := w.recv()
	is.Equal(m.id, int32(0))
	is.Equal(m.op.Tag, tagExtendedResponse)
	is.Equal(m.resultCode(t), ProtocolError)

	// No search result is sent, and the session is over.
	_ = w.nc.SetReadDeadline(time.Now().Add(testWait))
	_, err := readMessage(w.br)
	is.True(err != nil)
	is.True(!errors.Is(err, os.ErrDeadlineExceeded)) // closed, not merely quiet
}

// TestReservedMessageIDWhileDraining checks that the reserved ID rule outranks
// the draining refusal. A draining connection answers a new request with
// unavailable, but it cannot answer one carrying ID 0 that way: the response
// would echo the reserved ID and read as an unsolicited notification. The
// Notice of Disconnection is the only thing the server can say.
func TestReservedMessageIDWhileDraining(t *testing.T) {
	is := is.New(t)

	// A search held open for the whole test, so the connection is never
	// found idle and the shutdown cannot finish without it.
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
	t.Cleanup(func() {
		close(release)
		_ = srv.Close()
		<-served
	})

	w := dialWire(t, ln.Addr().String())
	w.send(1, searchOp(nil))
	select {
	case <-started:
	case <-time.After(testWait):
		t.Fatal("search handler did not start")
	}

	// Drained directly rather than through Server.Shutdown, which reaches
	// the connection on its own goroutine: this puts it in the state under
	// test without waiting for that to happen. The held search keeps the
	// connection from closing as it drains.
	drain(srv)

	// A fresh ID confirms the connection really is draining.
	w.send(2, searchOp(nil))
	m := w.recv()
	is.Equal(m.id, int32(2))
	is.Equal(m.resultCode(t), Unavailable)

	// ID 0 cannot be refused that way, however much the connection would
	// rather report unavailable.
	w.send(0, searchOp(nil))
	m = w.recv()
	is.Equal(m.id, int32(0))
	is.Equal(m.op.Tag, tagExtendedResponse) // a notification, not a result
	is.Equal(m.resultCode(t), ProtocolError)

	// And the connection is dropped rather than left usable.
	_ = w.nc.SetReadDeadline(time.Now().Add(testWait))
	_, err := readMessage(w.br)
	is.True(err != nil)
	is.True(!errors.Is(err, os.ErrDeadlineExceeded)) // closed, not merely quiet
}

// drain puts every connection the server holds into draining, which is what
// Server.Shutdown does to each of them. Collected under the lock and shut down
// outside it, for the reason Shutdown gives.
func drain(srv *Server) {
	srv.mu.Lock()
	conns := slices.Collect(maps.Keys(srv.conns))
	srv.mu.Unlock()

	for _, c := range conns {
		c.shutdown()
	}
}

// TestReservedMessageIDOnAbandon checks the other side of that rule. Abandon
// takes no response and reads its target from the request body rather than the
// envelope, so it is carried out under the reserved ID rather than costing the
// client its session and everything still running on it.
func TestReservedMessageIDOnAbandon(t *testing.T) {
	is := is.New(t)

	started := make(chan struct{}, 1)
	stopped := make(chan error, 1)
	h := &testHandler{search: func(ctx context.Context, _ *SearchRequest, _ *SearchResponse) error {
		started <- struct{}{}
		<-ctx.Done()
		stopped <- ctx.Err()
		return ctx.Err()
	}}

	w := dialWire(t, startPlain(t, h))
	w.send(1, searchOp(nil))
	select {
	case <-started:
	case <-time.After(testWait):
		t.Fatal("search handler did not start")
	}

	w.send(0, abandonOp(1))
	select {
	case err := <-stopped:
		is.True(errors.Is(err, context.Canceled))
	case <-time.After(testWait):
		t.Fatal("abandon did not reach the search")
	}

	// The session survives it.
	w.send(2, adminBindOp())
	m := w.recv()
	is.Equal(m.id, int32(2))
	is.Equal(m.resultCode(t), Success)
}

// TestSASLBindDeclinedByDefault checks that a handler which does not implement
// SASL declines it with authMethodNotSupported rather than the request being
// misread as a simple bind.
func TestSASLBindDeclinedByDefault(t *testing.T) {
	is := is.New(t)

	w := dialWire(t, startPlain(t, &testHandler{}))
	w.send(1, saslBindOp("EXTERNAL", nil))

	m := w.recv()
	is.Equal(m.op.Tag, tagBindResponse)
	is.Equal(m.resultCode(t), AuthMethodNotSupported)
}

// TestSASLBindReachesHandler checks that the mechanism and credentials are
// decoded and handed over, so a handler can implement a mechanism itself.
func TestSASLBindReachesHandler(t *testing.T) {
	is := is.New(t)

	got := make(chan *BindRequest, 1)
	h := &testHandler{bind: func(r *BindRequest) error {
		got <- r
		return nil
	}}

	w := dialWire(t, startPlain(t, h))
	w.send(1, saslBindOp("EXTERNAL", []byte("u:foo")))
	is.Equal(w.recv().resultCode(t), Success)

	r := <-got
	is.True(r.SASL())
	is.Equal(r.Mechanism, "EXTERNAL")
	is.Equal(string(r.Credentials), "u:foo")
	is.Equal(r.Password, "") // a SASL bind carries no simple password
}

// TestSASLBindWithoutMechanism checks that an empty mechanism is a protocol
// error rather than being taken for a simple bind.
func TestSASLBindWithoutMechanism(t *testing.T) {
	is := is.New(t)

	w := dialWire(t, startPlain(t, &testHandler{}))
	w.send(1, saslBindOp("", nil))

	m := w.recv()
	is.Equal(m.op.Tag, tagBindResponse)
	is.Equal(m.resultCode(t), ProtocolError)
}

// TestStartTLSHandshakeTimeout checks that a client which asks for StartTLS and
// then never begins the handshake is dropped. The server sets no IdleTimeout,
// so no read deadline is armed and nothing but the handshake's own bound ends
// the wait.
func TestStartTLSHandshakeTimeout(t *testing.T) {
	is := is.New(t)

	restore := tlsHandshakeTimeout
	tlsHandshakeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { tlsHandshakeTimeout = restore })

	tlsConf, _ := testTLS(t)
	srv := &Server{Handler: &testHandler{}, TLSConfig: tlsConf}
	ln := listen(t)
	serveTest(t, srv, func() error { return srv.Serve(ln) })

	w := dialWire(t, ln.Addr().String())
	w.send(1, extendedOp(oidStartTLS))

	// The success response is sent in the clear, and the handshake is then
	// expected to follow. This client never sends one.
	m := w.recv()
	is.Equal(m.op.Tag, tagExtendedResponse)
	is.Equal(m.resultCode(t), Success)

	_ = w.nc.SetReadDeadline(time.Now().Add(testWait))
	_, err := readMessage(w.br)
	is.True(err != nil)
	is.True(!errors.Is(err, os.ErrDeadlineExceeded)) // dropped, not merely quiet
}

// TestIdleTimeout checks that a connection which says nothing is dropped once
// IdleTimeout passes. Without this the read deadline could stop being set and
// nothing would notice: a quiet peer would hold a connection for the life of
// the process.
func TestIdleTimeout(t *testing.T) {
	is := is.New(t)

	srv := &Server{Handler: &testHandler{}, IdleTimeout: 50 * time.Millisecond}
	ln := listen(t)
	serveTest(t, srv, func() error { return srv.Serve(ln) })

	w := dialWire(t, ln.Addr().String())

	// The server closes the connection, so the read ends rather than
	// running out the client's own deadline.
	_ = w.nc.SetReadDeadline(time.Now().Add(testWait))
	_, err := readMessage(w.br)
	is.True(err != nil)
	is.True(!errors.Is(err, os.ErrDeadlineExceeded)) // dropped, not merely quiet
}

// drainSearch reads a search's responses, returning how many entries arrived
// and the result code that concluded it.
func (w *wireConn) drainSearch() (int, Code) {
	w.t.Helper()
	entries := 0
	for {
		m := w.recv()
		if m.op.Tag == tagSearchResultDone {
			return entries, m.resultCode(w.t)
		}
		entries++
	}
}

// TestSearchLimitOutOfRange checks that a search limit outside the 0..maxInt
// of RFC 4511 section 4.5.1 is refused as a protocol error. A time limit past
// the bound overflows the duration it becomes, which would otherwise hand the
// search a context that had already expired and report timeLimitExceeded for a
// search that never ran.
func TestSearchLimitOutOfRange(t *testing.T) {
	tests := []struct {
		name      string
		sizeLimit int
		timeLimit int
	}{
		{name: "negative size", sizeLimit: -1},
		{name: "negative time", timeLimit: -1},
		{name: "size past maxInt", sizeLimit: math.MaxInt32 + 1},
		{name: "time past maxInt", timeLimit: math.MaxInt32 + 1},
		{name: "time that overflows a duration", timeLimit: math.MaxInt64 / 2},
	}

	addr := startPlain(t, &testHandler{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			w := dialWire(t, addr)
			w.send(1, searchLimitOp(tt.sizeLimit, tt.timeLimit, nil))

			m := w.recv()
			is.Equal(m.op.Tag, tagSearchResultDone)
			is.Equal(m.resultCode(t), ProtocolError)
		})
	}
}

// TestSearchReference checks that a search result reference reaches the client
// and arrives before the result concluding the search. A reference is its own
// message sharing the search's ID, so a client that took every message before
// the done to be an entry would mis-read it.
//
// Count is entries only, so the reference must not advance it.
func TestSearchReference(t *testing.T) {
	is := is.New(t)

	const uri = "ldap://other.example.com/dc=example,dc=com"
	counted := make(chan int, 1)
	h := &testHandler{search: func(_ context.Context, _ *SearchRequest, w *SearchResponse) error {
		if err := w.Entry(baseDN, map[string][]any{"cn": {"x"}}); err != nil {
			return err
		}
		if err := w.Reference(uri); err != nil {
			return err
		}
		counted <- w.Count()
		return nil
	}}

	w := dialWire(t, startPlain(t, h))
	w.send(1, searchOp(nil))

	m := w.recv()
	is.Equal(m.op.Tag, tagSearchResultEntry)

	m = w.recv()
	is.Equal(m.id, int32(1))
	is.Equal(m.op.Tag, tagSearchResultReference)
	is.Equal(content(m.op.Children[0]), uri)

	m = w.recv()
	is.Equal(m.op.Tag, tagSearchResultDone)
	is.Equal(m.resultCode(t), Success)

	is.Equal(<-counted, 1)
}

// TestSearchSizeLimit checks that the package holds a handler to the request's
// size limit: the writes past it fail, and the search ends with
// sizeLimitExceeded however eagerly the handler was writing.
func TestSearchSizeLimit(t *testing.T) {
	is := is.New(t)

	const want = 2
	stopped := make(chan error, 1)
	h := &testHandler{search: func(_ context.Context, _ *SearchRequest, w *SearchResponse) error {
		// The handler counts nothing itself; it writes until told not
		// to, which is what a handler unaware of the limit would do.
		for range want + 5 {
			if err := w.Entry(baseDN, map[string][]any{"cn": {"x"}}); err != nil {
				stopped <- err
				return err
			}
		}
		stopped <- nil
		return nil
	}}

	w := dialWire(t, startPlain(t, h))
	w.send(1, searchLimitOp(want, 0, nil))

	entries, code := w.drainSearch()
	is.Equal(entries, want)
	is.Equal(code, SizeLimitExceeded)

	select {
	case err := <-stopped:
		is.True(err != nil) // the handler must have been refused, not run out
	case <-time.After(testWait):
		t.Fatal("handler did not finish")
	}
}

// TestSearchTimeLimit checks that the request's time limit cancels the search
// and concludes it with timeLimitExceeded.
func TestSearchTimeLimit(t *testing.T) {
	is := is.New(t)

	// The protocol counts the limit in whole seconds, so the unit is
	// shortened rather than waited out.
	restore := timeLimitUnit
	t.Cleanup(func() { timeLimitUnit = restore })
	timeLimitUnit = 10 * time.Millisecond

	stopped := make(chan error, 1)
	h := &testHandler{search: func(ctx context.Context, _ *SearchRequest, w *SearchResponse) error {
		// Bounded so that a limit which never fires fails the test
		// rather than hanging it.
		for range 1000 {
			if err := w.Entry(baseDN, map[string][]any{"cn": {"x"}}); err != nil {
				stopped <- err
				return err
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Millisecond):
			}
		}
		stopped <- nil
		return nil
	}}

	w := dialWire(t, startPlain(t, h))
	w.send(1, searchLimitOp(0, 1, nil))

	_, code := w.drainSearch()
	is.Equal(code, TimeLimitExceeded)

	select {
	case err := <-stopped:
		is.True(errors.Is(err, context.DeadlineExceeded)) // stopped by the limit
	case <-time.After(testWait):
		t.Fatal("handler did not finish")
	}
}

// TestAbandonSearchWithTimeLimit checks that a time limit does not turn an
// abandon into a response. The two both cancel the search, and only the cause
// tells them apart.
func TestAbandonSearchWithTimeLimit(t *testing.T) {
	is := is.New(t)

	started := make(chan struct{})
	stopped := make(chan error, 1)
	h := &testHandler{search: func(ctx context.Context, _ *SearchRequest, _ *SearchResponse) error {
		close(started)
		<-ctx.Done()
		stopped <- ctx.Err()
		return ctx.Err()
	}}

	w := dialWire(t, startPlain(t, h))
	// A limit far enough out that only the abandon can end this search.
	w.send(1, searchLimitOp(0, 300, nil))

	select {
	case <-started:
	case <-time.After(testWait):
		t.Fatal("search handler did not start")
	}

	w.send(2, abandonOp(1))
	select {
	case err := <-stopped:
		is.True(errors.Is(err, context.Canceled))
	case <-time.After(testWait):
		t.Fatal("abandon did not cancel the search")
	}

	// RFC 4511 section 4.11: an abandoned operation gets no response.
	w.recvNothing()
}

// logBuffer collects a server's log so that a test can assert on it. The server
// writes from its own goroutines, so writes are serialised.
type logBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestPanicInSearch checks that a handler panic costs the client its operation
// rather than costing every client the server. The connection must survive it,
// since one bad entry is no reason to drop a client's other lookups.
func TestPanicInSearch(t *testing.T) {
	is := is.New(t)

	h := &testHandler{search: func(_ context.Context, _ *SearchRequest, w *SearchResponse) error {
		// An entry is written first, so the panic lands mid-response.
		if err := w.Entry(baseDN, map[string][]any{"cn": {"x"}}); err != nil {
			return err
		}
		panic("handler bug")
	}}

	// The log is the only record of the panic, so it is captured rather
	// than discarded.
	logged := &logBuffer{}
	srv := &Server{Handler: h, Logger: slog.New(slog.NewTextHandler(logged, nil))}
	ln := listen(t)
	serveTest(t, srv, func() error { return srv.Serve(ln) })

	w := dialWire(t, ln.Addr().String())
	w.send(1, searchOp(nil))

	entries, code := w.drainSearch()
	is.Equal(entries, 1)
	is.Equal(code, OperationsError)

	// The connection is still good.
	w.send(2, adminBindOp())
	m := w.recv()
	is.Equal(m.id, int32(2))
	is.Equal(m.resultCode(t), Success)

	// The panic and where it came from must be recoverable from the log.
	out := logged.String()
	is.True(strings.Contains(out, "handler panicked"))
	is.True(strings.Contains(out, "handler bug"))
	is.True(strings.Contains(out, "wire_test.go")) // the stack, not just the value
}

// TestPanicInBind checks the same for an operation that runs on the read loop
// rather than on its own goroutine. A panicked bind leaves the connection
// anonymous, as any other failed bind does.
func TestPanicInBind(t *testing.T) {
	is := is.New(t)

	// Which bind panics is decided from the request rather than from a
	// variable the test flips. The handler runs on the read loop, and
	// socket I/O is not a happens-before edge, so a shared flag would be a
	// data race however reliably the writes and reads alternate.
	const panicDN = "cn=panic,dc=example,dc=com"
	h := &testHandler{bind: func(r *BindRequest) error {
		if r.Name == panicDN {
			panic("handler bug")
		}
		return nil
	}}

	w := dialWire(t, startPlain(t, h))
	w.send(1, bindOp(panicDN, "x"))
	m := w.recv()
	is.Equal(m.op.Tag, tagBindResponse)
	is.Equal(m.resultCode(t), OperationsError)

	// The read loop survived, so a later bind on the same connection works.
	w.send(2, adminBindOp())
	m = w.recv()
	is.Equal(m.id, int32(2))
	is.Equal(m.resultCode(t), Success)
}

// TestConcurrentOperations checks that operations on one connection are served
// concurrently and that their responses do not interleave on the wire. Without
// concurrency an abandon could never reach a running operation.
func TestConcurrentOperations(t *testing.T) {
	is := is.New(t)

	release := make(chan struct{})
	entered := make(chan int32, 2)

	h := &testHandler{search: func(ctx context.Context, r *SearchRequest, w *SearchResponse) error {
		entered <- r.MessageID
		<-release
		// Write enough entries that interleaved writes would corrupt
		// the stream if responses were not serialised.
		for i := range 20 {
			if err := w.Entry("uid=user, "+baseDN, map[string][]any{
				"uid": {i}, "messageID": {r.MessageID},
			}); err != nil {
				return err
			}
		}
		return nil
	}}

	w := dialWire(t, startPlain(t, h))
	w.send(1, searchOp(nil))
	w.send(2, searchOp(nil))

	// Both searches must be in the handler at once.
	for range 2 {
		select {
		case <-entered:
		case <-time.After(testWait):
			t.Fatal("operations were not served concurrently")
		}
	}
	close(release)

	// Every message must decode cleanly, and both searches must finish.
	done := map[int32]bool{}
	for len(done) < 2 {
		m := w.recv()
		if m.op.Tag == tagSearchResultDone {
			is.Equal(m.resultCode(t), Success)
			done[m.id] = true
		}
	}
	is.True(done[1] && done[2])
}
