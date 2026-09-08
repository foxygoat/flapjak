# The `ldap` package

flapjak serves LDAP from its own `ldap` package rather than a third-party
library. This document explains why, and records the design decisions so they
don't have to be rediscovered from the code.

## Why not gldap

flapjak originally used [gldap]. It works, but it carries design choices we
kept having to work around:

- Routing is modelled on `http.Handler`. That fits HTTP, where every request
  has the same shape. LDAP operations are heterogeneous — a Bind and a Search
  have almost nothing in common — so a uniform handler signature means every
  handler starts by type-asserting its way back to the request it actually
  wanted.
- Attribute values are `map[string][]string`, which forces callers to flatten
  every non-string value before it reaches the server.
- Filters are handed to the handler as an RFC 4515 string. gldap decodes the
  BER filter and re-serialises it, so a server that wants to evaluate the
  filter has to parse it again.
- It logs through `hclog` rather than `log/slog`.

None of these are fatal, but the protocol surface flapjak needs turns out to be
small. [go-asn1-ber] already does the BER encoding and decoding; what remains
is the LDAP message layer — the operation tags, their schemas, and the
connection lifecycle. That is a few hundred lines, so we own it.

## Scope

The package implements what a read-only directory server needs, and rejects the
rest cleanly:

| Operation | Status |
|---|---|
| Bind (simple and SASL), Unbind, Search, Abandon | Fully decoded and dispatched |
| StartTLS, Who Am I | Handled as extended operations (below) |
| Compare | Fully decoded; declined by `Unsupported` |
| Add, Delete, Modify, ModifyDN | Not decoded; refused by the server with `unwillingToPerform` |

The write operations are not on the `Handler` interface at all, and the server
refuses them itself. A method that could be implemented but had no decoded
request to act on would be a promise the package does not keep — so serving one
means writing its decoder and adding its method together.

There is no schema and no plan for one. Attribute names are matched
case-insensitively; see [Values](#values) for how value comparison works
without one.

## The Handler interface

```go
type Handler interface {
	Bind(ctx context.Context, r *BindRequest) error
	Unbind(ctx context.Context, r *UnbindRequest)
	Search(ctx context.Context, r *SearchRequest, w *SearchResponse) error
	Compare(ctx context.Context, r *CompareRequest) (bool, error)
	WhoAmI(ctx context.Context, r *WhoAmIRequest) (string, error)
}
```

It is deliberately a fat interface with one method per operation, each taking
the request type it actually handles. `Unsupported` implements every method by
returning `unwillingToPerform`; embed it and override only the operations you
serve. flapjak implements `Bind`, `Search` and `WhoAmI`.

The error is the result code. Returning `nil` means success. An error that
unwraps to `*ldap.Error` supplies its result code, diagnostic message and
matched DN. Any other error is logged in full and reported to the client as
`operationsError` with a generic message, so internal detail never leaks onto
the wire. This removes the `defer w.Write(resp)` / `SetResultCode` pattern that
a response-object API forces on every handler. `Compare` adds a `bool` for its
answer, which is a result rather than a failure and so does not belong in the
error.

`Search` is the one operation that writes as it goes, because a search is *N*
entries followed by a result:

```go
func (h *Handler) Search(ctx context.Context, r *ldap.SearchRequest, w *ldap.SearchResponse) error {
	for node := range base.All() {
		if !Match(r.Filter, node.Entry) {
			continue
		}
		if err := w.Entry(node.Entry.DN.String(), attrs); err != nil {
			return err
		}
	}
	return nil
}
```

Matching is the caller's to implement: `Filter` is a syntax tree, and this
package has no schema to evaluate it against. flapjak's `Match` walks it in
`filter.go`.

`Bind` handles both authentication choices. `BindRequest.Mechanism` is empty
for a simple bind and otherwise names a SASL mechanism, and the handler decides
what it accepts — the package does not pre-judge it, as with every other
operation. `Unsupported.Bind` declines SASL with `authMethodNotSupported`
rather than `unwillingToPerform`, so a client learns the mechanism was the
problem rather than its credentials.

The mechanism worth having is EXTERNAL (RFC 4422 appendix A), which asks the
server to authenticate the client by something the connection already
established — in practice a client certificate, read from
`r.Conn.TLS.PeerCertificates`. That is what `ldapsearch -Y EXTERNAL` sends.

A SASL bind has an empty `Name` and `Password`, exactly like an anonymous
simple bind. A handler that checks only those two fields will accept a SASL
bind as anonymous and report success for an authentication it never performed.
Check `r.SASL()` first; both handlers in this repository do, and it is the one
real hazard in this API.

Multi-step SASL exchanges are not supported: a handler cannot usefully return
`saslBindInProgress`, because the response carries nowhere to put a server
challenge. EXTERNAL needs no exchange, so this does not limit it.

## Abandon is context cancellation

RFC 4511 gives Abandon no response — the client sends it and the server goes
quiet. gldap routed did not decode and and returned an error to the client, and
the resulting stray response is what upset `nslcd`.

Here, Abandon is not in the `Handler` interface at all. Each in-flight
operation gets a `context.Context` registered against its message ID; an
Abandon cancels it, and the entry goes when the operation returns. Handlers
take a `ctx` and long loops check it. The response writer drops any result
whose context was already cancelled, which handles the race where an operation
finishes just as the Abandon arrives. Everything outstanding is cancelled when
the connection closes.

flapjak has no long-running operations to cancel, so in practice this just
means Abandon is silently correct. But it costs about the same as ignoring it
and generalises properly.

## Extended operations

`ExtendedRequest [APPLICATION 23]` is an extension envelope, not an operation:

```
ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
     requestName   [0] LDAPOID,
     requestValue  [1] OCTET STRING OPTIONAL }
```

An OID names the real operation and the payload is opaque octets whose
structure each extension defines for itself. It exists so operations could be
added after RFC 4511 without minting new `APPLICATION` tags.

Rather than exposing that envelope, the package decodes it, dispatches on the
OID, and surfaces the results as ordinary named methods. No handler ever sees
an OID or a raw payload.

| OID | Operation | Handled by |
|---|---|---|
| `1.3.6.1.4.1.1466.20037` | StartTLS | Server-internal; it's a transport concern |
| `1.3.6.1.4.1.4203.1.11.3` | Who Am I ([RFC 4532]) | `Handler.WhoAmI`, which reads the bound DN from `r.Conn.BindDN` |
| anything else | — | `protocolError`, per RFC 4511 §4.12 |

Password Modify ([RFC 3062]) is not wired up because flapjak is read-only. The
tradeoff is that an embedder cannot add an extension we didn't anticipate
without changing the interface. For a server this size that is fine, and it is
reversible.

## Filters

The BER filter is decoded into an AST and handed to the handler as
`SearchRequest.Filter`. This is the main reason the rewrite is a net deletion:
flapjak previously shipped a hand-written RFC 4515 parser whose only job was to
undo gldap's re-serialisation, and it supported just presence and equality.
Decoding from BER gives every node type structurally, leaving only the matching
semantics to implement.

Filter tags are context-specific:

```
and[0]  or[1]  not[2]  equalityMatch[3]  substrings[4]
greaterOrEqual[5]  lessOrEqual[6]  present[7]  approxMatch[8]  extensibleMatch[9]
```

`present` is primitive; the rest are constructed. Substring components are
`initial[0] any[1] final[2]`.

## Values

`Search` responses take `map[string][]any`, not `map[string][]string`.

This needs care, because it is easy to assume it buys more than it does. In
LDAPv3 every attribute value is an `OCTET STRING` on the wire:

```
AttributeValue ::= OCTET STRING
```

There is no type tagging. X.500's DAP did use real ASN.1 types per attribute
syntax; LDAP dropped that. What a schema's syntax controls is the value space
and matching rules, and [RFC 4517] defines a string transfer encoding for
every syntax:

| Syntax | Wire bytes |
|---|---|
| Integer | `1000` (ASCII decimal) |
| Boolean | `TRUE` / `FALSE`, uppercase |
| Generalized Time | `20260805123000Z` |
| Directory String | UTF-8 |
| Octet String, Certificate, JPEG | raw bytes |

So `[]string` was never wrong — a Go `string` is an arbitrary byte sequence
and holds any of these losslessly. What `[]any` buys is that the RFC 4517
encoding happens once, in `Value(v any) ([]byte, error)`, instead of at every
call site:

| Go type | Wire |
|---|---|
| `string`, `[]byte` | as-is |
| `bool` | `TRUE` / `FALSE` |
| signed and unsigned integers | ASCII decimal |
| `float64` | `strconv.FormatFloat(v, 'f', -1, 64)`, so an integral value renders `1000`, not `1000.0` or `1e+03` |
| `time.Time` | GeneralizedTime |
| `encoding.TextMarshaler`, then `fmt.Stringer` | fallbacks |
| anything else | error |

The larger benefit is on flapjak's side rather than the wire. Because values
keep their Go types through the database, the type can select the comparison —
numeric attributes compare numerically, so `9 < 10` rather than `"10" < "9"`.
That is a poor-man's substitute for the matching rules a schema would otherwise
supply. Every value of a single attribute must therefore share a kind, which is
validated when entries are loaded.

flapjak's kinds are String, Number and Bool, and its numbers are `float64`.
That is the database's own model, not an echo of what jsonnet happens to
provide: a second input source, such as Kubernetes CRDs, would be free to
supply integers, and the kinds would grow to hold them. `Value` above already
encodes every integer type exactly, so only the database side would need to
change.

## Listeners and TLS

The server follows the model of `net/http.Server`: one `Server` serves any
number of listeners, each passed to its own `Serve` call on its own goroutine.

```go
srv := &ldap.Server{Handler: h, TLSConfig: cfg}
go srv.ListenAndServe(":389")
go srv.ListenAndServeTLS(":636")
```

`TLSConfig` is shared, so the same certificate secures LDAPS listeners and
answers StartTLS on plain ones. A listener the caller has already wrapped with
`tls.NewListener` can be passed to `Serve` rather than `ServeTLS`; connections
arriving on it are recognised as secure either way, so they are never offered
StartTLS on an already-encrypted connection.

There is no `Addr` field, unlike `http.Server`. A field naming a single address
would only describe one of several listeners, and callers who want to choose
the listener themselves — for a Unix socket, a socket-activated fd, or a test
on port zero — call `Serve` with their own `net.Listener` and already know its
address.

`Shutdown(ctx)` closes every listener and puts each connection into draining:
requests arriving from then on are refused with `unavailable` (52, defined as
"the server is shutting down"), and a connection closes once the operations
already running on it finish. `Serve` then returns `ErrServerClosed`. The grace
period is the deadline on `ctx`, chosen per shutdown rather than configured on
the server. `Close` skips the waiting and cancels the context of every
operation still running, which handlers observe exactly as they would an
Abandon.

"Operations already running" means search and compare, the two that get their
own goroutines. A draining connection waits on `pending`, a count of operations
that have not finished writing their response, and closes when it reaches zero.
The registry is a separate thing: it maps message ID to cancellation for
Abandon and for refusing a duplicate ID, and an operation leaves it before
writing, which is why the count and the map are not the same question.

Bind, unbind, WhoAmI and StartTLS run inline on the read loop and are counted by
neither the `pending` count or registry, so a shutdown does not wait for one
that is inside its handler: the connection closes under it and its response is
not delivered. Tracking them would put the read loop in and out of the count
around every operation to cover a window that lasts a single handler call, and
the handler contract already asks that the three it defines be quick.

Refusing new requests is what makes a graceful shutdown terminate. Waiting for
connections to fall idle is not enough on its own: one long operation, or
overlapping ones, keeps a connection busy for as long as the client cares to,
so the only way out would be the deadline expiring and `Close` dropping it
mid-operation — precisely the case a graceful shutdown exists to handle.

Nothing is written to a client from the shutdown goroutine. Writes belong to
the read loop and the operation goroutines, and a StartTLS upgrade may be in
flight; the `unavailable` results are how a client learns the server is going
away. This is why no Notice of Disconnection is sent.

StartTLS never reaches the handler. Per [RFC 4513] it is refused if TLS is
already active or if operations are outstanding, and it resets the connection's
bind state to anonymous.

## Connection model

Each connection runs one reader goroutine and a goroutine per in-flight
operation. The read loop is the only reader. Search and compare, the two that
can be abandoned, are dispatched to their own goroutines so an Abandon has
something to cancel; bind, unbind, abandon, StartTLS and WhoAmI run inline on
the read loop. Bind additionally waits for outstanding operations to drain, per
RFC 4511 §4.2.1, since it changes the connection's authorisation state.

That split is what keeps the locking small. Two mutexes cover it. `opsMu`
guards the operation registry, a `map[int32]context.CancelFunc`, together with
the `pending` count and the draining flag, all three written by the read loop
and the operation goroutines and read by `Shutdown` to find connections that
are still busy. `writeMu` serialises writes and guards the transport, below.

The transport — the `net.Conn`, its `bufio.Reader` and its TLS state — is one
value replaced wholesale by StartTLS rather than mutated field by field, so a
reader never sees a half-upgraded mixture. Only the read loop replaces it, and
`writeMu` is what guards the replacement against the operation goroutines: they
reach the field only through `writeLocked`, and StartTLS holds `writeMu` from
before its success response through to the swap. That hold does double duty,
since it is also what stops a leftover cleartext response landing in the middle
of the client's handshake. A write that reaches the transport without `writeMu`
needs its own answer to this — it is the one invariant here that a future
change could silently break.

Neither the registry nor the `pending` count can serve as that guard. An
operation leaves the registry before writing its response, and that ordering is
deliberate: RFC 4511 §4.1.1.1 lets a client reuse a message ID as soon as the
operation using it has completed, so the ID has to be free by the time the
response that completes it can be seen, and releasing it after the write would
leave a window in which a perfectly legal reuse is refused as already in
progress. `pending` is released after the write and so does bound the writes,
but StartTLS reads it before the swap rather than holding it across, which is
the part that matters. The outstanding-operations check is the RFC 4513 rule
about when an upgrade is allowed; `writeMu` is the memory guard.

The socket as accepted is kept separately as `raw` and never replaced. `close`
uses that rather than the transport, which matters twice over: `close` is
called from the shutdown goroutine, so reading a field the read loop replaces
would be a genuine race; and closing the socket directly cannot block, where
closing an upgraded transport would send a TLS `close_notify` alert that a peer
which has stopped reading could stall. Since a forced close exists precisely to
tear down a connection that is not making progress, it must never be the thing
that blocks. Closing the socket tears down any TLS session built on it just as
effectively.

Everything else — `bindDN` included — belongs to the read loop alone and is
synchronised by nothing, because nothing else touches it. Every request
snapshot is taken on the read loop before its goroutine starts, which is what
makes that true.

Writes are serialised by a mutex. That one is irreducible: message IDs
interleave on the wire, so two operations responding at once must not
interleave their bytes. A writer goroutine fed by a channel would replace the
mutex with a goroutine, a channel and a shutdown ordering problem, which is not
a trade worth making.

A failed write closes the connection. A `WriteTimeout` can expire partway
through a message, and what is left on the wire is a truncated element the
client cannot decode. Only the read loop ends the connection by returning an
error, so without this an operation goroutine's failed write would be logged
and the connection left carrying a corrupt stream.

## TLS state, not a TLS flag

`ConnInfo.TLS` is a `*tls.ConnectionState`, nil when the connection is not
encrypted. Being nil is what "not a TLS connection" means; there is no
separate boolean that could disagree with it. Handlers get the cipher and
version for logging, and `PeerCertificates` for authenticating a client by
certificate.

This requires completing the handshake before the first operation is
dispatched, which the connection does explicitly when it starts rather than
leaving it to the first read. That is worth doing on its own: a failed LDAPS
handshake is now reported as a handshake failure instead of surfacing later as
an unreadable message.

A listener the caller has already wrapped with `tls.NewListener` and passed to
`Serve` rather than `ServeTLS` is handled the same way, since the connection is
inspected rather than the way it was served.

## Notes and gotchas

Things that are easy to get wrong and expensive to debug:

- `SearchResultReference` is `[APPLICATION 19]`, not 6. The application tags
  are not contiguous with the request/response pairs.
- A control with `criticality: TRUE` that the server does not recognise must be
  answered `unavailableCriticalExtension` (12) without invoking the handler.
  The recognised set is currently empty.
- LDAP encodes boolean `TRUE` as `0xFF`, where BER in general uses any non-zero
  byte. Nothing here encodes a boolean — only `typesOnly` and control
  criticality are read — and both decode paths treat any non-zero byte as true,
  so both spellings are accepted. Code that starts writing booleans needs
  `ber.NewLDAPBoolean` rather than `ber.NewBoolean`.
- `ber.MaxPacketLengthBytes` is a package-level global in go-asn1-ber, so it
  cannot be scoped per connection. It is left at its default: `readElement`
  refuses anything larger than `MaxMessageSize` from the length octets alone,
  before `ber.ReadPacket` sees the message.
- StartTLS is refused if anything is already buffered from the client.
  `tls.Server` wraps the socket, not the buffered reader, so bytes that arrived
  before the handshake would be dropped on upgrade rather than protected — the
  hole that STARTTLS command injection exploits elsewhere. Pipelining is legal
  in LDAP generally, so this is checked only once an upgrade is certain.
- A `CompareResponse` has no field for the answer. RFC 4511 §4.10 carries it as
  the result code `compareTrue` (6) or `compareFalse` (5), so a compare never
  returns `success`. The `Handler` method answers with a `bool` and the package
  maps it, which is why those two codes are unexported.
- LDIF base64-encodes values that aren't safe UTF-8 (the `::` separator). That
  is a property of the text format, not of the wire protocol — it does not mean
  anything was encoded differently in the response.

[gldap]: https://github.com/jimlambrt/gldap
[go-asn1-ber]: https://github.com/go-asn1-ber/asn1-ber
[RFC 3062]: https://datatracker.ietf.org/doc/html/rfc3062
[RFC 4513]: https://datatracker.ietf.org/doc/html/rfc4513
[RFC 4517]: https://datatracker.ietf.org/doc/html/rfc4517
[RFC 4532]: https://datatracker.ietf.org/doc/html/rfc4532
