package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // matching the scheme the server implements
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"foxygo.at/flapjak/ldap"
	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/matryer/is"
)

const testWait = 5 * time.Second

// sshaPassword returns an RFC 2307 {SSHA} hash of password, the form flapjak
// authenticates against.
func sshaPassword(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("read salt: %v", err)
	}
	h := sha1.New() //nolint:gosec // the scheme is defined to use SHA-1
	h.Write([]byte(password))
	h.Write(salt)
	return "{SSHA}" + base64.StdEncoding.EncodeToString(append(h.Sum(nil), salt...))
}

// startFlapjak loads entries from JSON, serves them, and returns a connected
// client. This exercises the whole path from the file to the wire.
func startFlapjak(t *testing.T, entriesJSON string) *goldap.Conn {
	t.Helper()
	is := is.New(t)

	entries, err := ReadJSON(strings.NewReader(entriesJSON))
	is.NoErr(err)

	db := NewDB()
	is.NoErr(db.AddEntries(entries))

	// Driven through the embedded server so the test can supply its own
	// listener and discover the port; Run takes an address instead.
	srv := NewServer(db).ldap
	srv.Logger = slog.New(slog.DiscardHandler)

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	is.NoErr(err)

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()

	t.Cleanup(func() {
		// Not t.Context(): it is cancelled before cleanup runs, which
		// would leave the shutdown no grace period at all.
		ctx, cancel := context.WithTimeout(context.Background(), testWait)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown returned %v", err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, ldap.ErrServerClosed) {
				t.Errorf("Serve returned %v, want ErrServerClosed", err)
			}
		case <-time.After(testWait):
			t.Error("Serve did not return after Shutdown")
		}
	})

	c, err := goldap.DialURL("ldap://" + ln.Addr().String())
	is.NoErr(err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func testEntries(t *testing.T) string {
	t.Helper()
	return `[
	  {"dn": "dc=example,dc=com", "objectClass": "domain", "dc": "example"},
	  {
	    "dn": "uid=alice,dc=example,dc=com",
	    "objectClass": "posixAccount",
	    "uid": "alice",
	    "cn": "Alice Aardvark",
	    "uidNumber": 1000,
	    "gidNumber": 1000,
	    "enabled": true,
	    "userPassword": "` + sshaPassword(t, "hunter2") + `"
	  },
	  {
	    "dn": "uid=other,dc=example,dc=com",
	    "objectClass": "posixAccount",
	    "uid": "other",
	    "cn": "Other User",
	    "uidNumber": 9,
	    "gidNumber": 9
	  }
	]`
}

func search(t *testing.T, c *goldap.Conn, filter string, attrs []string) *goldap.SearchResult {
	t.Helper()
	is := is.New(t)
	res, err := c.Search(goldap.NewSearchRequest(
		"dc=example,dc=com", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil))
	is.NoErr(err)
	return res
}

// TestEndToEnd drives the server the way a real client does.
func TestEndToEnd(t *testing.T) {
	c := startFlapjak(t, testEntries(t))

	t.Run("anonymous search", func(t *testing.T) {
		is := is.New(t)
		res := search(t, c, "(objectClass=*)", nil)
		is.Equal(len(res.Entries), 3)
	})

	t.Run("bind", func(t *testing.T) {
		is := is.New(t)
		is.NoErr(c.Bind("uid=alice,dc=example,dc=com", "hunter2"))
	})

	t.Run("whoami", func(t *testing.T) {
		is := is.New(t)
		// Bound here rather than relying on the bind subtest, so this
		// one can be run on its own.
		is.NoErr(c.Bind("uid=alice,dc=example,dc=com", "hunter2"))

		res, err := c.WhoAmI(nil)
		is.NoErr(err)
		is.Equal(res.AuthzID, "dn:uid=alice,dc=example,dc=com")
	})

	t.Run("bad password", func(t *testing.T) {
		is := is.New(t)
		err := c.Bind("uid=alice,dc=example,dc=com", "wrong")
		is.True(err != nil)
		var lerr *goldap.Error
		is.True(errors.As(err, &lerr))
		is.Equal(lerr.ResultCode, uint16(ldap.InvalidCredentials))
	})

	t.Run("numbers are served as bare integers", func(t *testing.T) {
		is := is.New(t)
		res := search(t, c, "(uid=alice)", []string{"uidNumber", "enabled"})
		is.Equal(len(res.Entries), 1)
		// jsonnet numbers arrive as float64 but must not render as
		// "1000.0" or "1e+03" on the wire.
		is.Equal(res.Entries[0].GetAttributeValue("uidNumber"), "1000")
		is.Equal(res.Entries[0].GetAttributeValue("enabled"), "TRUE")
	})

	t.Run("numeric filters compare numerically", func(t *testing.T) {
		is := is.New(t)
		// uidNumber 1000 and 9 both match, though "1000" < "9" as strings.
		res := search(t, c, "(uidNumber>=9)", []string{"uid"})
		is.Equal(len(res.Entries), 2)

		res = search(t, c, "(uidNumber>=1000)", []string{"uid"})
		is.Equal(len(res.Entries), 1)
		is.Equal(res.Entries[0].GetAttributeValue("uid"), "alice")

		res = search(t, c, "(uidNumber<=9)", []string{"uid"})
		is.Equal(len(res.Entries), 1)
		is.Equal(res.Entries[0].GetAttributeValue("uid"), "other")
	})

	t.Run("substring filters", func(t *testing.T) {
		is := is.New(t)
		res := search(t, c, "(cn=Ali*)", []string{"uid"})
		is.Equal(len(res.Entries), 1)
		is.Equal(res.Entries[0].GetAttributeValue("uid"), "alice")

		res = search(t, c, "(cn=*User)", []string{"uid"})
		is.Equal(len(res.Entries), 1)
		is.Equal(res.Entries[0].GetAttributeValue("uid"), "other")
	})

	t.Run("extensible match is refused", func(t *testing.T) {
		is := is.New(t)
		// Undefined is the right answer and Match cannot give it, so a
		// negated extensible match would otherwise return every entry.
		_, err := c.Search(goldap.NewSearchRequest(
			"dc=example,dc=com", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			0, 0, false, "(!(uid:caseExactMatch:=alice))", nil, nil))
		is.True(err != nil)
		var lerr *goldap.Error
		is.True(errors.As(err, &lerr))
		is.Equal(lerr.ResultCode, uint16(ldap.InappropriateMatching))
	})

	t.Run("passwords are never returned", func(t *testing.T) {
		is := is.New(t)
		res := search(t, c, "(uid=alice)", nil)
		is.Equal(len(res.Entries), 1)
		is.Equal(res.Entries[0].GetAttributeValue("userPassword"), "")

		// Not even when asked for by name.
		res = search(t, c, "(uid=alice)", []string{"userPassword"})
		is.Equal(len(res.Entries), 1)
		is.Equal(len(res.Entries[0].Attributes), 0)
	})

	t.Run("scopes", func(t *testing.T) {
		is := is.New(t)
		res, err := c.Search(goldap.NewSearchRequest(
			"dc=example,dc=com", goldap.ScopeBaseObject, goldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", nil, nil))
		is.NoErr(err)
		is.Equal(len(res.Entries), 1)

		res, err = c.Search(goldap.NewSearchRequest(
			"dc=example,dc=com", goldap.ScopeSingleLevel, goldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", nil, nil))
		is.NoErr(err)
		is.Equal(len(res.Entries), 2)
	})

	t.Run("unknown base DN", func(t *testing.T) {
		is := is.New(t)
		_, err := c.Search(goldap.NewSearchRequest(
			"dc=nowhere,dc=com", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", nil, nil))
		is.True(err != nil)
		var lerr *goldap.Error
		is.True(errors.As(err, &lerr))
		is.Equal(lerr.ResultCode, uint16(ldap.NoSuchObject))
	})

	t.Run("writes are declined", func(t *testing.T) {
		is := is.New(t)
		err := c.Del(goldap.NewDelRequest("uid=alice,dc=example,dc=com", nil))
		is.True(err != nil)
		var lerr *goldap.Error
		is.True(errors.As(err, &lerr))
		is.Equal(lerr.ResultCode, uint16(ldap.UnwillingToPerform))
	})
}

// TestAttributeValueKinds checks which Go types the database accepts as
// attribute values. Numbers are float64; there is no integer kind, so nothing
// silently degrades an integer to a float on the way in.
func TestAttributeValueKinds(t *testing.T) {
	is := is.New(t)

	e, err := NewEntryFromMap(map[string]any{
		"dn":          "dc=example,dc=com",
		"objectClass": "domain",
		"num":         float64(1000),
		"flag":        true,
	})
	is.NoErr(err)

	num, ok := e.GetAttr("num")
	is.True(ok)
	is.Equal(num.Kind, KindNumber)

	flag, ok := e.GetAttr("flag")
	is.True(ok)
	is.Equal(flag.Kind, KindBool)

	_, err = NewEntryFromMap(map[string]any{
		"dn":          "dc=example,dc=com",
		"objectClass": "domain",
		"num":         1000, // an int is not a value the database stores
	})
	is.True(errors.Is(err, ErrInvalidAttrValue))
}

// TestMixedAttributeKinds checks that an attribute cannot hold values of
// different kinds, since there would be no sensible way to compare them.
func TestMixedAttributeKinds(t *testing.T) {
	is := is.New(t)

	_, err := ReadJSON(strings.NewReader(`[{
	  "dn": "dc=example,dc=com",
	  "objectClass": "domain",
	  "mixed": ["a string", 1000]
	}]`))
	is.True(errors.Is(err, ErrMixedAttrKinds))
}

// TestServerTimeouts checks that the connection timeouts are configured. The
// ldap package treats zero as no limit, so dropping either of these would leave
// a quiet client holding a goroutine and a file descriptor indefinitely.
func TestServerTimeouts(t *testing.T) {
	is := is.New(t)

	s := NewServer(NewDB())
	is.True(s.ldap.IdleTimeout > 0)
	is.True(s.ldap.WriteTimeout > 0)
}

// TestSearchSizeLimit checks that a search returns no more entries than the
// request asked for, and says why it stopped.
func TestSearchSizeLimit(t *testing.T) {
	is := is.New(t)

	c := startFlapjak(t, testEntries(t))

	// The tree holds three entries; two of them is a limit it can exceed.
	_, err := c.Search(goldap.NewSearchRequest(
		"dc=example,dc=com", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, 0, false, "(objectClass=*)", nil, nil))
	is.True(goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded))

	// A limit the search stays within is not reported as exceeded.
	res, err := c.Search(goldap.NewSearchRequest(
		"dc=example,dc=com", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		3, 0, false, "(objectClass=*)", nil, nil))
	is.NoErr(err)
	is.Equal(len(res.Entries), 3)
}

// searchRequest encodes a whole-subtree search for (objectClass=*) under
// baseDN as message ID 1. It is built by hand because the client below must
// not read the response, and a go-ldap client always drains one.
func searchRequest(baseDN string) []byte {
	const tagSearchRequest, tagPresent = 3, 7

	s := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tagSearchRequest, nil, "SearchRequest")
	s.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, baseDN, "baseObject"))
	s.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(2), "scope"))
	s.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "derefAliases"))
	s.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "sizeLimit"))
	s.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "timeLimit"))
	s.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))

	f := ber.Encode(ber.ClassContext, ber.TypePrimitive, tagPresent, nil, "present")
	f.Data.Write([]byte("objectClass"))
	s.AppendChild(f)
	s.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))

	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "messageID"))
	m.AppendChild(s)
	return m.Bytes()
}

// TestRunReportsIncompleteShutdown checks that Run reports a shutdown that ran
// out of grace rather than returning nil. The exit status is the only signal an
// operator gets that live operations were dropped, so a forced close must not
// look like a clean stop.
//
// The server is held busy by a client that sends a search and then stops
// reading. The response is larger than any socket buffer, so the write blocks
// and the search stays outstanding until the grace period expires.
func TestRunReportsIncompleteShutdown(t *testing.T) {
	is := is.New(t)

	logger := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	grace := shutdownGrace
	shutdownGrace = 200 * time.Millisecond
	t.Cleanup(func() {
		slog.SetDefault(logger)
		shutdownGrace = grace
	})

	db := NewDB()
	dbEntries := []map[string]any{
		{"dn": "dc=com", "objectClass": "domain"},
		{"dn": "dc=example,dc=com", "objectClass": "domain"},
		// The blob is what makes the response outrun the socket buffers.
		{"dn": "cn=big,dc=example,dc=com", "objectClass": "top", "blob": strings.Repeat("x", 8<<20)},
	}
	entries := make([]*Entry, 0, len(dbEntries))
	for _, m := range dbEntries {
		e, err := NewEntryFromMap(m)
		is.NoErr(err)
		entries = append(entries, e)
	}
	is.NoErr(db.AddEntries(entries))

	// Run takes an address rather than a listener, so the port must be
	// chosen up front and released for Run to claim.
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	is.NoErr(err)
	addr := ln.Addr().String()
	is.NoErr(ln.Close())

	ctx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error, 1)
	go func() { runErr <- NewServer(db).Run(ctx, addr) }()

	var nc net.Conn
	var d net.Dialer
	for range 100 {
		if nc, err = d.DialContext(t.Context(), "tcp", addr); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	is.NoErr(err) // Run never started listening
	t.Cleanup(func() { _ = nc.Close() })

	_, err = nc.Write(searchRequest("dc=example,dc=com"))
	is.NoErr(err)

	// One byte proves the server is writing the entry, so the search is
	// registered and holding the connection open. Leaving the rest unread
	// is what blocks the write past the grace period.
	is.NoErr(nc.SetReadDeadline(time.Now().Add(testWait)))
	var b [1]byte
	_, err = nc.Read(b[:])
	is.NoErr(err)

	cancel()
	select {
	case err := <-runErr:
		is.True(err != nil) // dropped operations must not exit clean
		is.True(strings.Contains(err.Error(), "graceful shutdown"))
	case <-time.After(testWait):
		t.Fatal("Run did not return")
	}
}

// TestBindErrorsCarryTheirCause checks that a failed bind returns the cause
// behind the result the client is given. The ldap package logs the error the
// handler returns, so wrapping is what puts the real reason in the log while
// the client still learns only the result code. Returning a bare result code
// made a malformed hash, an entry that cannot authenticate and a wrong
// password indistinguishable in the log.
func TestBindErrorsCarryTheirCause(t *testing.T) {
	is := is.New(t)

	entries, err := ReadJSON(strings.NewReader(testEntries(t)))
	is.NoErr(err)
	db := NewDB()
	is.NoErr(db.AddEntries(entries))
	h := &Handler{db: db}

	tests := []struct {
		name string
		dn   string
		pw   string
		code ldap.Code
		// diagnostic is what the client is told. It is empty for every
		// failure of the credential check, which must not say which
		// part failed.
		diagnostic string
		// cause is what the log is told, where there is a sentinel to
		// match. ParseRDN has none, so the malformed DN row leaves it
		// nil and the chain is checked for carrying anything at all.
		cause error
	}{
		{
			// Syntax is not a credential, so this one says why.
			name: "malformed DN", dn: "not a dn", pw: "x",
			code: ldap.InvalidDNSyntax, diagnostic: "malformed bind DN",
		},
		{
			name: "unknown DN", dn: "uid=nobody,dc=example,dc=com", pw: "x",
			code: ldap.InvalidCredentials, cause: errNoSuchEntry,
		},
		{
			name: "wrong password", dn: "uid=alice,dc=example,dc=com", pw: "wrong",
			code: ldap.InvalidCredentials, cause: ErrAuthenticationFailed,
		},
		{
			// dc=example,dc=com is a domain, not an account.
			name: "entry cannot authenticate", dn: "dc=example,dc=com", pw: "x",
			code: ldap.InvalidCredentials, cause: ErrInvalidEntryForAuth,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			err := h.Bind(t.Context(), &ldap.BindRequest{Name: tt.dn, Password: tt.pw})
			is.True(err != nil)

			// The result the client is given.
			lerr, ok := errors.AsType[*ldap.Error](err)
			is.True(ok)
			is.Equal(lerr.Code, tt.code)
			is.Equal(lerr.Diagnostic, tt.diagnostic)

			// The cause the log is given.
			if tt.cause != nil {
				is.True(errors.Is(err, tt.cause))
			} else {
				is.True(err.Error() != lerr.Error()) // a cause rode along
			}
		})
	}
}
