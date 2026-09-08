package ldap

import (
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/matryer/is"
)

func TestValue(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{name: "string", in: "foo", want: "foo"},
		{name: "empty string", in: "", want: ""},
		{name: "bytes", in: []byte{0x00, 0xff, 0x7f}, want: "\x00\xff\x7f"},
		{name: "true", in: true, want: "TRUE"},
		{name: "false", in: false, want: "FALSE"},
		{name: "int", in: 1000, want: "1000"},
		{name: "negative int", in: -1, want: "-1"},
		{name: "int64", in: int64(1) << 40, want: "1099511627776"},
		{name: "uint", in: uint(7), want: "7"},
		{name: "byte", in: uint8(200), want: "200"},
		// jsonnet and JSON deliver every number as a float64, so an
		// integral one has to render without a fractional part.
		{name: "integral float", in: float64(1000), want: "1000"},
		{name: "large integral float", in: float64(1e21), want: "1000000000000000000000"},
		{name: "fractional float", in: 1.5, want: "1.5"},
		{name: "float32", in: float32(2.5), want: "2.5"},
		{name: "time UTC", in: time.Date(2026, 8, 5, 12, 30, 0, 0, time.UTC), want: "20260805123000Z"},
		{
			name: "time with offset",
			in:   time.Date(2026, 8, 5, 12, 30, 0, 0, time.FixedZone("AEST", 10*60*60)),
			want: "20260805123000+1000",
		},
		// net.IP implements fmt.Stringer, standing in for any type that
		// knows how to render itself.
		{name: "stringer", in: net.IPv4(10, 0, 0, 1), want: "10.0.0.1"},
		{name: "textmarshaler", in: mustURL(t), want: "https://example.com/x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			got, err := Value(tt.in)
			is.NoErr(err)
			is.Equal(string(got), tt.want)
		})
	}
}

func TestValueErrors(t *testing.T) {
	is := is.New(t)

	_, err := Value(nil)
	is.True(errors.Is(err, ErrBadValue)) // LDAP cannot express a nil value

	_, err = Value(struct{ A int }{1})
	is.True(errors.Is(err, ErrBadValue)) // no conversion for arbitrary structs

	_, err = Value(map[string]string{})
	is.True(errors.Is(err, ErrBadValue))
}

func TestValues(t *testing.T) {
	is := is.New(t)

	got, err := values([]any{"a", 1, true})
	is.NoErr(err)
	is.Equal(len(got), 3)
	is.Equal(string(got[0]), "a")
	is.Equal(string(got[1]), "1")
	is.Equal(string(got[2]), "TRUE")

	got, err = values(nil)
	is.NoErr(err)
	is.Equal(len(got), 0)

	// One bad value fails the whole attribute rather than being skipped.
	_, err = values([]any{"a", nil})
	is.True(errors.Is(err, ErrBadValue))
}

func TestCodeString(t *testing.T) {
	is := is.New(t)
	is.Equal(Success.String(), "success")
	is.Equal(UnwillingToPerform.String(), "unwillingToPerform")
	is.Equal(Code(999).String(), "Code(999)")
}

func TestErrorResult(t *testing.T) {
	is := is.New(t)

	code, diag, _ := result(nil)
	is.Equal(code, Success)
	is.Equal(diag, "")

	code, diag, matched := result(&Error{Code: NoSuchObject, Diagnostic: "gone", MatchedDN: "dc=x"})
	is.Equal(code, NoSuchObject)
	is.Equal(diag, "gone")
	is.Equal(matched, "dc=x")

	// A wrapped Error is still found.
	code, _, _ = result(errors.Join(errTest, &Error{Code: InvalidCredentials}))
	is.Equal(code, InvalidCredentials)

	// A decode failure is the client's fault.
	code, _, _ = result(ErrMalformed)
	is.Equal(code, ProtocolError)

	// Anything else is reported without disclosing the cause.
	code, diag, _ = result(errTest)
	is.Equal(code, OperationsError)
	is.Equal(diag, "internal error")
	is.True(diag != errTest.Error()) // the cause must not reach the client
}

// errTest stands in for an unexpected failure inside a handler.
var errTest = errors.New("connection to the mothership failed")

// mustURL returns a *url.URL, which implements encoding.TextMarshaler.
func mustURL(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse("https://example.com/x")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}
