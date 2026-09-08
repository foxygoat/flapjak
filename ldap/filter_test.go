package ldap

import (
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/matryer/is"
)

// TestDecodeFilter round-trips filters through go-ldap's RFC 4515 compiler and
// back out through this package's decoder and String method. Using an
// independent encoder checks the wire format, not just our own symmetry.
func TestDecodeFilter(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "present", in: "(objectClass=*)"},
		{name: "equality", in: "(cn=foo)"},
		{name: "greaterOrEqual", in: "(uidNumber>=1000)"},
		{name: "lessOrEqual", in: "(uidNumber<=2000)"},
		{name: "approx", in: "(cn~=foo)"},
		{name: "not", in: "(!(cn=foo))"},
		{name: "and", in: "(&(cn=foo)(objectClass=posixAccount))"},
		{name: "or", in: "(|(cn=foo)(cn=other))"},
		{name: "nested", in: "(&(|(cn=a)(cn=b))(!(uid=c)))"},
		{name: "substring initial", in: "(cn=foo*)"},
		{name: "substring final", in: "(cn=*foo)"},
		{name: "substring any", in: "(cn=*foo*)"},
		{name: "substring all", in: "(cn=a*b*c*d)"},
		{name: "escaped star", in: `(cn=foo\2a)`},
		{name: "escaped parens", in: `(cn=\28x\29)`},
		{name: "escaped backslash", in: `(cn=a\5cb)`},
		{name: "escaped nul", in: `(cn=a\00b)`},
		{name: "extensible with rule", in: "(cn:caseExactMatch:=foo)"},
		{name: "extensible dn", in: "(cn:dn:caseExactMatch:=foo)"},
		{name: "extensible no rule", in: "(cn:=foo)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			pkt, err := goldap.CompileFilter(tt.in)
			is.NoErr(err) // go-ldap must be able to compile the filter

			f, err := decodeFilter(pkt)
			is.NoErr(err) // decodeFilter must accept go-ldap's encoding
			is.Equal(f.String(), tt.in)
		})
	}
}

// TestDecodeFilterValues checks the decoded structure, not just its string
// form, for the cases where the structure carries more than String shows.
func TestDecodeFilterValues(t *testing.T) {
	is := is.New(t)

	pkt, err := goldap.CompileFilter("(cn=a*b*c*d)")
	is.NoErr(err)
	f, err := decodeFilter(pkt)
	is.NoErr(err)

	sub, ok := f.(Substrings)
	is.True(ok) // must decode to Substrings
	is.Equal(sub.Attribute, "cn")
	is.Equal(sub.Initial, "a")
	is.Equal(sub.Any, []string{"b", "c"})
	is.Equal(sub.Final, "d")

	// present is a primitive context-tagged packet, the case where
	// go-asn1-ber leaves ByteValue empty.
	pkt, err = goldap.CompileFilter("(objectClass=*)")
	is.NoErr(err)
	f, err = decodeFilter(pkt)
	is.NoErr(err)
	p, ok := f.(Present)
	is.True(ok) // must decode to Present
	is.Equal(p.Attribute, "objectClass")

	// An equality value holding a NUL byte must survive decoding intact.
	pkt, err = goldap.CompileFilter(`(cn=a\00b)`)
	is.NoErr(err)
	f, err = decodeFilter(pkt)
	is.NoErr(err)
	eq, ok := f.(Equality)
	is.True(ok) // must decode to Equality
	is.Equal(eq.Value, "a\x00b")
}

func TestDecodeFilterErrors(t *testing.T) {
	is := is.New(t)

	// A universal-class packet is not a filter.
	pkt, err := goldap.CompileFilter("(cn=foo)")
	is.NoErr(err)
	pkt.ClassType = 0 // ber.ClassUniversal
	_, err = decodeFilter(pkt)
	is.True(err != nil) // universal class must be rejected

	pkt, err = goldap.CompileFilter("(cn=foo)")
	is.NoErr(err)
	pkt.Tag = 30 // not a filter tag
	_, err = decodeFilter(pkt)
	is.True(err != nil) // unknown filter tag must be rejected
}
