package main

import (
	"testing"

	"foxygo.at/flapjak/ldap"
	"github.com/matryer/is"
)

// testEntry is the entry every filter test matches against. The attributes
// deliberately cover each kind, since the kind is what selects how values
// compare in the absence of a schema. userPassword is here so that the
// sensitive-attribute cases have something to fail to find.
func testEntry(t *testing.T) *Entry {
	t.Helper()
	is := is.New(t)
	e, err := NewEntryFromMap(map[string]any{
		"dn":           "dc=example,dc=com",
		"objectClass":  "top",
		"uid":          "1234",
		"cn":           []any{"Alice", "second"},
		"uidNumber":    float64(1000),
		"enabled":      true,
		"userPassword": "{SSHA}abcdef0123456789",
	})
	is.NoErr(err)
	return e
}

// testView is testEntry as an anonymous client sees it, which is what Match
// takes.
func testView(t *testing.T) EntryView {
	t.Helper()
	return testEntry(t).View("")
}

func Test_FilterMatch(t *testing.T) {
	tests := []struct {
		name   string
		filter ldap.Filter
		want   bool
	}{
		{name: "present", filter: ldap.Present{Attribute: "uid"}, want: true},
		{name: "not present", filter: ldap.Present{Attribute: "sn"}, want: false},
		{name: "present is case insensitive", filter: ldap.Present{Attribute: "UID"}, want: true},

		{name: "equal", filter: ldap.Equality{Attribute: "uid", Value: "1234"}, want: true},
		{name: "not equal", filter: ldap.Equality{Attribute: "uid", Value: "1235"}, want: false},
		{name: "equal missing attr", filter: ldap.Equality{Attribute: "cn2", Value: "x"}, want: false},
		// Strings compare case-insensitively, as caseIgnoreMatch would.
		{name: "equal ignores case", filter: ldap.Equality{Attribute: "cn", Value: "ALICE"}, want: true},
		{name: "equal second value", filter: ldap.Equality{Attribute: "cn", Value: "second"}, want: true},

		// The point of keeping jsonnet's types: numbers compare
		// numerically. As strings, "1000" would sort before "9".
		{name: "number equal", filter: ldap.Equality{Attribute: "uidNumber", Value: "1000"}, want: true},
		{name: "number not equal", filter: ldap.Equality{Attribute: "uidNumber", Value: "1001"}, want: false},
		{name: "number ge smaller", filter: ldap.GreaterOrEqual{Attribute: "uidNumber", Value: "9"}, want: true},
		{name: "number ge equal", filter: ldap.GreaterOrEqual{Attribute: "uidNumber", Value: "1000"}, want: true},
		{name: "number ge larger", filter: ldap.GreaterOrEqual{Attribute: "uidNumber", Value: "1001"}, want: false},
		{name: "number le larger", filter: ldap.LessOrEqual{Attribute: "uidNumber", Value: "9999"}, want: true},
		{name: "number le smaller", filter: ldap.LessOrEqual{Attribute: "uidNumber", Value: "9"}, want: false},
		{name: "number vs non-number", filter: ldap.Equality{Attribute: "uidNumber", Value: "abc"}, want: false},
		// NaN parses as a float but has no useful ordering: without
		// refusing it, cmp.Compare would sort it below every value and
		// make a >= assertion match everything.
		{name: "number equal NaN", filter: ldap.Equality{Attribute: "uidNumber", Value: "NaN"}, want: false},
		{name: "number ge NaN", filter: ldap.GreaterOrEqual{Attribute: "uidNumber", Value: "NaN"}, want: false},
		{name: "number le NaN", filter: ldap.LessOrEqual{Attribute: "uidNumber", Value: "NaN"}, want: false},

		// Booleans accept the RFC 4517 spelling and Go's.
		{name: "bool TRUE", filter: ldap.Equality{Attribute: "enabled", Value: "TRUE"}, want: true},
		{name: "bool true", filter: ldap.Equality{Attribute: "enabled", Value: "true"}, want: true},
		{name: "bool FALSE", filter: ldap.Equality{Attribute: "enabled", Value: "FALSE"}, want: false},
		{name: "bool nonsense", filter: ldap.Equality{Attribute: "enabled", Value: "yes"}, want: false},

		{name: "substring initial", filter: ldap.Substrings{Attribute: "cn", Initial: "Ali"}, want: true},
		{name: "substring initial no match", filter: ldap.Substrings{Attribute: "cn", Initial: "xyz"}, want: false},
		{name: "substring final", filter: ldap.Substrings{Attribute: "cn", Final: "ice"}, want: true},
		{name: "substring any", filter: ldap.Substrings{Attribute: "cn", Any: []string{"ic"}}, want: true},
		{
			name:   "substring initial and final",
			filter: ldap.Substrings{Attribute: "cn", Initial: "A", Final: "e"},
			want:   true,
		},
		{
			name:   "substring ordered any",
			filter: ldap.Substrings{Attribute: "cn", Any: []string{"A", "c"}},
			want:   true,
		},
		{
			name:   "substring out of order any",
			filter: ldap.Substrings{Attribute: "cn", Any: []string{"c", "A"}},
			want:   false,
		},
		// Substrings work against non-string values through their wire form.
		{name: "substring on number", filter: ldap.Substrings{Attribute: "uidNumber", Initial: "10"}, want: true},

		// Without a schema, approximate matching is equality.
		{name: "approx", filter: ldap.Approx{Attribute: "uid", Value: "1234"}, want: true},
		{name: "approx no match", filter: ldap.Approx{Attribute: "uid", Value: "9999"}, want: false},

		// There is no matching rule to look up, so this always fails.
		{
			name:   "extensible match",
			filter: ldap.ExtensibleMatch{Attribute: "uid", Value: "1234", MatchingRule: "caseExactMatch"},
			want:   false,
		},

		{
			name: "and true",
			filter: ldap.And{
				ldap.Present{Attribute: "objectClass"},
				ldap.Equality{Attribute: "uid", Value: "1234"},
			},
			want: true,
		},
		{
			name: "and false",
			filter: ldap.And{
				ldap.Present{Attribute: "objectClass"},
				ldap.Equality{Attribute: "uid", Value: "1235"},
			},
			want: false,
		},
		{name: "empty and matches", filter: ldap.And{}, want: true},
		{
			name: "or true",
			filter: ldap.Or{
				ldap.Present{Attribute: "sn"},
				ldap.Equality{Attribute: "uid", Value: "1234"},
			},
			want: true,
		},
		{
			name: "or false",
			filter: ldap.Or{
				ldap.Present{Attribute: "sn"},
				ldap.Equality{Attribute: "uid", Value: "1235"},
			},
			want: false,
		},
		{name: "empty or does not match", filter: ldap.Or{}, want: false},
		{name: "not true", filter: ldap.Not{Filter: ldap.Present{Attribute: "sn"}}, want: true},
		{name: "not false", filter: ldap.Not{Filter: ldap.Present{Attribute: "uid"}}, want: false},
		{
			name: "nested",
			filter: ldap.And{
				ldap.Present{Attribute: "objectClass"},
				ldap.Or{
					ldap.Equality{Attribute: "uid", Value: "nope"},
					ldap.Not{Filter: ldap.Present{Attribute: "sn"}},
				},
			},
			want: true,
		},

		// A sensitive attribute is absent as far as a filter is
		// concerned. Without this, substring and ordering filters
		// recover a password hash a character at a time.
		{name: "sensitive not present", filter: ldap.Present{Attribute: "userPassword"}, want: false},
		{
			name:   "sensitive not equal",
			filter: ldap.Equality{Attribute: "userPassword", Value: "{SSHA}abcdef0123456789"},
			want:   false,
		},
		{
			name:   "sensitive prefix does not match",
			filter: ldap.Substrings{Attribute: "userPassword", Initial: "{SSHA}a"},
			want:   false,
		},
		{
			name:   "sensitive is not ordered",
			filter: ldap.GreaterOrEqual{Attribute: "userPassword", Value: "{SSHA}a"},
			want:   false,
		},
		{
			name:   "sensitive is not approximate",
			filter: ldap.Approx{Attribute: "userPassword", Value: "{SSHA}abcdef0123456789"},
			want:   false,
		},
		// Not of an absent attribute is true, as it is for any other
		// attribute the entry does not have.
		{
			name:   "sensitive negated presence matches",
			filter: ldap.Not{Filter: ldap.Present{Attribute: "userPassword"}},
			want:   true,
		},
	}

	view := testView(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(Match(tt.filter, view), tt.want)
		})
	}
}

// Test_FilterMatch_NumericOrdering is the case that a schema-less server gets
// wrong when it compares every value as a string.
func Test_FilterMatch_NumericOrdering(t *testing.T) {
	is := is.New(t)

	e, err := NewEntryFromMap(map[string]any{
		"dn":          "uid=x,dc=example,dc=com",
		"objectClass": "posixAccount",
		"uidNumber":   float64(9),
	})
	is.NoErr(err)
	view := e.View("")

	// 9 < 10 numerically, though "9" > "10" as strings.
	is.True(Match(ldap.LessOrEqual{Attribute: "uidNumber", Value: "10"}, view))
	is.True(!Match(ldap.GreaterOrEqual{Attribute: "uidNumber", Value: "10"}, view))
}

// Test_FilterMatch_NonFiniteAssertion checks that an assertion parsing as a
// float but not as a finite number matches nothing. ParseFloat accepts several
// spellings of the infinities, and honouring one makes a range filter
// degenerate: (uidNumber<=inf) would otherwise match every numeric attribute.
func Test_FilterMatch_NonFiniteAssertion(t *testing.T) {
	is := is.New(t)

	e, err := NewEntryFromMap(map[string]any{
		"dn":          "uid=x,dc=example,dc=com",
		"objectClass": "posixAccount",
		"uidNumber":   float64(9),
	})
	is.NoErr(err)
	view := e.View("")

	// 1e400 overflows rather than parsing, and is here so that the
	// overflow stays rejected alongside the spellings that do parse.
	for _, val := range []string{"inf", "+Inf", "-inf", "infinity", "-Infinity", "nan", "NaN", "1e400"} {
		t.Run(val, func(t *testing.T) {
			is := is.New(t)
			is.True(!Match(ldap.LessOrEqual{Attribute: "uidNumber", Value: val}, view))
			is.True(!Match(ldap.GreaterOrEqual{Attribute: "uidNumber", Value: val}, view))
			is.True(!Match(ldap.Equality{Attribute: "uidNumber", Value: val}, view))
		})
	}
}

// Test_HasExtensibleMatch checks that a search can find an extensible match
// anywhere in a filter, since that is what makes refusing the search possible.
// Match cannot answer one correctly: under a negation, failing selects every
// entry rather than none.
func Test_HasExtensibleMatch(t *testing.T) {
	ext := ldap.ExtensibleMatch{MatchingRule: "caseExactMatch", Attribute: "uid", Value: "1234"}
	uid := ldap.Equality{Attribute: "uid", Value: "1234"}

	tests := []struct {
		name   string
		filter ldap.Filter
		want   bool
	}{
		{name: "bare", filter: ext, want: true},
		{name: "negated", filter: ldap.Not{Filter: ext}, want: true},
		{name: "under and", filter: ldap.And{uid, ext}, want: true},
		{name: "under or", filter: ldap.Or{uid, ext}, want: true},
		{name: "nested", filter: ldap.And{uid, ldap.Or{ldap.Not{Filter: ext}}}, want: true},
		{name: "absent", filter: ldap.And{uid, ldap.Not{Filter: ldap.Present{Attribute: "sn"}}}, want: false},
		{name: "empty and", filter: ldap.And{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(HasExtensibleMatch(tt.filter), tt.want)
		})
	}
}
