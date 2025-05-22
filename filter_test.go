package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_FilterParse(t *testing.T) {
	type testcase struct {
		name         string
		filter       string
		expectedNode FilterNode
	}

	testfunc := func(t *testing.T, tt testcase) { //nolint:thelper // not a helper
		n, err := Parse(tt.filter)
		require.NoError(t, err)
		require.Equal(t, tt.expectedNode, n)
	}

	// fixtures
	presence := &Presence{Attr: "present"}
	presence2 := &Presence{Attr: "present2"}
	equality := &Equality{Attr: "eq", Value: "eqval"}
	equality2 := &Equality{Attr: "eq", Value: "eqval2"}

	tests := []testcase{
		{
			name:         "presence",
			filter:       "(present=*)",
			expectedNode: presence,
		},
		{
			name:         "equality",
			filter:       "(eq=eqval)",
			expectedNode: equality,
		},
		{
			name:         "and one",
			filter:       "(&(eq=eqval))",
			expectedNode: &And{Nodes: []FilterNode{equality}},
		},
		{
			name:         "and many",
			filter:       "(&(eq=eqval)(present=*))",
			expectedNode: &And{Nodes: []FilterNode{equality, presence}},
		},
		{
			name:         "or one",
			filter:       "(|(eq=eqval))",
			expectedNode: &Or{Nodes: []FilterNode{equality}},
		},
		{
			name:         "or many",
			filter:       "(|(eq=eqval)(present=*))",
			expectedNode: &Or{Nodes: []FilterNode{equality, presence}},
		},
		{
			name:         "not",
			filter:       "(!(present=*))",
			expectedNode: &Not{Node: presence},
		},
		{
			name:   "nested and or not",
			filter: "(&(present=*)(|(eq=eqval)(!(present2=*))(eq=eqval2)))",
			expectedNode: &And{Nodes: []FilterNode{
				presence,
				&Or{Nodes: []FilterNode{equality, &Not{Node: presence2}, equality2}},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { testfunc(t, tt) })
	}
}

func Test_FilterParse_Fail(t *testing.T) {
	type testcase struct {
		name   string
		filter string
		err    error
	}

	testfunc := func(t *testing.T, tt testcase) { //nolint:thelper // not a helper
		_, err := Parse(tt.filter)
		require.ErrorIs(t, err, tt.err)
	}

	tests := []testcase{
		{
			name:   "empty input",
			filter: "",
			err:    ErrUnexpectedEOF,
		},
		{
			name:   "short input",
			filter: "(",
			err:    ErrUnexpectedEOF,
		},
		{
			name:   "empty attr name",
			filter: "(=value)",
			err:    ErrEmptyAttrName,
		},
		{
			name:   "empty attr value",
			filter: "(attr=)",
			err:    ErrEmptyAttrValue,
		},
		{
			name:   "missing operation",
			filter: "(attr-value)",
			err:    ErrMissingOperation,
		},
		{
			name:   "invalid attribute name",
			filter: "(attr$=value)",
			err:    ErrInvalidAttrName,
		},
		{
			name:   "missing end",
			filter: "(attr=value",
			err:    ErrUnexpectedEOF,
		},
		{
			name:   "extra chars",
			filter: "(attr=value)X",
			err:    ErrUnexpectedInput,
		},
		{
			name:   "unexpected non-filter",
			filter: "(&(attr=value)X)",
			err:    ErrUnexpectedInput,
		},
		{
			name:   "no subfilters",
			filter: "(&)",
			err:    ErrUnexpectedInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { testfunc(t, tt) })
	}
}

func Test_FilterParse_Unimplemented(t *testing.T) {
	type testcase struct {
		name   string
		filter string
		err    error
	}

	testfunc := func(t *testing.T, tt testcase) { //nolint:thelper // not a helper
		_, err := Parse(tt.filter)
		require.ErrorIs(t, err, tt.err)
	}

	tests := []testcase{
		{
			name:   "less than or equal",
			filter: "(attr<=value)",
			err:    ErrUnimplemented,
		},
		{
			name:   "greater than or equal",
			filter: "(attr>=value)",
			err:    ErrUnimplemented,
		},
		{
			name:   "tilde equal",
			filter: "(attr~=value)",
			err:    ErrUnimplemented,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { testfunc(t, tt) })
	}
}

func Test_FilterMatch(t *testing.T) {
	type testcase struct {
		name   string
		filter string
		want   bool
	}

	testfunc := func(t *testing.T, tt testcase) { //nolint:thelper // not a helper
		attrs := map[string]any{
			"dn":          "dc=example,dc=com",
			"objectClass": "top",
			"uid":         "1234",
		}
		e, err := NewEntryFromMap(attrs)
		require.NoError(t, err)

		n, err := Parse(tt.filter)
		require.NoError(t, err)
		got := n.Match(e)
		require.Equal(t, tt.want, got)
	}

	tests := []testcase{
		{
			name:   "present",
			filter: "(uid=*)",
			want:   true,
		},
		{
			name:   "not present",
			filter: "(cn=*)",
			want:   false,
		},
		{
			name:   "equal",
			filter: "(uid=1234)",
			want:   true,
		},
		{
			name:   "not equal",
			filter: "(uid=1235)",
			want:   false,
		},
		{
			name:   "equal not present",
			filter: "(cn=username)",
			want:   false,
		},
		{
			name:   "and true",
			filter: "(&(objectClass=*)(uid=1234))",
			want:   true,
		},
		{
			name:   "and false",
			filter: "(&(objectClass=*)(uid=1235))",
			want:   false,
		},
		{
			name:   "or true",
			filter: "(|(cn=*)(uid=1234))",
			want:   true,
		},
		{
			name:   "or false",
			filter: "(|(cn=*)(uid=1235))",
			want:   false,
		},
		{
			name:   "not true",
			filter: "(!(uid=1235))",
			want:   true,
		},
		{
			name:   "not false",
			filter: "(!(uid=1234))",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { testfunc(t, tt) })
	}
}
