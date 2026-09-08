package ldap

import (
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Filter tags from the Filter CHOICE of RFC 4511 section 4.5.1. All are in the
// context class. Every tag but present is constructed.
const (
	tagFilterAnd             ber.Tag = 0
	tagFilterOr              ber.Tag = 1
	tagFilterNot             ber.Tag = 2
	tagFilterEquality        ber.Tag = 3
	tagFilterSubstrings      ber.Tag = 4
	tagFilterGreaterOrEqual  ber.Tag = 5
	tagFilterLessOrEqual     ber.Tag = 6
	tagFilterPresent         ber.Tag = 7
	tagFilterApprox          ber.Tag = 8
	tagFilterExtensibleMatch ber.Tag = 9
)

// Substring component tags from SubstringFilter, in the context class.
const (
	tagSubstringInitial ber.Tag = 0
	tagSubstringAny     ber.Tag = 1
	tagSubstringFinal   ber.Tag = 2
)

// MatchingRuleAssertion component tags, in the context class.
const (
	tagMatchingRule ber.Tag = 1
	tagMatchType    ber.Tag = 2
	tagMatchValue   ber.Tag = 3
	tagDNAttributes ber.Tag = 4
)

// Filter is a decoded LDAP search filter. It is a plain syntax tree: this
// package has no schema and so does not evaluate filters. Callers match a
// filter against their own entries by switching over the concrete types, all
// of which are defined in this package.
//
// Assertion values are octet strings on the wire and are exposed here as Go
// strings, which hold arbitrary bytes.
type Filter interface {
	fmt.Stringer
	isFilter()
}

// And matches when every sub-filter matches. An empty And matches everything.
type And []Filter

// Or matches when any sub-filter matches. An empty Or matches nothing.
type Or []Filter

// Not matches when its sub-filter does not.
type Not struct{ Filter Filter }

// Equality matches entries with an attribute equal to Value.
type Equality struct{ Attribute, Value string }

// Substrings matches entries with an attribute matching the given substring
// components, any of which may be absent. Initial anchors the start of the
// value and Final the end; each element of Any must appear in order between
// them.
type Substrings struct {
	Attribute string
	Initial   string
	Any       []string
	Final     string
}

// GreaterOrEqual matches entries with an attribute ordered at or after Value.
type GreaterOrEqual struct{ Attribute, Value string }

// LessOrEqual matches entries with an attribute ordered at or before Value.
type LessOrEqual struct{ Attribute, Value string }

// Present matches entries that have the named attribute at all.
type Present struct{ Attribute string }

// Approx matches entries with an attribute approximately equal to Value. What
// "approximately" means is left to the caller; most servers treat it as
// equality.
type Approx struct{ Attribute, Value string }

// ExtensibleMatch matches using a named matching rule, an attribute, or both.
// If DNAttributes is set, attributes of the entry's DN are matched as well.
type ExtensibleMatch struct {
	MatchingRule string
	Attribute    string
	Value        string
	DNAttributes bool
}

func (And) isFilter()             {}
func (Or) isFilter()              {}
func (Not) isFilter()             {}
func (Equality) isFilter()        {}
func (Substrings) isFilter()      {}
func (GreaterOrEqual) isFilter()  {}
func (LessOrEqual) isFilter()     {}
func (Present) isFilter()         {}
func (Approx) isFilter()          {}
func (ExtensibleMatch) isFilter() {}

// String returns the RFC 4515 string representation of the filter.
func (f And) String() string { return "(&" + joinFilters(f) + ")" }

// String returns the RFC 4515 string representation of the filter.
func (f Or) String() string { return "(|" + joinFilters(f) + ")" }

// String returns the RFC 4515 string representation of the filter.
func (f Not) String() string { return "(!" + f.Filter.String() + ")" }

// String returns the RFC 4515 string representation of the filter.
func (f Equality) String() string { return assertion(f.Attribute, "=", f.Value) }

// String returns the RFC 4515 string representation of the filter.
func (f GreaterOrEqual) String() string { return assertion(f.Attribute, ">=", f.Value) }

// String returns the RFC 4515 string representation of the filter.
func (f LessOrEqual) String() string { return assertion(f.Attribute, "<=", f.Value) }

// String returns the RFC 4515 string representation of the filter.
func (f Approx) String() string { return assertion(f.Attribute, "~=", f.Value) }

// String returns the RFC 4515 string representation of the filter.
func (f Present) String() string { return "(" + f.Attribute + "=*)" }

// String returns the RFC 4515 string representation of the filter.
func (f Substrings) String() string {
	parts := make([]string, 0, len(f.Any)+2)
	parts = append(parts, escapeAssertion(f.Initial))
	for _, a := range f.Any {
		parts = append(parts, escapeAssertion(a))
	}
	parts = append(parts, escapeAssertion(f.Final))
	return "(" + f.Attribute + "=" + strings.Join(parts, "*") + ")"
}

// String returns the RFC 4515 string representation of the filter.
func (f ExtensibleMatch) String() string {
	var sb strings.Builder
	sb.WriteString("(")
	sb.WriteString(f.Attribute)
	if f.DNAttributes {
		sb.WriteString(":dn")
	}
	if f.MatchingRule != "" {
		sb.WriteString(":")
		sb.WriteString(f.MatchingRule)
	}
	sb.WriteString(":=")
	sb.WriteString(escapeAssertion(f.Value))
	sb.WriteString(")")
	return sb.String()
}

func joinFilters(fs []Filter) string {
	var sb strings.Builder
	for _, f := range fs {
		sb.WriteString(f.String())
	}
	return sb.String()
}

func assertion(attr, op, val string) string {
	return "(" + attr + op + escapeAssertion(val) + ")"
}

// escapeAssertion escapes the characters RFC 4515 section 3 requires to be
// escaped in an assertion value.
func escapeAssertion(s string) string {
	if !strings.ContainsAny(s, "*()\\\x00") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := range len(s) {
		switch c := s[i]; c {
		case '*', '(', ')', '\\', 0x00:
			fmt.Fprintf(&sb, `\%02x`, c)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// decodeFilter decodes the Filter CHOICE at p.
func decodeFilter(p *ber.Packet) (Filter, error) {
	if p.ClassType != ber.ClassContext {
		return nil, fmt.Errorf("%w: filter class %d", ErrBadFilter, p.ClassType)
	}

	switch p.Tag {
	case tagFilterAnd:
		fs, err := decodeFilters(p)
		return And(fs), err
	case tagFilterOr:
		fs, err := decodeFilters(p)
		return Or(fs), err
	case tagFilterNot:
		if len(p.Children) != 1 {
			return nil, fmt.Errorf("%w: not filter has %d children", ErrBadFilter, len(p.Children))
		}
		f, err := decodeFilter(p.Children[0])
		if err != nil {
			return nil, err
		}
		return Not{Filter: f}, nil
	case tagFilterEquality:
		attr, val, err := decodeAssertion(p)
		return Equality{Attribute: attr, Value: val}, err
	case tagFilterGreaterOrEqual:
		attr, val, err := decodeAssertion(p)
		return GreaterOrEqual{Attribute: attr, Value: val}, err
	case tagFilterLessOrEqual:
		attr, val, err := decodeAssertion(p)
		return LessOrEqual{Attribute: attr, Value: val}, err
	case tagFilterApprox:
		attr, val, err := decodeAssertion(p)
		return Approx{Attribute: attr, Value: val}, err
	case tagFilterPresent:
		// present is primitive: the content octets are the attribute
		// description itself, with no inner packet.
		return Present{Attribute: content(p)}, nil
	case tagFilterSubstrings:
		return decodeSubstrings(p)
	case tagFilterExtensibleMatch:
		return decodeExtensibleMatch(p)
	default:
		return nil, fmt.Errorf("%w: filter tag %d", ErrBadFilter, p.Tag)
	}
}

func decodeFilters(p *ber.Packet) ([]Filter, error) {
	fs := make([]Filter, 0, len(p.Children))
	for _, child := range p.Children {
		f, err := decodeFilter(child)
		if err != nil {
			return nil, err
		}
		fs = append(fs, f)
	}
	return fs, nil
}

// decodeAssertion decodes an AttributeValueAssertion: a two-element sequence
// of attribute description and assertion value.
func decodeAssertion(p *ber.Packet) (attr, val string, err error) {
	if len(p.Children) != 2 {
		return "", "", fmt.Errorf("%w: assertion has %d children", ErrBadFilter, len(p.Children))
	}
	return content(p.Children[0]), content(p.Children[1]), nil
}

func decodeSubstrings(p *ber.Packet) (Filter, error) {
	if len(p.Children) != 2 {
		return nil, fmt.Errorf("%w: substrings has %d children", ErrBadFilter, len(p.Children))
	}
	f := Substrings{Attribute: content(p.Children[0])}
	for _, sub := range p.Children[1].Children {
		switch sub.Tag {
		case tagSubstringInitial:
			f.Initial = content(sub)
		case tagSubstringAny:
			f.Any = append(f.Any, content(sub))
		case tagSubstringFinal:
			f.Final = content(sub)
		default:
			return nil, fmt.Errorf("%w: substring tag %d", ErrBadFilter, sub.Tag)
		}
	}
	return f, nil
}

func decodeExtensibleMatch(p *ber.Packet) (Filter, error) {
	var f ExtensibleMatch
	for _, child := range p.Children {
		switch child.Tag {
		case tagMatchingRule:
			f.MatchingRule = content(child)
		case tagMatchType:
			f.Attribute = content(child)
		case tagMatchValue:
			f.Value = content(child)
		case tagDNAttributes:
			f.DNAttributes = len(content(child)) > 0 && content(child)[0] != 0
		default:
			return nil, fmt.Errorf("%w: extensible match tag %d", ErrBadFilter, child.Tag)
		}
	}
	return f, nil
}
