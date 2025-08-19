package main

import (
	"errors"
	"fmt"
	"iter"
	"slices"
	"strconv"
	"strings"
)

// DB is an LDAP database, which is just a collection of entries and indicies
// over that collection. The DIT is the hierarchy of entries based on each
// entries DN.
type DB struct {
	DIT DITNode
}

// Entry is a single ldap entry comprising a Distinguished Name (DN) and named
// attributes that have multiple values. In an LDAP entry, attributes can
// appear multiple times, requiring a slice of values for each named attribute.
type Entry struct {
	// DN is the distinguished name of the entry.
	DN DN
	// Attrs maps the lower-case attribute name to the attribute, so that
	// attributes can be looked-up case-insensitively.
	Attrs map[string]Attr
}

// Attr is an attribute of an Entry.
type Attr struct {
	// Name is the canonical name of an attribute, preserving the
	// case as originally entered into the database.
	Name string
	// Vals are the values of an attribute. Currently all attribute
	// values are stored (and returned) as strings.
	Vals []string
}

// AddAttr adds attr to e. It can be retrieved with GetAttr. The name
// of the attribute is case-insensitive for lookups. If the attribute
// already exists with the same case-insensitive name, the existing
// attribute will be replaced.
func (e *Entry) AddAttr(attr Attr) {
	e.Attrs[strings.ToLower(attr.Name)] = attr
}

// GetAttr returns the attribute values for the given attribute name and true
// if the attribute exists, or an empty slice and false if it does not.
// The attribute name is case-insensitive.
func (e *Entry) GetAttr(attr string) (Attr, bool) {
	// TODO(camh): Support lookup by OID
	v, ok := e.Attrs[strings.ToLower(attr)]
	return v, ok
}

// HasValue returns true if val is one of the values of the attribute. The
// value is compared case-sensitively, regardless of what an LDAP schema
// may say for that attribute.
func (a Attr) HasValue(val string) bool {
	// TODO(camh): Handle case-insensitive values
	return slices.Contains(a.Vals, val)
}

// DITNode is a node in the Directory Information Tree (DIT), the hierarchical
// index of entries indexed by DN. Often an LDAP search is performed relative
// to a BaseDN. The DIT allows a search to be constrained to a sub-tree of the
// total DIT.
type DITNode struct {
	Entry    *Entry
	children []*DITNode
}

// RDN (Relative Distinguished Name) is a single element of a DN (Distinguished
// Name) and is a name/value pair specifying an attribute name and value. Multi-
// valued RDNs are not supported. When compared, RDN names are case-insensitive.
// Values are case-sensitive. In string form, RDNs are of the form "name=value"
// with possible whitespace around the "=", which is stripped when parsed.
type RDN struct{ Name, Value string }

// DN is a parsed DN string into a slice of RDNs, in the reverse order they
// are in the string. Each RDN is separated by a comma and may contain
// whitespace around the comma, which is stripped.
type DN []RDN

// NewDB returns a new DB with a single root entry for the DIT for the server's
// Directory Server Entry ([DSE]) (or is it DSA-Specific Entry?).
//
// For now, we do not populate it with any attributes.
//
// [DSE}: https://ldap.com/dit-and-the-ldap-root-dse/
func NewDB() *DB {
	dse := DITNode{
		Entry: &Entry{
			DN: DN{},
			Attrs: map[string]Attr{
				"objectClass": {"objectClass", []string{"top"}},
			},
		},
	}
	return &DB{DIT: dse}
}

// AddEntries adds the given entries to the database. If the database has any
// entries with the same DN as any of the ones being added, an error is
// returned. Any entries prior to the one with the duplicate DN will be added
// to the database.
func (db *DB) AddEntries(entries []*Entry) error {
	for _, e := range entries {
		if err := db.DIT.insert(e); err != nil {
			return err
		}
	}
	return nil
}

func (dit *DITNode) insert(entry *Entry) error {
	// Duplicate DN
	if entry.DN.Equal(dit.Entry.DN) {
		return fmt.Errorf("duplicate DN: %s", entry.DN)
	}

	// We are below a child of the current node
	for _, child := range dit.children {
		if child.Entry.DN.IsAncestor(entry.DN) {
			return child.insert(entry)
		}
	}

	// We are a child of the current node and maybe take over some of
	// its children we are their ancestor.
	newnode := &DITNode{Entry: entry}
	siblings := []*DITNode{}
	for _, child := range dit.children {
		if entry.DN.IsAncestor(child.Entry.DN) {
			newnode.children = append(newnode.children, child)
		} else {
			siblings = append(siblings, child)
		}
	}
	dit.children = append(siblings, newnode)

	return nil
}

// Find searches the DIT for an entry with the given DN and returns it. If no
// entry matches, nil is returned.
func (dit *DITNode) Find(dn DN) *DITNode {
	if dit.Entry.DN.Equal(dn) {
		return dit
	}
	if !dit.Entry.DN.IsAncestor(dn) {
		return nil
	}
	for _, child := range dit.children {
		if child.Entry.DN.IsAncestor(dn) {
			return child.Find(dn)
		}
	}
	return nil
}

func (dit *DITNode) String() string {
	return dit.str(DN{}, 0)
}

func (dit *DITNode) str(parent DN, level int) string {
	indent := 0
	s := ""
	if !dit.Entry.DN.IsEmpty() {
		s = fmt.Sprintf("%*s%s\n", level, "", dit.Entry.DN.Tail(parent))
		indent = 2
	}
	for _, child := range dit.children {
		s += child.str(dit.Entry.DN, level+indent)
	}
	return s
}

// Self returns an interator that yields just the node of the DIT on which it
// is called.
func (dit *DITNode) Self() iter.Seq[*DITNode] {
	return func(yield func(*DITNode) bool) {
		yield(dit)
	}
}

// Children returns an iterator that yields all the direct children of the DIT
// node on which it is called.
func (dit *DITNode) Children() iter.Seq[*DITNode] {
	return slices.Values(dit.children)
}

// All returns an iterator that yields the node of the DIT on which it is
// called and all of its descendents.
func (dit *DITNode) All() iter.Seq[*DITNode] {
	return func(yield func(*DITNode) bool) {
		dit.walk(yield)
	}
}

func (dit *DITNode) walk(yield func(*DITNode) bool) bool {
	if dit.Entry != nil {
		if !yield(dit) {
			return false
		}
	}
	for _, c := range dit.children {
		if !c.walk(yield) {
			return false
		}
	}
	return true
}

// ParseRDN parse a RDN string value, returning an RDN or an error if it could
// not be parsed. The format must be "name=value" with optional whitespace
// around the "=". name is mandatory. value may be omitted.
func ParseRDN(rdn string) (RDN, error) {
	name, val, ok := strings.Cut(rdn, "=")
	if !ok {
		return RDN{}, fmt.Errorf("invalid rdn: %v", rdn)
	}
	result := RDN{Name: strings.TrimSpace(name), Value: strings.TrimSpace(val)}
	if result.Name == "" {
		return RDN{}, fmt.Errorf("no attribute name in rdn: %v", rdn)
	}
	return result, nil
}

// String returns rdn in string form. It implements the [fmt.Stringer]
// interface.
func (rdn RDN) String() string {
	return rdn.Name + "=" + rdn.Value
}

// Equal compares rdn to rhs returning true if they are equal and false if not.
// The attribute name of the RDNs are compared case-insensitively. The values
// are compared case-sensitively if the names compare equal.
func (rdn RDN) Equal(rhs RDN) bool {
	if !strings.EqualFold(rdn.Name, rhs.Name) {
		return false
	}
	// TODO(camh): Handle case-insensitive attribute values where appropriate
	return rdn.Value == rhs.Value
}

// Compare compares rdn to rhs returning -1 if rdn orders before rhs, 1 if it
// orders after it and 0 if the are equal. The attribute names are compared
// case-insensitively. The values are compared case-sensitively if the names
// compare equal. Compare can be used as a comparison function for
// [slices.CompareFunc] and similar functions.
func (rdn RDN) Compare(rhs RDN) int {
	lname, rname := strings.ToLower(rdn.Name), strings.ToLower(rhs.Name)
	switch {
	case lname < rname:
		return -1
	case lname > rname:
		return +1
	default:
		// TODO(camh): Handle case-insensitive attribute values where appropriate
		return strings.Compare(rdn.Value, rhs.Value)
	}
}

// NewDN constructs a DN from the given string representing a DN. If any of the
// RDN components in the DN string are invalid (see [ParseRDN]), an error is
// returned.
func NewDN(dnstr string) (DN, error) {
	dnstr = strings.TrimSpace(dnstr)
	if dnstr == "" {
		// The empty DN string is the root DN.
		return DN{}, nil
	}

	elems := strings.Split(dnstr, ",")
	result := make(DN, 0, len(elems))
	for i := len(elems) - 1; i >= 0; i-- {
		rdn, err := ParseRDN(elems[i])
		if err != nil {
			return nil, err
		}
		result = append(result, rdn)
		// TODO(camh): backslash de-escaping
	}
	return result, nil
}

// String formats dn into a string representation of the DN and returns it.
func (dn DN) String() string {
	// TODO(camh): escape chars (RFC 4514)
	elems := make([]string, 0, len(dn))
	for i := len(dn) - 1; i >= 0; i-- {
		elems = append(elems, dn[i].String())
	}
	return strings.Join(elems, ",")
}

// IsAncestor returns whether sub is an ancestor of dn. A sub is an ancestor
// of dn if dn matches the leading elements of sub. A DN is an ancestor of itself.
func (dn DN) IsAncestor(sub DN) bool {
	if len(dn) > len(sub) {
		return false
	}
	for i := range dn {
		if !dn[i].Equal(sub[i]) {
			return false
		}
	}
	return true
}

// Equal returns true if dn is equal to rhs.
func (dn DN) Equal(rhs DN) bool {
	return slices.EqualFunc(dn, rhs, RDN.Equal)
}

// CommonAncestor returns a DN that has the common ancestor of dn and other.
// If there is no common ancestor, the root DN is returned.
func (dn DN) CommonAncestor(other DN) DN {
	common := make(DN, 0, min(len(dn), len(other)))
	for i := range cap(common) {
		if !dn[i].Equal(other[i]) {
			break
		}
		common = append(common, dn[i])
	}
	return common
}

// Tail returns the parts of dn after the common ancestor of dn and head.
func (dn DN) Tail(head DN) DN {
	c := dn.CommonAncestor(head)
	return dn[len(c):]
}

// IsEmpty returns true if dn is the root DN. The root DN has no components.
func (dn DN) IsEmpty() bool {
	return len(dn) == 0
}

// NewEntryFromMap returns an Entry from the elements in attrs. It is intended
// to build an entry from a JSON or similar representation - a string-encoded
// map of attribute names to slice of values.
//
// The provided attrs must contain "objectClass" and "dn" elements at a
// minimum. The values need not be an array but may be. The values must be
// strings, float64s or bools.
func NewEntryFromMap(attrs map[string]any) (*Entry, error) {
	e := &Entry{
		Attrs: make(map[string]Attr),
	}

	for attrName, val := range attrs {
		attrVal, ok := val.([]any)
		if !ok {
			attrVal = []any{val}
		}

		if strings.ToLower(attrName) == "dn" {
			if len(attrVal) > 1 {
				return nil, fmt.Errorf("dn cannot have multiple values: %v", attrVal)
			}
			dnstr, ok := attrVal[0].(string)
			if !ok || strings.TrimSpace(dnstr) == "" {
				return nil, fmt.Errorf("dn must be a non-empty string: %v", attrVal[0])
			}
			if !e.DN.IsEmpty() {
				return nil, fmt.Errorf("dn already set: %v, %v", e.DN, dnstr)
			}
			dn, err := NewDN(dnstr)
			if err != nil {
				return nil, err
			}
			if dn.IsEmpty() {
				return nil, errors.New("dn must not be empty")
			}
			e.DN = dn
			continue
		}

		attr, ok := e.GetAttr(attrName)
		if ok {
			return nil, fmt.Errorf("duplicate attribute: %v, %v", attrName, attr.Name)
		}
		attr.Name = attrName

		for _, aval := range attrVal {
			switch v := aval.(type) {
			case string:
				attr.Vals = append(attr.Vals, v)
			case float64:
				attr.Vals = append(attr.Vals, strconv.FormatFloat(v, 'f', -1, 64))
			case bool:
				attr.Vals = append(attr.Vals, strconv.FormatBool(v))
			default:
				return nil, fmt.Errorf("invalid type for attribute: %v: %#T", aval, aval)
			}
		}
		e.AddAttr(attr)
	}

	// Validate that the entry contains at least an objectClass
	// and a dn attribute.
	if e.DN.IsEmpty() {
		return nil, errors.New("missing DN")
	}
	if _, ok := e.GetAttr("objectClass"); !ok {
		return nil, fmt.Errorf("missing objectClass for %s", e.DN)
	}

	return e, nil
}
