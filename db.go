package main

import (
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
	DN    DN
	Attrs map[string][]string
}

// GetAttr returns the attribute values for the given attribute name and true
// if the attribute exists, or an empty slice and false if it does not.
func (e *Entry) GetAttr(attr string) ([]string, bool) {
	// TODO(camh): Make lookup case-insensitive
	// TODO(camh): Support lookup by OID
	v, ok := e.Attrs[attr]
	return v, ok
}

// DITNode is a node in the Directory Information Tree (DIT), the hierarchical
// index of entries indexed by DN. Often an LDAP search is performed relative
// to a BaseDN. The DIT allows a search to be constrained to a sub-tree of the
// total DIT.
type DITNode struct {
	Entry    *Entry
	children []*DITNode
}

// DN is a decomposed DN string, where each element of the DN is broken out. DN
// strings are comma-separated DN string components. The order of the
// components is tree-traversal order - i.e. top-level first, so the DN
// ou=people,dc=example,dc=com is ["dc=com", "dc=example", "ou=people"].
type DN []string

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
			Attrs: map[string][]string{
				"objectClass": {"top"},
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
	if !dit.Entry.DN.IsRoot() {
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

// NewDN constructs a DN from the given string representing a DN.
func NewDN(dnstr string) DN {
	dnstr = strings.TrimSpace(dnstr)
	if dnstr == "" {
		return []string{}
	}
	dn := strings.Split(dnstr, ",")
	result := make(DN, 0, len(dn))
	for _, rdn := range dn {
		if attr, val, ok := strings.Cut(rdn, "="); ok {
			rdn = strings.TrimSpace(attr) + "=" + strings.TrimSpace(val)
		}
		result = append(result, rdn)
		// TODO(camh): backslash de-escaping
		// TODO(camh): multi-valued RDNs
	}

	slices.Reverse(result)
	return result
}

// String formats dn into a string representation of the DN and returns it.
func (dn DN) String() string {
	// TODO(camh): escape chars (RFC 4514)
	clone := slices.Clone(dn)
	slices.Reverse(clone)
	return strings.Join(clone, ",")
}

// IsAncestor returns whether sub is an ancestor of dn. A sub is an ancestor
// of dn if dn matches the leading elements of sub. A DN is an ancestor of itself.
func (dn DN) IsAncestor(sub DN) bool {
	if len(dn) > len(sub) {
		return false
	}
	for i := range dn {
		if dn[i] != sub[i] {
			return false
		}
	}
	return true
}

// Equal returns true if dn is equal to rhs.
func (dn DN) Equal(rhs DN) bool {
	return slices.Equal(dn, rhs)
}

// CommonAncestor returns a DN that has the common ancestor of dn and other.
// If there is no common ancestor, the root DN is returned.
func (dn DN) CommonAncestor(other DN) DN {
	common := make(DN, 0, min(len(dn), len(other)))
	for i := range cap(common) {
		if dn[i] != other[i] {
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

// IsRoot returns true if dn is the root DN. The root DN has no components.
func (dn DN) IsRoot() bool {
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
	// Validate that the entry contains at least an objectClass
	// and a dn attribute.
	if attrs["objectClass"] == nil || attrs["dn"] == nil {
		return nil, fmt.Errorf("value missing mandatory attributes: %#v", attrs)
	}

	e := Entry{
		Attrs: make(map[string][]string),
	}

	for attr, val := range attrs {
		attrVal := e.Attrs[attr]
		array, ok := val.([]any)
		if !ok {
			array = []any{val}
		}

		if attr == "dn" {
			if len(array) > 1 {
				return nil, fmt.Errorf("dn cannot have multiple values: %v", array)
			}
			dn, ok := array[0].(string)
			if !ok {
				return nil, fmt.Errorf("dn must be a string: %v", array[0])
			}
			e.DN = NewDN(dn)
			continue
		}

		for _, aval := range array {
			switch v := aval.(type) {
			case string:
				attrVal = append(attrVal, v)
			case float64:
				attrVal = append(attrVal, strconv.FormatFloat(v, 'f', -1, 64))
			case bool:
				attrVal = append(attrVal, strconv.FormatBool(v))
			default:
				return nil, fmt.Errorf("invalid type for attribute: %v: %#T", aval, aval)
			}
		}
		e.Attrs[attr] = attrVal
	}

	return &e, nil
}
