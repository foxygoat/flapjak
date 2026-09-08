package main

import (
	"cmp"
	"crypto/sha1" //nolint:gosec // may be weak, but we use it
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"iter"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"foxygo.at/flapjak/ldap"
)

var (
	ErrInvalidEntryForAuth  = errors.New("invalid entry for authentication")
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrMalformedBase64      = errors.New("hashtext base64 encoding malformed")
	ErrHashtextTooShort     = errors.New("hashtext too short")
	ErrMissingSalt          = errors.New("hashtext has missing salt")
	ErrInvalidAttrValue     = errors.New("invalid type for attribute value")
	ErrMixedAttrKinds       = errors.New("attribute values are of mixed kinds")
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
	// Vals are the values of an attribute, retaining the type they were
	// given when created. They are converted to their LDAP wire encoding
	// only when a search response is written.
	Vals []any
	// Kind is the kind shared by every value of the attribute. All values
	// of one attribute must be of the same kind, which is checked when the
	// entry is built.
	Kind Kind
}

// Kind is the broad type of an attribute's values.
//
// LDAP has no type information on the wire, and flapjak has no schema, so the
// Go type a value arrived with stands in for the syntax a schema would
// otherwise assign. It decides how values compare: numbers compare
// numerically, so uidNumber 9 sorts before 10 rather than after it.
type Kind int

// Attribute kinds.
const (
	KindString Kind = iota
	KindNumber
	KindBool
)

// String returns the name of the kind.
func (k Kind) String() string {
	switch k {
	case KindString:
		return "string"
	case KindNumber:
		return "number"
	case KindBool:
		return "bool"
	default:
		return "unknown"
	}
}

// KindOf returns the kind of a single attribute value. Numbers are float64;
// the database stores no other numeric type.
func KindOf(v any) (Kind, error) {
	switch v.(type) {
	case string:
		return KindString, nil
	case float64:
		return KindNumber, nil
	case bool:
		return KindBool, nil
	default:
		return 0, fmt.Errorf("%w: %T", ErrInvalidAttrValue, v)
	}
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

// Authenticate checks that the LDAP Entry is valid for authentication and that
// the entry has a password that matches the given password. If so nil is
// returned. Otherwise an error is returned.
//
// The form of hashed password in an entry is described by "[RFC 2307, 5.3]
// Interpreting user and group entries" with the supported schemes being SSHA
// (salted SHA-1), SSHA256 (salted SHA-256) and SSHA512 (salted SHA-512). This
// is how [OpenLDAP passwords] are done, so this does it the same. e.g.
// "{SSHA}<base64-encoded-hash+salt>".
//
// [RFC 2307, 5.3]: https://datatracker.ietf.org/doc/html/rfc2307#section-5.3
// [OpenLDAP passwords]: https://www.openldap.org/faq/data/cache/347.html
func (e *Entry) Authenticate(password string) error {
	if !e.isValidForAuthentication() {
		return ErrInvalidEntryForAuth
	}

	// hashSchemes is a list of supported password hashing schemes
	// with their functions for creating a hash.Hash for that scheme.
	hashSchemes := map[string]func() hash.Hash{
		"{SSHA}":    sha1.New,
		"{SSHA256}": sha256.New,
		"{SSHA512}": sha512.New,
	}

	var firstErr error
	hashedPasswords, _ := e.GetAttr("userPassword")
	for _, val := range hashedPasswords.Vals {
		hashedPassword, ok := val.(string)
		if !ok {
			continue
		}
		scheme, hashtext, ok := splitScheme(hashedPassword)
		if !ok || hashSchemes[scheme] == nil {
			continue
		}
		ok, err := pwCheckSaltedHash(password, hashtext, hashSchemes[scheme])
		if ok {
			return nil
		}
		firstErr = cmp.Or(firstErr, err)
	}

	return cmp.Or(firstErr, ErrAuthenticationFailed)
}

func (e *Entry) isValidForAuthentication() bool {
	// authClasses is a list of objectClasses for entries that are
	// valid for authentication. If an entry does not have one of
	// these objectClasses, an attempt to authenticate with its DN
	// will fail.
	authClasses := []string{"posixAccount", "posixGroup", "shadowAccount"}

	entryClasses, _ := e.GetAttr("objectClass")
	return slices.ContainsFunc(authClasses, entryClasses.HasValue)
}

func splitScheme(hashedPassword string) (string, string, bool) {
	idx := strings.IndexRune(hashedPassword, '}')
	if idx == -1 || (len(hashedPassword) > 0 && hashedPassword[0] != '{') {
		return "", "", false
	}
	return hashedPassword[:idx+1], hashedPassword[idx+1:], true
}

func pwCheckSaltedHash(password string, hashtext string, newHash func() hash.Hash) (bool, error) {
	h := newHash()
	hps, err := base64.StdEncoding.DecodeString(hashtext)
	if err != nil {
		return false, ErrMalformedBase64
	}
	if len(hps) < h.Size() {
		return false, ErrHashtextTooShort
	}
	if len(hps) == h.Size() {
		return false, ErrMissingSalt
	}

	expected := hps[:h.Size()]
	salt := hps[h.Size():]

	h.Write([]byte(password))
	h.Write(salt)

	// Constant time, so that how long the comparison takes says nothing
	// about how much of the digest matched.
	return subtle.ConstantTimeCompare(h.Sum(nil), expected) == 1, nil
}

// HasValue returns true if val is one of the values of the attribute.
//
// An assertion value from a filter is always a string, since that is all LDAP
// puts on the wire. It is interpreted according to the attribute's kind:
// numbers are compared numerically and booleans by truth value. Strings are
// compared case-insensitively, which is what caseIgnoreMatch, the default
// matching rule for Directory String, would do given a schema.
func (a Attr) HasValue(val string) bool {
	return a.matchAny(val, func(c int) bool { return c == 0 })
}

// AtLeast reports whether any value of the attribute orders at or after val,
// which is what a greaterOrEqual filter asks.
func (a Attr) AtLeast(val string) bool {
	return a.matchAny(val, func(c int) bool { return c >= 0 })
}

// AtMost reports whether any value of the attribute orders at or before val,
// which is what a lessOrEqual filter asks.
func (a Attr) AtMost(val string) bool {
	return a.matchAny(val, func(c int) bool { return c <= 0 })
}

// matchAny reports whether any value of the attribute compares against val in
// a way that satisfies f. If val cannot be parsed as the attribute's kind,
// false is returned: an assertion that cannot be interpreted matches nothing.
func (a Attr) matchAny(val string, f func(int) bool) bool {
	rhs := parseValue(a.Kind, val)
	if rhs == nil {
		return false
	}
	for _, lhs := range a.Vals {
		if c, ok := compareValue(lhs, rhs); ok && f(c) {
			return true
		}
	}
	return false
}

// compareValue orders attribute value lhs against assertion value rhs,
// returning a negative number, zero or a positive number as lhs sorts before,
// with or after rhs. It reports false if lhs and rhs are not of the same type,
// or are not a type that a Kind can hold.
func compareValue(lhs any, rhs any) (int, bool) {
	switch lhsV := lhs.(type) {
	case float64:
		if rhsV, ok := rhs.(float64); ok {
			return cmp.Compare(lhsV, rhsV), true
		}
	case bool:
		if rhsV, ok := rhs.(bool); ok {
			// false sorts before true.
			return cmp.Compare(btoi(lhsV), btoi(rhsV)), true
		}
	case string:
		if rhsV, ok := rhs.(string); ok {
			return cmp.Compare(strings.ToLower(lhsV), strings.ToLower(rhsV)), true
		}
	}
	return 0, false
}

// MatchSubstrings reports whether any value of the attribute matches the
// components of a substring filter: a prefix, a suffix, and the middles that
// must appear between them. Each middle must appear after the previous one, so
// (cn=a*b*c*d) matches a value beginning "a" and ending "d" that holds "b" and
// then "c" in between.
//
// Any of the three may be absent, which is what makes the component a filter
// does not carry simply not constrain the value.
func (a Attr) MatchSubstrings(initial string, middles []string, final string) bool {
	for _, v := range a.Vals {
		if matchSubstrings(ValueString(v), initial, middles, final) {
			return true
		}
	}
	return false
}

func matchSubstrings(s, initial string, middles []string, final string) bool {
	var ok bool
	if initial != "" {
		if s, ok = foldPrefix(s, initial); !ok {
			return false
		}
	}
	// The suffix is cut before the middles are searched for, so that no
	// middle can match inside it.
	if final != "" {
		if s, ok = foldSuffix(s, final); !ok {
			return false
		}
	}
	for _, mid := range middles {
		if s, ok = foldCut(s, mid); !ok {
			return false
		}
	}
	return true
}

// foldEqual reports whether the leading rune of lhs matches that of rhs,
// ignoring case, and returns the width of each. It is the primitive the rest of
// the fold helpers are built on.
//
// Case-insensitive matching is done a rune at a time rather than by lowercasing
// both sides and comparing bytes. Lowercasing replaces every byte that is not
// valid UTF-8 with the replacement character, which makes values that differ
// compare equal; an attribute value is arbitrary octets, and a filter from the
// wire is too. Comparing rune by rune also keeps a match from beginning or
// ending inside one.
//
// A byte that is not valid UTF-8 decodes as [utf8.RuneError] with a width of
// one. Those compare as the byte they are, rather than as the rune they decoded
// to, so that two different invalid bytes stay different and neither matches a
// value that spells the replacement character out.
func foldEqual(lhs, rhs string) (int, int, bool) {
	lr, lw := utf8.DecodeRuneInString(lhs)
	rr, rw := utf8.DecodeRuneInString(rhs)
	if lr == utf8.RuneError && lw == 1 || rr == utf8.RuneError && rw == 1 {
		return lw, rw, lw == 1 && rw == 1 && lhs[0] == rhs[0]
	}
	return lw, rw, unicode.ToLower(lr) == unicode.ToLower(rr)
}

// foldPrefix reports whether s begins with prefix, ignoring case, and returns
// what is left of s.
func foldPrefix(s, prefix string) (string, bool) {
	for prefix != "" {
		if s == "" {
			return s, false
		}
		sw, pw, ok := foldEqual(s, prefix)
		if !ok {
			return s, false
		}
		s, prefix = s[sw:], prefix[pw:]
	}
	return s, true
}

// foldSuffix reports whether s ends with suffix, ignoring case, and returns s
// without it. Folding does not preserve width, so the tail cannot be taken by
// length; it is found by trying each rune boundary.
func foldSuffix(s, suffix string) (string, bool) {
	for i := 0; i <= len(s); {
		if rest, ok := foldPrefix(s[i:], suffix); ok && rest == "" {
			return s[:i], true
		}
		if i == len(s) {
			break
		}
		_, w := utf8.DecodeRuneInString(s[i:])
		i += w
	}
	return s, false
}

// foldCut returns what is left of s after the first occurrence of sub, ignoring
// case, and whether there was one.
func foldCut(s, sub string) (string, bool) {
	for i := 0; i <= len(s); {
		if rest, ok := foldPrefix(s[i:], sub); ok {
			return rest, true
		}
		if i == len(s) {
			break
		}
		_, w := utf8.DecodeRuneInString(s[i:])
		i += w
	}
	return s, false
}

// parseValue parses a filter's assertion value as kind k, returning nil if it
// cannot be read as that kind. Values of a kind are never nil themselves, so
// nil is unambiguous.
func parseValue(k Kind, s string) any {
	switch k {
	case KindNumber:
		// Only a finite number is a usable assertion. NaN parses but
		// does not order: cmp.Compare puts it below everything, so a
		// >= assertion against it would match every value. The
		// infinities order, but degenerately - <=+Inf and >=-Inf match
		// everything, and their opposites match nothing - and no
		// attribute can hold one, since ParseFloat reports an overflow
		// as an error and JSON has no literal for them. Refusing all
		// three makes the assertion match nothing, which is what
		// matchAny does with any value it cannot interpret.
		v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err == nil && !math.IsInf(v, 0) && !math.IsNaN(v) {
			return v
		}
	case KindBool:
		if v, ok := parseBool(s); ok {
			return v
		}
	case KindString:
		return s
	}
	return nil
}

// ValueString returns the string form of an attribute value: the same encoding
// that would be put on the wire.
func ValueString(v any) string {
	b, err := ldap.Value(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// parseBool accepts both the RFC 4517 encoding of a boolean, which is TRUE or
// FALSE in upper case, and Go's spelling, since either may be typed into a
// filter by hand.
func parseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// IsSensitive returns true if the attribute is a sensitive one, such as a
// hashed password that should not be returned in a search without some sort of
// permission controls. Usually this information of sensitivity would belong in
// the schema or some separate permissions config, but we have neither, so this
// is hardcoded for now.
func (a Attr) IsSensitive() bool {
	return strings.ToLower(a.Name) == "userpassword"
}

// View returns a view of e as the identity named by bindDN may see it. An
// empty bindDN is an anonymous connection.
func (e *Entry) View(bindDN string) EntryView {
	return EntryView{e: e, bindDN: bindDN}
}

// EntryView presents the attributes of an [Entry] that one identity may see.
// Every read a client can reach goes through a view: [Match] and selectAttrs
// both take one, so an attribute the view withholds cannot be recovered by
// filtering on it either.
//
// [Entry.Authenticate] reads the password from the entry rather than through a
// view, since it is checking the password rather than disclosing it.
type EntryView struct {
	e      *Entry
	bindDN string
}

// GetAttr returns the attribute if the view's identity may see it, following
// the case-insensitive rules of [Entry.GetAttr].
func (v EntryView) GetAttr(attr string) (Attr, bool) {
	a, ok := v.e.GetAttr(attr)
	if !ok || v.hidden(a) {
		return Attr{}, false
	}
	return a, true
}

// Names iterates the names of the attributes the view's identity may see.
func (v EntryView) Names() iter.Seq[string] {
	return func(yield func(string) bool) {
		for name, a := range v.e.Attrs {
			if v.hidden(a) {
				continue
			}
			if !yield(name) {
				return
			}
		}
	}
}

// hidden reports whether a is withheld from the view's identity.
//
// TODO(camh): filter entries, attributes and values based on permissions.
// bindDN is held for that. Until there is a permissions config, a sensitive
// attribute is hidden from everyone, including the entry it belongs to.
func (v EntryView) hidden(a Attr) bool {
	return a.IsSensitive()
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
				"objectclass": {Name: "objectClass", Vals: []any{"top"}, Kind: KindString},
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
	for _, elem := range slices.Backward(elems) {
		rdn, err := ParseRDN(elem)
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
	for _, d := range slices.Backward(dn) {
		elems = append(elems, d.String())
	}
	return strings.Join(elems, ",")
}

// IsAncestor returns whether dn is an ancestor of sub. A dn is an ancestor
// of sub if dn matches the leading elements of sub. A DN is an ancestor of itself.
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
// strings, float64s or bools; see [KindOf].
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

		for i, aval := range attrVal {
			kind, err := KindOf(aval)
			if err != nil {
				return nil, fmt.Errorf("attribute %s: %w", attrName, err)
			}
			// Values keep their type, so every value of one attribute
			// must share a kind: there is no sensible way to compare a
			// filter assertion against an attribute that is a number
			// in one value and a string in the next.
			if i == 0 {
				attr.Kind = kind
			} else if kind != attr.Kind {
				return nil, fmt.Errorf("%w: attribute %s mixes %s and %s values",
					ErrMixedAttrKinds, attrName, attr.Kind, kind)
			}
			attr.Vals = append(attr.Vals, aval)
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
