package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

var (
	ErrInternal         = errors.New("internal error")
	ErrUnexpectedEOF    = errors.New("unexpected end of filter")
	ErrUnexpectedInput  = errors.New("unexpected input")
	ErrUnimplemented    = errors.New("unimplemented")
	ErrInvalidAttrName  = errors.New("invalid attribute name")
	ErrEmptyAttrName    = errors.New("empty attribute name")
	ErrEmptyAttrValue   = errors.New("empty attribute value")
	ErrMissingOperation = errors.New("missing filter operation")
)

// FilterNode represents an individual filter element of a parsed LDAP filter
// string. A full filter is an abstract syntax tree (AST) made of FilterNodes.
//
// LDAP filters: https://ldap.com/ldap-filters/
type FilterNode interface {
	Match(e *Entry) bool
}

// Parse parses an LDAP filter string into an [FilterNode] AST that can be
// used to match against an LDAP Entry. If the filter string could not be
// parsed due to a syntax error or unimplemented filter, an error is
// returned with a nil FilterNode.
func Parse(filter string) (n FilterNode, err error) {
	defer func() {
		if r := recover(); r != nil {
			if perr, ok := r.(parseError); ok {
				n, err = nil, perr.err
			} else {
				panic(r)
			}
		}
	}()

	filter = strings.TrimSpace(filter)
	c := &cursor{input: []rune(filter)}
	n = parseFilter(c)

	if !c.isEOF() {
		panicf("%w: %s", ErrUnexpectedInput, string(c.input[c.pos:]))
	}

	return n, nil
}

func parseFilter(c *cursor) FilterNode {
	c.expectRune('(')
	switch c.peek() {
	case '&':
		return parseAndOrFilter(c, '&')
	case '|':
		return parseAndOrFilter(c, '|')
	case '!':
		return parseNotFilter(c)
	default:
		return parseOpFilter(c)
	}
}

func parseAndOrFilter(c *cursor, op rune) FilterNode {
	var nodes []FilterNode
	c.expectRune(op)

	for {
		if c.peek() == '(' {
			nodes = append(nodes, parseFilter(c))
		} else {
			c.expectRune(')')
			break
		}
	}

	if len(nodes) == 0 {
		panicf("%w: expected filter, got ')'", ErrUnexpectedInput)
	}

	switch op {
	case '&':
		return &And{Nodes: nodes}
	case '|':
		return &Or{Nodes: nodes}
	}
	panicf("%w: unknown and/or op: %q", ErrInternal, op)
	// NOTREACHED
	return nil
}

func parseNotFilter(c *cursor) FilterNode {
	c.expectRune('!')
	node := parseFilter(c)
	c.expectRune(')')
	return &Not{Node: node}
}

func parseOpFilter(c *cursor) FilterNode {
	rs := c.extractTo(')')
	c.expectRune(')')

	var attr, op, value string
	switch idx := slices.Index(rs, '='); {
	case idx == -1:
		panice(ErrMissingOperation)
	case idx > 0 && isOp(string(rs[idx-1:idx+1])):
		// 2-char op with second char being =
		attr = validateAttrName(rs[:idx-1])
		op = string(rs[idx-1 : idx+1])
		value = string(rs[idx+1:])
	default:
		// Op is '='
		attr = validateAttrName(rs[:idx])
		op = string(rs[idx])
		value = string(rs[idx+1:])
	}

	if value == "" {
		panice(ErrEmptyAttrValue)
	}

	if op == "=" && value == "*" {
		return &Presence{Attr: attr}
	}
	if op == "=" {
		// TODO: Implement Substring filters (value contains '*' globs)
		return &Equality{Attr: attr, Value: value}
	}

	// TODO: Implement >= (Greater-Or-Equal) and <= (Less-Or-Equal) filters.
	// TODO: Implement ~= (Approximate Match) filter (maybe)
	panicf("%w: operation: %s", ErrUnimplemented, op)
	return nil
}

func validateAttrName(rs []rune) string {
	if len(rs) == 0 {
		panice(ErrEmptyAttrName)
	}
	for i, r := range rs {
		if !isValidAttrRune(i, r) {
			panicf("%w: invalid char %q", ErrInvalidAttrName, r)
		}
	}
	return string(rs)
}

func isValidAttrRune(pos int, r rune) bool {
	if pos == 0 {
		return unicode.IsLetter(r)
	}
	return r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isOp(op string) bool {
	switch op {
	case "=", "<=", ">=", "~=":
		return true
	default:
		return false
	}
}

// Presence is a FilterNode for a presence filter - a filter that matches an
// entry if the entry has an attribute with the given name. Its syntax is
// `(attr=*)`.
type Presence struct {
	Attr string
}

// Match implements the Match method of the [FilterNode] interface.
func (f *Presence) Match(e *Entry) bool {
	_, ok := e.GetAttr(f.Attr)
	return ok
}

// Equality is a FilterNode for an equality filter - a filter that matches an
// entry if the entry has an attribute of the given name with the given value.
// Its syntax is `(attr=<value>)`.
type Equality struct {
	Attr  string
	Value string
}

// Match implements the Match method of the [FilterNode] interface.
func (f *Equality) Match(e *Entry) bool {
	attr, ok := e.GetAttr(f.Attr)
	return ok && attr.HasValue(f.Value)
}

// And is a FilterNode for an AND filter - a filter that matches if all its
// child FilterNodes match. It can have zero or more child nodes. If it has
// zero child nodes, it will match any entry. Its syntax is
// `(&(child1)(child2)...(childN))`.
type And struct {
	Nodes []FilterNode
}

// Match implements the Match method of the [FilterNode] interface.
func (f *And) Match(e *Entry) bool {
	for _, n := range f.Nodes {
		if !n.Match(e) {
			return false
		}
	}
	return true
}

// Or is a FilterNode for an OR filter - a filter that matches if any of its
// child FilterNodes match. It can have zero or more child entries. If it has
// zero child entries, it will not match any entry. Its syntax is
// `(|(child1)(child2)...(childN))`.
type Or struct {
	Nodes []FilterNode
}

// Match implements the Match method of the [FilterNode] interface.
func (f *Or) Match(e *Entry) bool {
	for _, n := range f.Nodes {
		if n.Match(e) {
			return true
		}
	}
	return false
}

// Not is a FilterNode for a NOT filter - a filter that matches if its child
// FilterNode does not match. It can have exactly one child. Its syntax is
// `(!(child))`.
type Not struct {
	Node FilterNode
}

// Match implements the Match method of the [FilterNode] interface.
func (f *Not) Match(e *Entry) bool {
	return !f.Node.Match(e)
}

type parseError struct{ err error }

// panice panics with a parseError so the top level Parse function can recover
// and return the error, while re-panicking a non-parse-error.
func panice(err error) {
	panic(parseError{err: err})
}

// panicf formats an error and panics with it in a parseError so the top level
// Parse function can recover and return the error, while re-panicking a
// non-parse-error.
func panicf(format string, args ...any) {
	panic(parseError{err: fmt.Errorf(format, args...)})
}

type cursor struct {
	input []rune
	pos   int
}

func (c *cursor) isEOF() bool {
	return c.pos >= len(c.input)
}

func (c *cursor) peek() rune {
	if c.isEOF() {
		panice(ErrUnexpectedEOF)
	}
	return c.input[c.pos]
}

func (c *cursor) extractTo(r rune) []rune {
	start := c.pos
	for ; !c.isEOF() && c.input[c.pos] != r; c.pos++ {
	}
	return c.input[start:c.pos]
}

func (c *cursor) expectRune(r rune) {
	if c.isEOF() {
		panicf("%w: expecting %q", ErrUnexpectedEOF, r)
	}
	next := c.peek()
	if next != r {
		panicf("%w: %q expecting %q", ErrUnexpectedInput, next, r)
	}
	c.pos++
}
