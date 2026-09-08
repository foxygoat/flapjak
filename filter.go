package main

import (
	"slices"

	"foxygo.at/flapjak/ldap"
)

// Match reports whether the entry behind view satisfies filter f.
//
// The filter arrives from the ldap package already decoded from the wire, so
// there is nothing to parse here: this is only the matching semantics. Since
// flapjak has no schema, how a value compares is decided by the kind the value
// was given in the jsonnet that defined it. See [Attr.HasValue].
//
// Matching goes through an [EntryView] rather than the entry, so the Entry as
// seen by the BindDN user is filtered, disallowing filters to match against
// fields they cannot see.
//
// An extensible match always fails, since evaluating one needs the named
// matching rule and flapjak has no schema to look one up in. A search refuses
// such a filter before it gets here, because failing is the wrong answer under
// a negation: see [HasExtensibleMatch].
func Match(f ldap.Filter, view EntryView) bool {
	switch f := f.(type) {
	case ldap.And:
		for _, sub := range f {
			if !Match(sub, view) {
				return false
			}
		}
		return true

	case ldap.Or:
		for _, sub := range f {
			if Match(sub, view) {
				return true
			}
		}
		return false

	case ldap.Not:
		return !Match(f.Filter, view)

	case ldap.Present:
		_, ok := view.GetAttr(f.Attribute)
		return ok

	case ldap.Equality:
		a, ok := view.GetAttr(f.Attribute)
		return ok && a.HasValue(f.Value)

	case ldap.Approx:
		// Without a schema there is no approximate matching rule to
		// apply, so this is equality, as on most servers.
		a, ok := view.GetAttr(f.Attribute)
		return ok && a.HasValue(f.Value)

	case ldap.GreaterOrEqual:
		a, ok := view.GetAttr(f.Attribute)
		return ok && a.AtLeast(f.Value)

	case ldap.LessOrEqual:
		a, ok := view.GetAttr(f.Attribute)
		return ok && a.AtMost(f.Value)

	case ldap.Substrings:
		a, ok := view.GetAttr(f.Attribute)
		return ok && a.MatchSubstrings(f.Initial, f.Any, f.Final)

	case ldap.ExtensibleMatch:
		return false

	default:
		return false
	}
}

// HasExtensibleMatch reports whether f contains an extensible match anywhere.
//
// RFC 4511 section 4.5.1.7 says a match whose rule cannot be applied evaluates
// to Undefined, and not of Undefined is Undefined, so neither answer [Match]
// can give is right: failing makes a negated extensible match select every
// entry. A search refuses the filter instead, which is both honest and
// something the client can act on.
func HasExtensibleMatch(f ldap.Filter) bool {
	switch f := f.(type) {
	case ldap.And:
		return slices.ContainsFunc(f, HasExtensibleMatch)
	case ldap.Or:
		return slices.ContainsFunc(f, HasExtensibleMatch)
	case ldap.Not:
		return HasExtensibleMatch(f.Filter)
	case ldap.ExtensibleMatch:
		return true
	default:
		return false
	}
}
