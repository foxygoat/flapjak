package main

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
)

// ReadJSON parses JSON from an [io.Reader] and returns a slice of the entries
// parsed. The top-level JSON can be either an array of objects or an object.
// If the top-level is an array, each element must be an ldap entry or an array
// of entries. If the top-level is an object, each field's value must be an
// ldap entry or an array of ldap entries.
//
// An entry must contain at least a `dn` field and an `objectClass` field. If
// the parsed JSON deviates from this structure or the io.Reader cannot be
// parsed as JSON, an error is returned instead.
func ReadJSON(r io.Reader) ([]*Entry, error) {
	var input any
	err := json.NewDecoder(r).Decode(&input)
	if err != nil {
		return nil, fmt.Errorf("could not create LDAP DB from JSON: %w", err)
	}

	// Allow an object (map) at the top level where fields in the object
	// are entries or slices of entries. All other objects must be entries.
	array, ok := input.([]any)
	if !ok {
		// If the top-level JSON is not an array, allow an object and
		// process each key's values as an entry or array of entries.
		obj, ok := input.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("non-aggregate type at top level of JSON: %#T", input)
		}
		// Check all top-level values (tlv) of the fields of the top-level object.
		// Join any arrays that a are values.
		for tlv := range maps.Values(obj) {
			if a, ok := tlv.([]any); ok {
				array = append(array, a...)
			} else {
				array = append(array, tlv)
			}
		}
	}

	entries, err := getEntries(array)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func getEntries(a any) ([]*Entry, error) {
	var entries []*Entry
	switch v := a.(type) {
	case []any:
		for _, elem := range v {
			e, err := getEntries(elem)
			if err != nil {
				return nil, err
			}
			entries = append(entries, e...)
		}
	case map[string]any:
		entry, err := NewEntryFromMap(v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	default:
		return nil, fmt.Errorf("non-aggregate value when aggregate expected: %v", v)
	}
	return entries, nil
}
