package ldap

import (
	"context"
	"errors"
	"maps"
	"slices"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// SearchResponse writes the entries a search finds. A search is a stream of
// zero or more entries followed by a single result, so entries are written as
// they are found and the result is sent by the package when the handler
// returns.
//
// A SearchResponse is not safe for concurrent use; write entries from the
// goroutine the handler runs on.
type SearchResponse struct {
	conn *conn
	// ctx is the operation's context, held so that Entry can refuse to
	// write after the search has been abandoned or has run past its time
	// limit. It is request-scoped and lives exactly as long as the handler
	// call.
	ctx       context.Context //nolint:containedctx // scoped to one operation
	id        int32
	typesOnly bool
	sizeLimit int
	count     int
}

// errSizeLimit is returned by Entry once the request's size limit is reached.
// A handler that passes it back gets the search concluded with
// sizeLimitExceeded, which is what the client is owed.
var errSizeLimit = errors.New("search size limit exceeded")

// Entry writes one entry of a search result.
//
// Attribute values are converted with [Value], so they may be any type it
// accepts rather than only strings. Attributes are written in name order so
// that responses are reproducible. If the request set TypesOnly, values are
// omitted and only the attribute names are sent; the caller does not need to
// handle that case.
//
// Entry returns an error if the search has been abandoned, has run past the
// request's time limit, or has already written as many entries as the request
// asked for. In each case the handler should stop and return that error, which
// the package turns into the right result for the client.
func (w *SearchResponse) Entry(dn string, attrs map[string][]any) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.sizeLimit > 0 && w.count >= w.sizeLimit {
		return errSizeLimit
	}

	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tagSearchResultEntry, nil, "SearchResultEntry")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "objectName"))

	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, name := range slices.Sorted(maps.Keys(attrs)) {
		attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))

		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		if !w.typesOnly {
			vals, err := values(attrs[name])
			if err != nil {
				return err
			}
			for _, v := range vals {
				set.AppendChild(newOctetString(v, "value"))
			}
		}
		attr.AppendChild(set)
		list.AppendChild(attr)
	}
	p.AppendChild(list)

	w.count++
	return w.conn.write(encodeMessage(w.id, p))
}

// Reference writes a search result reference: a set of URIs at which the
// client may continue the search. It is not used by servers that hold the
// whole tree, which is most of them.
func (w *SearchResponse) Reference(uris ...string) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tagSearchResultReference, nil, "SearchResultReference")
	for _, uri := range uris {
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, uri, "uri"))
	}
	return w.conn.write(encodeMessage(w.id, p))
}

// Count returns the number of entries written so far.
func (w *SearchResponse) Count() int { return w.count }

// encodeExtendedResponse builds an ExtendedResponse. Either of name and value
// may be empty, in which case it is omitted.
func encodeExtendedResponse(code Code, diagnostic, name string, value []byte) *ber.Packet {
	p := encodeResult(tagExtendedResponse, code, "", diagnostic)
	if name != "" {
		p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagResponseName, name, "responseName"))
	}
	if value != nil {
		v := ber.Encode(ber.ClassContext, ber.TypePrimitive, tagResponseValue, nil, "responseValue")
		v.Data.Write(value)
		p.AppendChild(v)
	}
	return p
}
