package ldap

import (
	"bytes"
	"errors"
	"io"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/matryer/is"
)

// nest builds an encoding of depth nested constructed elements, innermost
// first, so that a small input describes an arbitrarily deep structure.
func nest(depth int) []byte {
	buf := []byte{0x30, 0x00}
	for range depth - 1 {
		buf = append(sequenceHeader(len(buf)), buf...)
	}
	return buf
}

// sequenceHeader returns the identifier and length octets of a SEQUENCE holding
// size content octets, in the definite form BER requires.
func sequenceHeader(size int) []byte {
	if size < 0x80 {
		return []byte{0x30, byte(size & 0x7f)}
	}
	var length []byte
	for n := size; n > 0; n >>= 8 {
		length = append([]byte{byte(n & 0xff)}, length...)
	}
	count := byte(len(length) & 0x7f)
	return append([]byte{0x30, 0x80 | count}, length...)
}

// deepMessage builds a well-formed LDAPMessage whose protocol operation holds
// nothing but nested elements. The envelope has to be valid, or the message
// would be refused for its shape before its depth was ever reached.
func deepMessage(depth int) []byte {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tagSearchRequest, nil, "SearchRequest")
	op.Data.Write(nest(depth))
	return encodeMessage(1, op)
}

func TestReadMessageLimits(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{
			// A declared length of 2 GiB. The header is all that is
			// read: refusing it must not allocate what it asks for.
			name: "oversized declared length",
			in:   []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff},
		},
		{
			name: "length just over the limit",
			in:   []byte{0x30, 0x84, 0x00, 0x40, 0x00, 0x01},
		},
		{
			// 0x80 with no count is the indefinite form, which RFC
			// 4511 section 5.1 does not permit.
			name: "indefinite length",
			in:   []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00},
		},
		{
			name: "overlong length",
			in:   []byte{0x30, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
		},
		{
			name: "high tag number form",
			in:   []byte{0x3f, 0x81, 0x00, 0x02},
		},
		{
			// The envelope and the operation take two levels, so
			// this is the shallowest input the cap rejects.
			name: "nesting one past the limit",
			in:   deepMessage(MaxMessageDepth - 1),
		},
		{
			// Deep enough that decoding it would exhaust memory.
			name: "deep nesting",
			in:   deepMessage(20000),
		},
		{
			name: "element runs past the message",
			in:   []byte{0x30, 0x03, 0x30, 0x07, 0x00},
		},
		{
			// The outer element is in bounds, so this reaches the
			// parent check rather than the end-of-message one.
			name: "child runs past its parent",
			in:   []byte{0x30, 0x06, 0x30, 0x01, 0x30, 0x02, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			_, err := readMessage(bytes.NewReader(tt.in))
			is.True(err != nil)
			is.True(errors.Is(err, ErrMalformed))
		})
	}
}

// TestReadMessageBoundary checks the framing of well-formed input: a message is
// decoded without consuming the one behind it, and a clean close between
// messages is reported as io.EOF rather than as a fault.
func TestReadMessageBoundary(t *testing.T) {
	is := is.New(t)

	pipelined := append(
		encodeMessage(1, extendedOp(oidStartTLS)),
		encodeMessage(2, extendedOp(oidWhoAmI))...)
	r := bytes.NewReader(pipelined)

	m1, err := readMessage(r)
	is.NoErr(err)
	is.Equal(m1.id, int32(1))

	m2, err := readMessage(r)
	is.NoErr(err)
	is.Equal(m2.id, int32(2))

	_, err = readMessage(r)
	is.Equal(err, io.EOF)
}

// TestReadMessageNestedFilter checks that a filter nested to the limit is still
// accepted, so the cap rejects only what no real client sends.
func TestReadMessageNestedFilter(t *testing.T) {
	is := is.New(t)

	// The LDAPMessage envelope and the SearchRequest hold the outermost two
	// levels, so the filter gets the rest of the budget.
	const levels = MaxMessageDepth - 2

	filter := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterEquality, nil, "equalityMatch")
	filter.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "attributeDesc"))
	filter.AppendChild(newOctetString([]byte("x"), "assertionValue"))
	want := "(cn=x)"
	for range levels - 1 {
		and := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterAnd, nil, "and")
		and.AppendChild(filter)
		filter = and
		want = "(&" + want + ")"
	}

	m, err := readMessage(bytes.NewReader(encodeMessage(1, searchOp(filter))))
	is.NoErr(err)

	req, err := decodeSearch(m.op, Request{})
	is.NoErr(err)
	is.Equal(req.Filter.String(), want)
}
