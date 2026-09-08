package ldap

import (
	"bytes"
	"fmt"
	"io"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// MaxMessageSize bounds the encoded size of a single LDAP message. A message
// declaring more than this is rejected from its length octets alone, before any
// of its content is read.
const MaxMessageSize int64 = 4 << 20

// MaxMessageDepth bounds how deeply the elements of a message may nest.
// Decoding is recursive and each child is copied into its parent, so an
// unbounded depth costs memory quadratic in it. Nesting this deep only arises
// in a search filter, and no real one approaches the limit.
const MaxMessageDepth = 32

// Control is an LDAP control attached to a request, as defined by RFC 4511
// section 4.1.11.
//
// This package recognises no controls. A request carrying one marked critical
// is rejected with UnavailableCriticalExtension without reaching the handler,
// as RFC 4511 section 4.1.11 requires; non-critical controls are decoded and
// otherwise ignored.
type Control struct {
	OID         string
	Criticality bool
	Value       []byte
}

// message is a decoded LDAPMessage envelope. The protocol operation is kept as
// a BER packet for the per-operation decoders to interpret.
type message struct {
	id       int32
	op       *ber.Packet
	controls []Control
}

// opName returns a name for the message's operation, for logging.
func (m *message) opName() string {
	if name, ok := opNames[m.op.Tag]; ok {
		return name
	}
	return fmt.Sprintf("op(%d)", m.op.Tag)
}

// content returns the content octets of a primitive BER packet.
//
// go-asn1-ber only populates ByteValue for packets in the universal class; for
// application- and context-class packets it writes the content to Data alone.
// Reading Data works for both, so all content access goes through here.
func content(p *ber.Packet) string {
	return p.Data.String()
}

// readMessage reads one LDAPMessage from r. It returns io.EOF when the peer
// closes the connection cleanly between messages. An error is returned if the
// wire encoding of the message is larger than MaxMessageSize, the child
// nesting depth is larger than MaxMessageDepth, or the message cannot be
// decoded.
func readMessage(r io.Reader) (*message, error) {
	buf, err := readElement(r, MaxMessageSize)
	if err != nil {
		return nil, err
	}
	if err := checkDepth(buf, MaxMessageDepth); err != nil {
		return nil, err
	}

	p, err := ber.ReadPacket(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}

	if p.ClassType != ber.ClassUniversal || p.Tag != ber.TagSequence || len(p.Children) < 2 {
		return nil, fmt.Errorf("%w: not an LDAPMessage", ErrMalformed)
	}

	id, ok := p.Children[0].Value.(int64)
	if !ok {
		return nil, fmt.Errorf("%w: missing message ID", ErrMalformed)
	}
	if id < 0 || id > math.MaxInt32 {
		return nil, fmt.Errorf("%w: message ID %d out of range", ErrMalformed, id)
	}

	op := p.Children[1]
	if op.ClassType != ber.ClassApplication {
		return nil, fmt.Errorf("%w: protocol operation is not an application type", ErrMalformed)
	}

	m := &message{id: int32(id), op: op}

	// Controls are an optional [0] context-tagged element following the
	// protocol operation.
	for _, child := range p.Children[2:] {
		if child.ClassType == ber.ClassContext && child.Tag == tagControls {
			m.controls, err = decodeControls(child)
			if err != nil {
				return nil, err
			}
		}
	}

	return m, nil
}

// parseHeader decodes the identifier and length octets at the start of buf,
// returning the number of header octets and the declared content length.
//
// RFC 4511 section 5.1 restricts LDAP to the definite length form and to tags
// that fit the low bits of the identifier, so the indefinite form and the high
// tag number form are both rejected rather than decoded. A length is refused as
// soon as the octets read so far exceed limit, which also keeps the accumulator
// from overflowing.
func parseHeader(buf []byte, limit int64) (int, int64, error) {
	if len(buf) < 2 {
		return 0, 0, fmt.Errorf("%w: truncated element header", ErrMalformed)
	}
	if buf[0]&0x1f == 0x1f {
		return 0, 0, fmt.Errorf("%w: high tag number form", ErrMalformed)
	}
	if buf[1] < 0x80 {
		return 2, int64(buf[1]), nil
	}

	count := int(buf[1] & 0x7f)
	if count == 0 || count > 8 {
		return 0, 0, fmt.Errorf("%w: length is indefinite or overlong", ErrMalformed)
	}
	if len(buf) < 2+count {
		return 0, 0, fmt.Errorf("%w: truncated element header", ErrMalformed)
	}

	var size int64
	for _, octet := range buf[2 : 2+count] {
		size = size<<8 | int64(octet)
		if size > limit {
			return 0, 0, fmt.Errorf("%w: element of %d bytes exceeds the %d byte limit", ErrMalformed, size, limit)
		}
	}
	return 2 + count, size, nil
}

// readElement reads one complete BER element from r, header and content
// together, and returns its encoding. Nothing beyond the element is consumed.
//
// The declared length is checked against limit before the content is read, so an
// element claiming to be enormous is refused at the cost of its header rather
// than by allocating what it asks for.
func readElement(r io.Reader, limit int64) ([]byte, error) {
	hdr := make([]byte, 2, 10)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	// A first length octet above 0x80 counts the octets holding the length;
	// they have to be in hand before the header can be decoded.
	if hdr[1] > 0x80 {
		count := int(hdr[1] & 0x7f)
		if count > 8 {
			return nil, fmt.Errorf("%w: length is overlong", ErrMalformed)
		}
		hdr = hdr[:2+count]
		if _, err := io.ReadFull(r, hdr[2:]); err != nil {
			return nil, err
		}
	}

	hdrLen, size, err := parseHeader(hdr, limit)
	if err != nil {
		return nil, err
	}
	if size > limit-int64(hdrLen) {
		return nil, fmt.Errorf("%w: element of %d bytes exceeds the %d byte limit", ErrMalformed, size, limit)
	}

	buf := make([]byte, hdrLen+int(size))
	copy(buf, hdr)
	if _, err := io.ReadFull(r, buf[hdrLen:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// checkDepth returns an error if the elements encoded in buf nest deeper than
// limit, or if an element runs past its parent or past the end of buf. It walks
// the encoding iteratively, so checking costs no stack of its own.
func checkDepth(buf []byte, limit int) error {
	// ends holds the offset at which each open constructed element
	// finishes, so its length is the depth at the current position.
	ends := make([]int, 0, limit)
	for pos := 0; pos < len(buf); {
		for len(ends) > 0 && ends[len(ends)-1] <= pos {
			ends = ends[:len(ends)-1]
		}

		hdrLen, size, err := parseHeader(buf[pos:], int64(len(buf)))
		if err != nil {
			return err
		}
		end := pos + hdrLen + int(size)
		if end > len(buf) {
			return fmt.Errorf("%w: element runs past the end of the message", ErrMalformed)
		}
		if len(ends) > 0 && end > ends[len(ends)-1] {
			return fmt.Errorf("%w: element runs past its parent", ErrMalformed)
		}

		// A primitive element holds content octets, not more elements,
		// so it is stepped over rather than descended into.
		if buf[pos]&0x20 == 0 {
			pos = end
			continue
		}
		if len(ends)+1 > limit {
			return fmt.Errorf("%w: nesting deeper than %d elements", ErrMalformed, limit)
		}
		ends = append(ends, end)
		pos += hdrLen
	}
	return nil
}

func decodeControls(p *ber.Packet) ([]Control, error) {
	cs := make([]Control, 0, len(p.Children))
	for _, child := range p.Children {
		if len(child.Children) == 0 {
			return nil, fmt.Errorf("%w: empty control", ErrMalformed)
		}
		c := Control{OID: content(child.Children[0])}
		// criticality and controlValue are both optional and are
		// distinguished by their universal tag, not by position.
		for _, field := range child.Children[1:] {
			switch field.Tag {
			case ber.TagBoolean:
				c.Criticality = len(content(field)) > 0 && content(field)[0] != 0
			case ber.TagOctetString:
				c.Value = []byte(content(field))
			}
		}
		cs = append(cs, c)
	}
	return cs, nil
}

// checkControls rejects any control marked critical. This package recognises
// no controls, so a critical one can never be honoured.
func checkControls(cs []Control) error {
	for _, c := range cs {
		if c.Criticality {
			return &Error{
				Code:       UnavailableCriticalExtension,
				Diagnostic: "unrecognised critical control: " + c.OID,
			}
		}
	}
	return nil
}

// responseTags maps a request's application tag to the tag of the response
// that concludes it. Operations absent from this map take no response.
var responseTags = map[ber.Tag]ber.Tag{
	tagBindRequest:     tagBindResponse,
	tagSearchRequest:   tagSearchResultDone,
	tagModifyRequest:   tagModifyResponse,
	tagAddRequest:      tagAddResponse,
	tagDelRequest:      tagDelResponse,
	tagModifyDNRequest: tagModifyDNResponse,
	tagCompareRequest:  tagCompareResponse,
	tagExtendedRequest: tagExtendedResponse,
}

// encodeMessage wraps a protocol operation in an LDAPMessage envelope and
// returns its encoding.
func encodeMessage(id int32, op *ber.Packet) []byte {
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(id), "messageID"))
	m.AppendChild(op)
	return m.Bytes()
}

// encodeResult builds a response consisting of the COMPONENTS OF LDAPResult:
// result code, matched DN and diagnostic message.
func encodeResult(tag ber.Tag, code Code, matchedDN, diagnostic string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "resultCode"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, matchedDN, "matchedDN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnostic, "diagnosticMessage"))
	return p
}

// newOctetString returns a universal OCTET STRING packet holding b. Attribute
// values are arbitrary octets, so they are written as bytes rather than
// through ber.NewString.
func newOctetString(b []byte, description string) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, description)
	p.Data.Write(b)
	return p
}
