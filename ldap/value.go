package ldap

import (
	"encoding"
	"fmt"
	"strconv"
	"time"
)

// generalizedTimeLayout is the RFC 4517 GeneralizedTime encoding. A UTC time
// is suffixed with "Z"; any other zone with a "+hhmm" or "-hhmm" differential.
const generalizedTimeLayout = "20060102150405Z0700"

// Value encodes v as the octets of an LDAP attribute value.
//
// Every attribute value in LDAPv3 is transferred as an OCTET STRING: unlike
// X.500, the protocol carries no type information, and a schema's syntax
// selects a string encoding rather than an ASN.1 type. Value applies the
// RFC 4517 LDAP-specific encoding for the Go types that have one, so that
// callers do not have to.
//
// Values are converted as follows:
//
//	[]byte, string                 used as-is
//	bool                           "TRUE" or "FALSE"
//	integer types                  decimal
//	float32, float64               decimal, shortest round-trip form
//	time.Time                      GeneralizedTime
//	encoding.TextMarshaler         MarshalText
//	fmt.Stringer                   String
//
// Any other type returns an error wrapping [ErrBadValue]. In particular a nil
// value is an error: LDAP has no way to express one.
func Value(v any) ([]byte, error) {
	switch v := v.(type) {
	case nil:
		return nil, fmt.Errorf("%w: nil", ErrBadValue)
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	case bool:
		if v {
			return []byte("TRUE"), nil
		}
		return []byte("FALSE"), nil
	case int:
		return strconv.AppendInt(nil, int64(v), 10), nil
	case int8:
		return strconv.AppendInt(nil, int64(v), 10), nil
	case int16:
		return strconv.AppendInt(nil, int64(v), 10), nil
	case int32:
		return strconv.AppendInt(nil, int64(v), 10), nil
	case int64:
		return strconv.AppendInt(nil, v, 10), nil
	case uint:
		return strconv.AppendUint(nil, uint64(v), 10), nil
	case uint8:
		return strconv.AppendUint(nil, uint64(v), 10), nil
	case uint16:
		return strconv.AppendUint(nil, uint64(v), 10), nil
	case uint32:
		return strconv.AppendUint(nil, uint64(v), 10), nil
	case uint64:
		return strconv.AppendUint(nil, v, 10), nil
	// An integral float renders as a bare integer: 1000, not 1000.0 or
	// 1e+03. The RFC 4517 Integer syntax has no decimal point and no
	// exponent, so either spelling would be a value no client can read as a
	// number. 'f' with a precision of -1 is what keeps that true.
	case float32:
		return strconv.AppendFloat(nil, float64(v), 'f', -1, 32), nil
	case float64:
		return strconv.AppendFloat(nil, v, 'f', -1, 64), nil
	case time.Time:
		return []byte(v.Format(generalizedTimeLayout)), nil
	case encoding.TextMarshaler:
		b, err := v.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBadValue, err)
		}
		return b, nil
	case fmt.Stringer:
		return []byte(v.String()), nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrBadValue, v)
	}
}

// values encodes each element of vs with [Value].
func values(vs []any) ([][]byte, error) {
	if len(vs) == 0 {
		return nil, nil
	}
	result := make([][]byte, 0, len(vs))
	for _, v := range vs {
		b, err := Value(v)
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, nil
}
