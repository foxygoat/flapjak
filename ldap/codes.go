// Package ldap implements a minimal LDAPv3 server.
//
// It provides the message layer defined by RFC 4511 on top of the BER encoding
// provided by github.com/go-asn1-ber/asn1-ber. Applications implement the
// [Handler] interface to serve directory operations, embedding [Unsupported]
// to decline the operations they do not implement.
//
// See doc/ldap-server.md in this repository for the design rationale.
package ldap

import (
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Code is an LDAP result code as defined by RFC 4511 Appendix A.
type Code uint16

// Result codes. Only the codes this package can produce are given names; a
// handler may return any code, including ones not listed here.
//
// The compare codes are unexported: a compare handler reports its answer by
// returning a bool, so there is no reason for one to name them.
const (
	Success                      Code = 0
	OperationsError              Code = 1
	ProtocolError                Code = 2
	TimeLimitExceeded            Code = 3
	SizeLimitExceeded            Code = 4
	compareFalse                 Code = 5
	compareTrue                  Code = 6
	AuthMethodNotSupported       Code = 7
	StrongerAuthRequired         Code = 8
	Referral                     Code = 10
	AdminLimitExceeded           Code = 11
	UnavailableCriticalExtension Code = 12
	ConfidentialityRequired      Code = 13
	SASLBindInProgress           Code = 14
	NoSuchAttribute              Code = 16
	UndefinedAttributeType       Code = 17
	InappropriateMatching        Code = 18
	ConstraintViolation          Code = 19
	AttributeOrValueExists       Code = 20
	InvalidAttributeSyntax       Code = 21
	NoSuchObject                 Code = 32
	AliasProblem                 Code = 33
	InvalidDNSyntax              Code = 34
	AliasDereferencingProblem    Code = 36
	InappropriateAuthentication  Code = 48
	InvalidCredentials           Code = 49
	InsufficientAccessRights     Code = 50
	Busy                         Code = 51
	Unavailable                  Code = 52
	UnwillingToPerform           Code = 53
	LoopDetect                   Code = 54
	NamingViolation              Code = 64
	ObjectClassViolation         Code = 65
	NotAllowedOnNonLeaf          Code = 66
	NotAllowedOnRDN              Code = 67
	EntryAlreadyExists           Code = 68
	ObjectClassModsProhibited    Code = 69
	AffectsMultipleDSAs          Code = 71
	Other                        Code = 80
)

var codeNames = map[Code]string{
	Success:                      "success",
	OperationsError:              "operationsError",
	ProtocolError:                "protocolError",
	TimeLimitExceeded:            "timeLimitExceeded",
	SizeLimitExceeded:            "sizeLimitExceeded",
	compareFalse:                 "compareFalse",
	compareTrue:                  "compareTrue",
	AuthMethodNotSupported:       "authMethodNotSupported",
	StrongerAuthRequired:         "strongerAuthRequired",
	Referral:                     "referral",
	AdminLimitExceeded:           "adminLimitExceeded",
	UnavailableCriticalExtension: "unavailableCriticalExtension",
	ConfidentialityRequired:      "confidentialityRequired",
	SASLBindInProgress:           "saslBindInProgress",
	NoSuchAttribute:              "noSuchAttribute",
	UndefinedAttributeType:       "undefinedAttributeType",
	InappropriateMatching:        "inappropriateMatching",
	ConstraintViolation:          "constraintViolation",
	AttributeOrValueExists:       "attributeOrValueExists",
	InvalidAttributeSyntax:       "invalidAttributeSyntax",
	NoSuchObject:                 "noSuchObject",
	AliasProblem:                 "aliasProblem",
	InvalidDNSyntax:              "invalidDNSyntax",
	AliasDereferencingProblem:    "aliasDereferencingProblem",
	InappropriateAuthentication:  "inappropriateAuthentication",
	InvalidCredentials:           "invalidCredentials",
	InsufficientAccessRights:     "insufficientAccessRights",
	Busy:                         "busy",
	Unavailable:                  "unavailable",
	UnwillingToPerform:           "unwillingToPerform",
	LoopDetect:                   "loopDetect",
	NamingViolation:              "namingViolation",
	ObjectClassViolation:         "objectClassViolation",
	NotAllowedOnNonLeaf:          "notAllowedOnNonLeaf",
	NotAllowedOnRDN:              "notAllowedOnRDN",
	EntryAlreadyExists:           "entryAlreadyExists",
	ObjectClassModsProhibited:    "objectClassModsProhibited",
	AffectsMultipleDSAs:          "affectsMultipleDSAs",
	Other:                        "other",
}

// String returns the RFC 4511 name of the result code, or its decimal value if
// the code is not one this package knows.
func (c Code) String() string {
	if s, ok := codeNames[c]; ok {
		return s
	}
	return fmt.Sprintf("Code(%d)", uint16(c))
}

// Application tags for the protocolOp CHOICE of an LDAPMessage, from RFC 4511
// section 4.1.1. Note that these are not contiguous: searchResRef is 19, not
// the 6 that following on from searchResDone would suggest.
const (
	tagBindRequest           ber.Tag = 0
	tagBindResponse          ber.Tag = 1
	tagUnbindRequest         ber.Tag = 2
	tagSearchRequest         ber.Tag = 3
	tagSearchResultEntry     ber.Tag = 4
	tagSearchResultDone      ber.Tag = 5
	tagModifyRequest         ber.Tag = 6
	tagModifyResponse        ber.Tag = 7
	tagAddRequest            ber.Tag = 8
	tagAddResponse           ber.Tag = 9
	tagDelRequest            ber.Tag = 10
	tagDelResponse           ber.Tag = 11
	tagModifyDNRequest       ber.Tag = 12
	tagModifyDNResponse      ber.Tag = 13
	tagCompareRequest        ber.Tag = 14
	tagCompareResponse       ber.Tag = 15
	tagAbandonRequest        ber.Tag = 16
	tagSearchResultReference ber.Tag = 19
	tagExtendedRequest       ber.Tag = 23
	tagExtendedResponse      ber.Tag = 24
)

// AuthenticationChoice tags from the BindRequest of RFC 4511 section 4.2, in
// the context class.
const (
	tagAuthSimple ber.Tag = 0
	tagAuthSASL   ber.Tag = 3
)

// Extended operation component tags from RFC 4511 section 4.12, in the context
// class. The request and the response number their components separately.
const (
	tagRequestName   ber.Tag = 0
	tagRequestValue  ber.Tag = 1
	tagResponseName  ber.Tag = 10
	tagResponseValue ber.Tag = 11
)

// tagControls is the LDAPMessage controls component of RFC 4511 section 4.1.1,
// in the context class.
const tagControls ber.Tag = 0

// opNames maps a request application tag to a name for logging.
var opNames = map[ber.Tag]string{
	tagBindRequest:     "bind",
	tagUnbindRequest:   "unbind",
	tagSearchRequest:   "search",
	tagModifyRequest:   "modify",
	tagAddRequest:      "add",
	tagDelRequest:      "delete",
	tagModifyDNRequest: "modifyDN",
	tagCompareRequest:  "compare",
	tagAbandonRequest:  "abandon",
	tagExtendedRequest: "extended",
}

// Sentinel errors this package returns. They do not share a result code, and
// some are returned before any client is served.
var (
	ErrMalformed   = errors.New("malformed message")
	ErrUnknownOp   = errors.New("unknown protocol operation")
	ErrBadFilter   = errors.New("malformed search filter")
	ErrBadValue    = errors.New("value cannot be encoded as an LDAP attribute value")
	ErrNoTLSConfig = errors.New("no TLS configuration")
	ErrNoHandler   = errors.New("server has no handler")
)

// Error is an LDAP result carrying a non-success code. A [Handler] returns one
// to control the result code sent to the client; any other error is reported
// as OperationsError with a generic diagnostic so that internal detail is not
// disclosed.
type Error struct {
	Code       Code
	Diagnostic string
	MatchedDN  string
}

// Errorf returns an [Error] with the given code and a formatted diagnostic.
func Errorf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Diagnostic: fmt.Sprintf(format, args...)}
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Diagnostic == "" {
		return e.Code.String()
	}
	return e.Code.String() + ": " + e.Diagnostic
}

// result reduces err to the result code, diagnostic and matched DN to send to
// the client.
//
// A nil error is Success and an error unwrapping to an [Error] is reported as
// given. A request this package could not decode is a protocolError. Anything
// else is the handler failing in a way the client cannot act on, and is
// reported as OperationsError with a generic diagnostic so that internal
// detail is not disclosed; the caller is expected to log the original.
func result(err error) (Code, string, string) {
	var lerr *Error
	switch {
	case err == nil:
		return Success, "", ""
	case errors.As(err, &lerr):
		return lerr.Code, lerr.Diagnostic, lerr.MatchedDN
	case errors.Is(err, ErrMalformed), errors.Is(err, ErrBadFilter), errors.Is(err, ErrUnknownOp):
		return ProtocolError, err.Error(), ""
	case errors.Is(err, ErrBadValue):
		// The handler offered a value that cannot be put on the wire.
		return OperationsError, "attribute value cannot be encoded", ""
	default:
		return OperationsError, "internal error", ""
	}
}
