package jwt

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pascaldekloe/jwt"
	uuid "github.com/satori/go.uuid"
)

// ErrInvalidClaimType is returned when an operation tries to return an invalid claim type.
var ErrInvalidClaimType = errors.New("invalid claim type")

const (
	// Issuer is the IANA Registered claim for JWT issuer
	Issuer string = "iss"
	// Subject is the IANA Registered claim for JWT subject
	Subject string = "sub"
	// Audience is the IANA Registered claim for JWT audience
	Audience string = "aud"
	// Expires is the IANA Registered claim for JWT expiry time
	Expires string = "exp"
	// NotBefore is the IANA Registered claim for JWT not before time
	NotBefore string = "nbf"
	// Issued is the IANA Registered claim for JWT issue time
	Issued string = "iat"
	// ID is the IANA Registered claim for JWT ID
	ID string = "jti"
)

// A ClaimType indicates which member of the Field union struct should be used
// and how it should be serialized.
type ClaimType uint8

// Type list borrowed from uber-go/zap
const (
	// UnknownType is the default, this will throw an error.
	UnknownType ClaimType = iota
	// ArrayMarshalerType indicates that the field carries an ArrayMarshaler.
	ArrayMarshalerType
	// ObjectMarshalerType indicates that the field carries an ObjectMarshaler.
	ObjectMarshalerType
	// BinaryType indicates that the field carries an opaque binary blob.
	BinaryType
	// BoolType indicates that the field carries a bool.
	BoolType
	// ByteStringType indicates that the field carries UTF-8 encoded bytes.
	ByteStringType
	// Complex128Type indicates that the field carries a complex128.
	Complex128Type
	// Complex64Type indicates that the field carries a complex128.
	Complex64Type
	// DurationType indicates that the field carries a time.Duration.
	DurationType
	// Float64Type indicates that the field carries a float64.
	Float64Type
	// Float32Type indicates that the field carries a float32.
	Float32Type
	// Int64Type indicates that the field carries an int64.
	Int64Type
	// Int32Type indicates that the field carries an int32.
	Int32Type
	// Int16Type indicates that the field carries an int16.
	Int16Type
	// Int8Type indicates that the field carries an int8.
	Int8Type
	// StringType indicates that the field carries a string.
	StringType
	// TimeType indicates that the field carries a time.Time.
	TimeType
	// Uint64Type indicates that the field carries a uint64.
	Uint64Type
	// Uint32Type indicates that the field carries a uint32.
	Uint32Type
	// Uint16Type indicates that the field carries a uint16.
	Uint16Type
	// Uint8Type indicates that the field carries a uint8.
	Uint8Type
	// UintptrType indicates that the field carries a uintptr.
	UintptrType
	// ReflectType indicates that the field carries an interface{}, which should
	// be serialized using reflection.
	ReflectType
	// NamespaceType signals the beginning of an isolated namespace. All
	// subsequent fields should be added to the new namespace.
	NamespaceType
	// StringerType indicates that the field carries a fmt.Stringer.
	StringerType
	// ErrorType indicates that the field carries an error.
	ErrorType
	// SkipType indicates that the field is a no-op.
	SkipType
)

// // Claims is JWT payload representation relayed from `jwt.Claims`.
// type Claims jwt.Claims

// A Claim is a marshaling operation used to add a key-value pair to a tokens
// context. Most claims are lazily marshaled, so it's inexpensive to add claims
// to disabled debug-level log statements.
type Claim struct {
	Key       string
	Type      ClaimType
	Integer   int64
	Uinteger  uint64
	Float     float64
	String    string
	Interface interface{}
}

// IsRegistered returns true if the Key is a IANA registered "JSON Web Token Claims".
func (c Claim) IsRegistered() bool {
	switch strings.ToLower(c.Key) {
	case "issuer", Issuer, "subject", Subject, "audience", Audience, "expires", Expires, "notbefore", NotBefore, "issued", Issued, "id", ID:
		return true
	default:
		return false
	}
}

// Field returns the JWT compatible field from some useful longer names
func (c Claim) Field() string {
	switch strings.ToLower(c.Key) {
	case "issuer", Issuer:
		return Issuer
	case "subject", Subject:
		return Subject
	case "audience", Audience:
		return Audience
	case "expires", Expires:
		return Expires
	case "notbefore", NotBefore:
		return NotBefore
	case "issued", Issued:
		return Issued
	case "id", ID:
		return ID
	default:
		return c.Key
	}
}

// Time returns the time value of the `Claim` or an error if it is not a `TimeType`
func (c Claim) Time() (time.Time, error) {
	if c.Type == TimeType {
		t := time.Unix(0, c.Integer)
		return t, nil
	}
	if c.Type == Float64Type {
		t := time.Unix(int64(c.Float), 0)
		return t, nil
	}
	return time.Time{}, ErrInvalidClaimType
}

// String constructs a claim with the given key and value.
func String(key, val string) Claim {
	return Claim{Key: key, Type: StringType, String: val}
}

// Float constructs a claim with the given key and value.
func Float(key string, val float64) Claim {
	return Claim{Key: key, Type: Float64Type, Float: val}
}

// Int constructs a claim with the given key and value.
func Int(key string, val int64) Claim {
	return Float(key, float64(val))
	// TODO Find a way around the pascaldekloe/jwt package decoding json numbers as float64 (standard encoding/json Unmarshaling)
	// return Claim{Key: key, Type: Int64Type, Interface: int64(val)}
}

// Uint constructs a claim with the given key and value.
func Uint(key string, val uint64) Claim {
	return Float(key, float64(val))
	// TODO Find a way around the pascaldekloe/jwt package decoding json numbers as float64 (standard encoding/json Unmarshaling)
	// return Claim{Key: key, Type: Uint64Type, Interface: uint64(val)}
}

// Time constructs a claim with the given key and value.
func Time(key string, val time.Time) Claim {
	return Claim{
		Key:     key,
		Type:    TimeType,
		Integer: val.UnixNano(),
		// Interface: val.Location(),
	}
}

// Bool constructs a claim with the given key and value.
func Bool(key string, val bool) Claim {
	return Claim{Key: key, Type: BoolType, Interface: val}
}

// Reflect constructs a claim with the given key and an arbitrary object. It uses
// an encoding-appropriate, reflection-based function to lazily serialize nearly
// any object into the logging context, but it's relatively slow and
// allocation-heavy. Outside tests, Any is always a better choice.
//
// If encoding fails (e.g., trying to serialize a map[int]string to JSON), Reflect
// includes the error message in the final log output.
func Reflect(key string, val interface{}) Claim {
	return Claim{Key: key, Type: ReflectType, Interface: val}
}

// Any takes a key and an arbitrary value and chooses the best way to represent
// them as a claim, falling back to a reflection-based approach only if
// necessary.
//
// Since byte/uint8 and rune/int32 are aliases, Any can't differentiate between
// them. To minimize surprises, []byte values are treated as binary blobs, byte
// values are treated as uint8, and runes are always treated as integers.
//
// nolint: gocyclo
func Any(key string, value interface{}) Claim {
	switch val := value.(type) {
	// case ObjectMarshaler:
	// 	return Object(key, val)
	// case ArrayMarshaler:
	// 	return Array(key, val)
	case bool:
		return Bool(key, val)
	// case []bool:
	// 	return Bools(key, val)
	// case complex128:
	// 	return Complex128(key, val)
	// case []complex128:
	// 	return Complex128s(key, val)
	// case complex64:
	// 	return Complex64(key, val)
	// case []complex64:
	// 	return Complex64s(key, val)
	case float64:
		return Float(key, val)
	// case []float64:
	// 	return Float64s(key, val)
	case float32:
		return Float(key, float64(val))
	// case []float32:
	// 	return Float32s(key, val)
	case int:
		return Int(key, int64(val))
	// case []int:
	// 	return Ints(key, val)
	case int64:
		return Int(key, val)
	// case []int64:
	// 	return Int64s(key, val)
	case int32:
		return Int(key, int64(val))
	// case []int32:
	// 	return Int32s(key, val)
	case int16:
		return Int(key, int64(val))
	// case []int16:
	// 	return Int16s(key, val)
	case int8:
		return Int(key, int64(val))
	// case []int8:
	// 	return Int8s(key, val)
	case string:
		return String(key, val)
	// case []string:
	// 	return Strings(key, val)
	case uint:
		return Uint(key, uint64(val))
	// case []uint:
	// 	return Uints(key, val)
	case uint64:
		return Uint(key, val)
	// case []uint64:
	// 	return Uint64s(key, val)
	case uint32:
		return Uint(key, uint64(val))
	// case []uint32:
	// 	return Uint32s(key, val)
	case uint16:
		return Uint(key, uint64(val))
	// case []uint16:
	// 	return Uint16s(key, val)
	case uint8:
		return Uint(key, uint64(val))
	// case []byte:
	// 	return Binary(key, val)
	// case uintptr:
	// 	return Uintptr(key, val)
	// case []uintptr:
	// 	return Uintptrs(key, val)
	case time.Time:
		return Time(key, val)
	// case []time.Time:
	// 	return Times(key, val)
	// case time.Duration:
	// 	return Duration(key, val)
	// case []time.Duration:
	// 	return Durations(key, val)
	// case error:
	// 	return NamedError(key, val)
	// case []error:
	// 	return Errors(key, val)
	// case fmt.Stringer:
	// 	return Stringer(key, val)
	default:
		return Reflect(key, val)
	}
}

// ConstructClaimsFromSlice takes a slice of `Claim`s and returns a prepared `jwt.Claims` pointer, or an error if construction failed.
func ConstructClaimsFromSlice(claims ...Claim) (*jwt.Claims, error) {
	tokenClaims := &jwt.Claims{
		Registered: jwt.Registered{},
		Set:        map[string]interface{}{},
	}
	for _, claim := range claims {
		if claim.IsRegistered() {
			err := constructRegisteredClaim(tokenClaims, claim)
			if err != nil {
				return nil, err
			}
		} else {
			err := constructUnregisteredClaim(tokenClaims, claim)
			if err != nil {
				return nil, err
			}
		}
	}
	if tokenClaims.ID == "" {
		tokenClaims.ID = uuid.NewV4().String()
	}
	return tokenClaims, nil
}

// constructRegisteredClaim adds IANA registered `Claim` fields to the supplied `jwt.Claims`
func constructRegisteredClaim(tokenClaims *jwt.Claims, claim Claim) error {
	switch claim.Field() {
	case Issuer:
		tokenClaims.Registered.Issuer = claim.String
	case Subject:
		tokenClaims.Registered.Subject = claim.String
	case Audience:
		tokenClaims.Registered.Audience = claim.String
	case Expires:
		if claim.Type == TimeType {
			t, err := claim.Time()
			if err != nil {
				return err
			}
			tokenClaims.Registered.Expires = jwt.NewNumericTime(t)
		} else {
			return errors.New("invalid type for exp")
		}
	case NotBefore:
		if claim.Type == TimeType {
			t, err := claim.Time()
			if err != nil {
				return err
			}
			tokenClaims.Registered.NotBefore = jwt.NewNumericTime(t)
		} else {
			return errors.New("invalid type for nbf")
		}
	case Issued:
		if claim.Type == TimeType {
			t, err := claim.Time()
			if err != nil {
				return err
			}
			tokenClaims.Registered.Issued = jwt.NewNumericTime(t)
		} else {
			return errors.New("invalid type for iat")
		}
	case ID:
		tokenClaims.Registered.ID = claim.String
	}

	return nil
}

// constructRegisteredClaim adds unregistered `Claim` fields to the supplied `jwt.Claims`
func constructUnregisteredClaim(tokenClaims *jwt.Claims, claim Claim) error {
	switch claim.Type {
	// case Int8Type, Int16Type, Int32Type, Int64Type:
	// 	tokenClaims.Set[claim.Key] = claim.Interface.(int64)
	// case Uint8Type, Uint16Type, Uint32Type, Uint64Type:
	// 	tokenClaims.Set[claim.Key] = claim.Interface.(uint64)
	// case Float32Type, Float64Type:
	// 	tokenClaims.Set[claim.Key] = claim.Float
	// TODO Find a way around the pascaldekloe/jwt package decoding json numbers as float64 (standard encoding/json Unmarshaling)
	case Int8Type, Int16Type, Int32Type, Int64Type, Uint8Type, Uint16Type, Uint32Type, Uint64Type, Float32Type, Float64Type:
		tokenClaims.Set[claim.Key] = claim.Float
	case StringType:
		tokenClaims.Set[claim.Key] = claim.String
	case BoolType:
		if b, ok := claim.Interface.(bool); ok {
			tokenClaims.Set[claim.Key] = b
		} else {
			return fmt.Errorf("bool claim type format incorrect: %s", claim.Key)
		}
	case TimeType:
		t, err := claim.Time()
		if err != nil {
			return err
		}
		tokenClaims.Set[claim.Key] = jwt.NewNumericTime(t)
	default:
		return fmt.Errorf("Unsupported Claim Type: %d", claim.Type)
	}

	return nil
}
