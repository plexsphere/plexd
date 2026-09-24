package tunnel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// SigningKeySource yields the keys a mediated session token may be signed with
// at a given instant. *api.Ed25519Verifier satisfies it, so plexd follows the
// control plane's signing-key rotations without a second copy of the keys.
type SigningKeySource interface {
	TrustedKeys(now time.Time) []ed25519.PublicKey
}

var _ SigningKeySource = (*api.Ed25519Verifier)(nil)

// SessionTokenClaims is what VerifySessionToken hands back from a token it
// accepted. AllowedCommands is empty when the token lists no commands, which
// means the session may run a shell or any command.
type SessionTokenClaims struct {
	SessionID       string
	User            string
	AllowedCommands []string
	NotBefore       time.Time
	Expiry          time.Time
}

// The reasons VerifySessionToken refuses a token. They are returned bare,
// never wrapped, so no decoder message and no byte of the token reaches an
// error text or a log line.
var (
	ErrSessionTokenMalformed   = errors.New("tunnel: session token: malformed")
	ErrSessionTokenAlgorithm   = errors.New("tunnel: session token: algorithm is not EdDSA")
	ErrSessionTokenSignature   = errors.New("tunnel: session token: signature does not verify against a trusted key")
	ErrSessionTokenKind        = errors.New("tunnel: session token: not an ssh session token")
	ErrSessionTokenSession     = errors.New("tunnel: session token: issued for another session")
	ErrSessionTokenNotYetValid = errors.New("tunnel: session token: not yet valid")
	ErrSessionTokenExpired     = errors.New("tunnel: session token: expired")
	ErrSessionTokenUser        = errors.New("tunnel: session token: issued for another user")
)

// maxSessionTokenBytes bounds the token before any decoding happens. A real
// token is a few hundred bytes; the bound keeps a hostile password from
// costing more than a small allocation.
const maxSessionTokenBytes = 8192

// sessionTokenHeader is the part of the JWS header the check reads. kid is
// deliberately absent: the key id registration hands out comes from
// PLEXSPHERE_SIGNING_KEY_ID, which is independent of the id the token signer
// stamps, and the contract binds the key, not its id.
type sessionTokenHeader struct {
	Alg string `json:"alg"`
}

// sessionTokenPayload is the part of the claims the check reads. iss, aud,
// sub and iat are not consulted: the contract binds the signing key and the
// session id, and the session id is unique per grant.
type sessionTokenPayload struct {
	JTI    string `json:"jti"`
	Kind   string `json:"kind"`
	Target struct {
		Kind            string   `json:"kind"`
		User            string   `json:"user"`
		AllowedCommands []string `json:"allowed_commands"`
	} `json:"target"`
	// nbf and exp are RFC 7519 NumericDates: JSON numbers of seconds, which
	// may carry a fraction.
	NotBefore float64 `json:"nbf"`
	Expiry    float64 `json:"exp"`
}

// VerifySessionToken checks a mediated ssh session token, the compact JWS the
// control plane issues for one session, and returns its claims. It checks, in
// this order, and returns the first failure:
//
//  1. the token is at most 8192 bytes of three non-empty, dot-separated,
//     raw-base64url segments whose header and claims are JSON objects, and
//     nbf and exp are less than 2^53 seconds either side of the epoch
//     (ErrSessionTokenMalformed);
//  2. the header's alg is EdDSA (ErrSessionTokenAlgorithm);
//  3. the signature verifies against one of keys; nil or empty keys verify
//     nothing (ErrSessionTokenSignature);
//  4. kind and target.kind are both "ssh" (ErrSessionTokenKind);
//  5. jti equals sessionID (ErrSessionTokenSession);
//  6. nbf <= now (ErrSessionTokenNotYetValid) and now < exp, where a missing
//     exp counts as expired (ErrSessionTokenExpired);
//  7. target.user equals user (ErrSessionTokenUser).
//
// There is no clock-skew leeway: the contract states none.
func VerifySessionToken(token string, keys []ed25519.PublicKey, sessionID, user string, now time.Time) (SessionTokenClaims, error) {
	if len(token) > maxSessionTokenBytes {
		return SessionTokenClaims{}, ErrSessionTokenMalformed
	}
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return SessionTokenClaims{}, ErrSessionTokenMalformed
	}
	var header sessionTokenHeader
	var payload sessionTokenPayload
	if !decodeTokenObject(segments[0], &header) || !decodeTokenObject(segments[1], &payload) {
		return SessionTokenClaims{}, ErrSessionTokenMalformed
	}
	nbf, nbfOK := numericDate(payload.NotBefore)
	exp, expOK := numericDate(payload.Expiry)
	if !nbfOK || !expOK {
		return SessionTokenClaims{}, ErrSessionTokenMalformed
	}
	sig, ok := decodeTokenSegment(segments[2])
	if !ok {
		return SessionTokenClaims{}, ErrSessionTokenMalformed
	}

	if header.Alg != "EdDSA" {
		return SessionTokenClaims{}, ErrSessionTokenAlgorithm
	}

	signingInput := []byte(segments[0] + "." + segments[1])
	verified := false
	for _, key := range keys {
		// ed25519.Verify panics on a key of the wrong length.
		if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, signingInput, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return SessionTokenClaims{}, ErrSessionTokenSignature
	}

	if payload.Kind != api.SessionKindSSH || payload.Target.Kind != api.SessionKindSSH {
		return SessionTokenClaims{}, ErrSessionTokenKind
	}
	if payload.JTI != sessionID {
		return SessionTokenClaims{}, ErrSessionTokenSession
	}
	if now.Before(nbf) {
		return SessionTokenClaims{}, ErrSessionTokenNotYetValid
	}
	if !now.Before(exp) {
		return SessionTokenClaims{}, ErrSessionTokenExpired
	}
	if payload.Target.User != user {
		return SessionTokenClaims{}, ErrSessionTokenUser
	}

	return SessionTokenClaims{
		SessionID:       payload.JTI,
		User:            payload.Target.User,
		AllowedCommands: payload.Target.AllowedCommands,
		NotBefore:       nbf,
		Expiry:          exp,
	}, nil
}

// maxNumericDate bounds a NumericDate to where a float64 holds whole seconds
// exactly and time.Unix, which adds its own epoch offset to the seconds in an
// int64, cannot overflow.
const maxNumericDate = 1 << 53

// numericDate converts a NumericDate to a time. ok is false for a value of
// maxNumericDate seconds or more either side of the epoch, which no real
// signer emits.
func numericDate(seconds float64) (t time.Time, ok bool) {
	if seconds <= -maxNumericDate || seconds >= maxNumericDate {
		return time.Time{}, false
	}
	whole, frac := math.Modf(seconds)
	return time.Unix(int64(whole), int64(frac*1e9)), true
}

// decodeTokenSegment decodes one raw-base64url segment. The alphabet is
// checked first because the base64 decoder skips CR and LF, and a segment is
// only well formed when every byte of it is part of the encoding.
func decodeTokenSegment(seg string) ([]byte, bool) {
	if seg == "" {
		return nil, false
	}
	for i := 0; i < len(seg); i++ {
		if !isRawURLByte(seg[i]) {
			return nil, false
		}
	}
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, false
	}
	return data, true
}

// isRawURLByte reports whether c belongs to the base64url alphabet.
func isRawURLByte(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_':
		return true
	default:
		return false
	}
}

// decodeTokenObject decodes a segment that must hold a JSON object into v. A
// literal null would unmarshal into v without an error, so the object is
// checked for explicitly.
func decodeTokenObject(seg string, v any) bool {
	data, ok := decodeTokenSegment(seg)
	if !ok || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return false
	}
	return json.Unmarshal(data, v) == nil
}

// ParseSessionSigningPublicKey parses the standard-base64 Ed25519 public key
// that tunnel.session_signing_public_key and the helper's pin file hold.
// Surrounding whitespace, a trailing newline included, is ignored.
func ParseSessionSigningPublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("tunnel: session signing key: not standard base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("tunnel: session signing key: decodes to %d bytes, want 32", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
