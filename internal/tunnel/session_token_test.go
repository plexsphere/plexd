package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// staticKeys is a SigningKeySource holding a fixed key set.
type staticKeys []ed25519.PublicKey

func (k staticKeys) TrustedKeys(time.Time) []ed25519.PublicKey { return k }

func newSigningKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

// mintSessionToken signs header and claims as a compact JWS, the way the
// control plane issues a session token.
func mintSessionToken(t testing.TB, priv ed25519.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signingInput := enc(header) + "." + enc(claims)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(signingInput)))
}

func sessionTokenHeaderFields() map[string]any {
	return map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "signer-kid"}
}

// validSSHClaims builds the claims of a token for one ssh session and user,
// valid from a minute before now for ten minutes.
func validSSHClaims(sessionID, user string, now time.Time) map[string]any {
	return map[string]any{
		"iss":    "plexsphere://domain/test",
		"aud":    "resource://test",
		"sub":    "identity://test",
		"jti":    sessionID,
		"kind":   "ssh",
		"target": map[string]any{"kind": "ssh", "user": user},
		"iat":    now.Add(-time.Minute).Unix(),
		"nbf":    now.Add(-time.Minute).Unix(),
		"exp":    now.Add(10 * time.Minute).Unix(),
	}
}

func TestVerifySessionToken_Valid(t *testing.T) {
	pub, priv := newSigningKey(t)
	now := time.Now()

	t.Run("without allowed commands", func(t *testing.T) {
		token := mintSessionToken(t, priv, sessionTokenHeaderFields(), validSSHClaims("sess-1", "ubuntu", now))
		claims, err := VerifySessionToken(token, []ed25519.PublicKey{pub}, "sess-1", "ubuntu", now)
		if err != nil {
			t.Fatalf("VerifySessionToken() error: %v", err)
		}
		if claims.SessionID != "sess-1" || claims.User != "ubuntu" {
			t.Errorf("claims = %+v, want session sess-1 and user ubuntu", claims)
		}
		if len(claims.AllowedCommands) != 0 {
			t.Errorf("AllowedCommands = %q, want empty", claims.AllowedCommands)
		}
		if want := now.Add(10 * time.Minute).Unix(); claims.Expiry.Unix() != want {
			t.Errorf("Expiry = %d, want %d", claims.Expiry.Unix(), want)
		}
		if want := now.Add(-time.Minute).Unix(); claims.NotBefore.Unix() != want {
			t.Errorf("NotBefore = %d, want %d", claims.NotBefore.Unix(), want)
		}
	})

	t.Run("with allowed commands", func(t *testing.T) {
		claimSet := validSSHClaims("sess-1", "ubuntu", now)
		claimSet["target"] = map[string]any{"kind": "ssh", "user": "ubuntu", "allowed_commands": []string{"uptime", "df -h"}}
		token := mintSessionToken(t, priv, sessionTokenHeaderFields(), claimSet)
		claims, err := VerifySessionToken(token, []ed25519.PublicKey{pub}, "sess-1", "ubuntu", now)
		if err != nil {
			t.Fatalf("VerifySessionToken() error: %v", err)
		}
		if got := strings.Join(claims.AllowedCommands, "|"); got != "uptime|df -h" {
			t.Errorf("AllowedCommands = %q, want [uptime df -h]", claims.AllowedCommands)
		}
	})

	// RFC 7519 NumericDates may carry a fraction, and a signer may write them
	// in exponent form.
	t.Run("fractional and exponent NumericDates", func(t *testing.T) {
		nbf := time.Unix(now.Add(-time.Minute).Unix(), 500_000_000)
		exp := time.Unix(now.Add(10*time.Minute).Unix(), 250_000_000)
		claimSet := validSSHClaims("sess-1", "ubuntu", now)
		claimSet["nbf"] = float64(nbf.Unix()) + 0.5
		claimSet["exp"] = json.Number(strconv.FormatFloat(float64(exp.Unix())+0.25, 'e', -1, 64))
		token := mintSessionToken(t, priv, sessionTokenHeaderFields(), claimSet)
		claims, err := VerifySessionToken(token, []ed25519.PublicKey{pub}, "sess-1", "ubuntu", now)
		if err != nil {
			t.Fatalf("VerifySessionToken() error: %v", err)
		}
		if !claims.NotBefore.Equal(nbf) || !claims.Expiry.Equal(exp) {
			t.Errorf("NotBefore = %v, Expiry = %v, want %v and %v", claims.NotBefore, claims.Expiry, nbf, exp)
		}
	})
}

func TestVerifySessionToken_RotationGrace(t *testing.T) {
	oldPub, oldPriv := newSigningKey(t)
	newPub, _ := newSigningKey(t)
	now := time.Now()

	v := api.NewEd25519Verifier("kid-old", oldPub)
	transition := now.Add(time.Hour)
	if err := v.Rotate(api.SigningKeyRotation{
		KeyID:             "kid-new",
		PublicKey:         base64.StdEncoding.EncodeToString(newPub),
		PreviousKeyID:     "kid-old",
		TransitionExpires: transition,
	}); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	token := mintSessionToken(t, oldPriv, sessionTokenHeaderFields(), validSSHClaims("sess-rot", "ubuntu", now))
	if _, err := VerifySessionToken(token, v.TrustedKeys(now), "sess-rot", "ubuntu", now); err != nil {
		t.Errorf("a token signed with the previous key inside the grace window: %v", err)
	}
	if _, err := VerifySessionToken(token, v.TrustedKeys(transition), "sess-rot", "ubuntu", now); !errors.Is(err, ErrSessionTokenSignature) {
		t.Errorf("a token signed with the previous key after the window: error = %v, want ErrSessionTokenSignature", err)
	}
}

func TestVerifySessionToken_Malformed(t *testing.T) {
	pub, priv := newSigningKey(t)
	now := time.Now()
	valid := mintSessionToken(t, priv, sessionTokenHeaderFields(), validSSHClaims("sess-1", "ubuntu", now))
	parts := strings.Split(valid, ".")
	notJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	null := base64.RawURLEncoding.EncodeToString([]byte("null"))
	oversized := valid + "." + strings.Repeat("A", 8192-len(valid))
	if len(oversized) != 8193 {
		t.Fatalf("oversized fixture is %d bytes, want 8193", len(oversized))
	}

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"two segments", parts[0] + "." + parts[1]},
		{"four segments", valid + "." + parts[2]},
		{"empty segment", parts[0] + ".." + parts[2]},
		{"segment that is not base64url", parts[0] + ".!!!." + parts[2]},
		{"padded segment", parts[0] + "." + parts[1] + "=." + parts[2]},
		{"segment with a newline", parts[0] + "." + parts[1][:4] + "\n" + parts[1][4:] + "." + parts[2]},
		{"claims that are not JSON", parts[0] + "." + notJSON + "." + parts[2]},
		{"claims that are null", parts[0] + "." + null + "." + parts[2]},
		{"8193 bytes", oversized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifySessionToken(tc.token, []ed25519.PublicKey{pub}, "sess-1", "ubuntu", now)
			if !errors.Is(err, ErrSessionTokenMalformed) {
				t.Errorf("error = %v, want ErrSessionTokenMalformed", err)
			}
		})
	}
}

func TestVerifySessionToken_NoKeys(t *testing.T) {
	_, priv := newSigningKey(t)
	now := time.Now()
	token := mintSessionToken(t, priv, sessionTokenHeaderFields(), validSSHClaims("sess-1", "ubuntu", now))

	for name, keys := range map[string][]ed25519.PublicKey{
		"nil":              nil,
		"empty":            {},
		"wrong key length": {ed25519.PublicKey{1, 2, 3}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifySessionToken(token, keys, "sess-1", "ubuntu", now); !errors.Is(err, ErrSessionTokenSignature) {
				t.Errorf("error = %v, want ErrSessionTokenSignature", err)
			}
		})
	}
}

func TestVerifySessionToken_Refusals(t *testing.T) {
	pub, priv := newSigningKey(t)
	_, otherPriv := newSigningKey(t)
	now := time.Now()

	with := func(mutate func(h, c map[string]any)) (map[string]any, map[string]any) {
		h, c := sessionTokenHeaderFields(), validSSHClaims("sess-1", "ubuntu", now)
		mutate(h, c)
		return h, c
	}

	for _, tc := range []struct {
		name   string
		signer ed25519.PrivateKey
		mutate func(h, c map[string]any)
		want   error
	}{
		{"alg none", priv, func(h, _ map[string]any) { h["alg"] = "none" }, ErrSessionTokenAlgorithm},
		{"alg HS256", priv, func(h, _ map[string]any) { h["alg"] = "HS256" }, ErrSessionTokenAlgorithm},
		{"signed by another key", otherPriv, func(_, _ map[string]any) {}, ErrSessionTokenSignature},
		{"kind tcp", priv, func(_, c map[string]any) { c["kind"] = "tcp" }, ErrSessionTokenKind},
		{"target kind tcp", priv, func(_, c map[string]any) {
			c["target"] = map[string]any{"kind": "tcp", "user": "ubuntu"}
		}, ErrSessionTokenKind},
		{"another jti", priv, func(_, c map[string]any) { c["jti"] = "sess-2" }, ErrSessionTokenSession},
		{"nbf in the future", priv, func(_, c map[string]any) { c["nbf"] = now.Add(60 * time.Second).Unix() }, ErrSessionTokenNotYetValid},
		{"nbf half a second ahead", priv, func(_, c map[string]any) { c["nbf"] = unixSeconds(now) + 0.5 }, ErrSessionTokenNotYetValid},
		{"exp equal to now", priv, func(_, c map[string]any) { c["exp"] = now.Unix() }, ErrSessionTokenExpired},
		{"exp half a second ago", priv, func(_, c map[string]any) { c["exp"] = unixSeconds(now) - 0.5 }, ErrSessionTokenExpired},
		{"no exp", priv, func(_, c map[string]any) { delete(c, "exp") }, ErrSessionTokenExpired},
		{"exp beyond an int64 of seconds", priv, func(_, c map[string]any) { c["exp"] = json.Number("1e19") }, ErrSessionTokenMalformed},
		// time.Unix would overflow on this and make the token valid since the
		// year -292 billion.
		{"nbf just below 2^63 seconds", priv, func(_, c map[string]any) { c["nbf"] = json.Number("9223372036854775000") }, ErrSessionTokenMalformed},
		{"nbf as a string", priv, func(_, c map[string]any) { c["nbf"] = "0" }, ErrSessionTokenMalformed},
		{"another target user", priv, func(_, c map[string]any) {
			c["target"] = map[string]any{"kind": "ssh", "user": "root"}
		}, ErrSessionTokenUser},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, c := with(tc.mutate)
			token := mintSessionToken(t, tc.signer, h, c)
			_, err := VerifySessionToken(token, []ed25519.PublicKey{pub}, "sess-1", "ubuntu", now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), strings.Split(token, ".")[2]) {
				t.Errorf("error %q carries the token", err)
			}
		})
	}

	// Checked in order: a token that fails the signature and the kind reports
	// the signature, the earlier check.
	h, c := with(func(_, c map[string]any) { c["kind"] = "tcp" })
	if _, err := VerifySessionToken(mintSessionToken(t, otherPriv, h, c), []ed25519.PublicKey{pub}, "sess-1", "ubuntu", now); !errors.Is(err, ErrSessionTokenSignature) {
		t.Errorf("error = %v, want the signature check to come first", err)
	}
}

// unixSeconds is t as fractional seconds since the epoch.
func unixSeconds(t time.Time) float64 {
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}

func TestParseSessionSigningPublicKey(t *testing.T) {
	pub, _ := newSigningKey(t)

	got, err := ParseSessionSigningPublicKey("  " + base64.StdEncoding.EncodeToString(pub) + "\n")
	if err != nil {
		t.Fatalf("ParseSessionSigningPublicKey() error: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("parsed key differs from the encoded one")
	}

	for _, tc := range []struct {
		name, in, wantPrefix string
	}{
		{"not base64", "not base64!", "tunnel: session signing key: not standard base64: "},
		{"31 bytes", base64.StdEncoding.EncodeToString(pub[:31]), "tunnel: session signing key: decodes to 31 bytes, want 32"},
		{"empty", "", "tunnel: session signing key: decodes to 0 bytes, want 32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSessionSigningPublicKey(tc.in)
			if err == nil || !strings.HasPrefix(err.Error(), tc.wantPrefix) {
				t.Errorf("error = %v, want prefix %q", err, tc.wantPrefix)
			}
		})
	}
}

// FuzzVerifySessionToken holds the verifier to its contract on arbitrary
// input: it never panics, it refuses with one of its sentinels, and the
// refusal never echoes the input.
func FuzzVerifySessionToken(f *testing.F) {
	pub, priv := newSigningKey(f)
	now := time.Now()
	valid := mintSessionToken(f, priv, sessionTokenHeaderFields(), validSSHClaims("sess-1", "ubuntu", now))
	f.Add(valid)
	f.Add("")
	f.Add("a.b")
	f.Add("a..c")
	f.Add("e30.e30.AA")
	f.Add("bnVsbA.bnVsbA.AA")

	sentinels := []error{
		ErrSessionTokenMalformed, ErrSessionTokenAlgorithm, ErrSessionTokenSignature,
		ErrSessionTokenKind, ErrSessionTokenSession, ErrSessionTokenNotYetValid,
		ErrSessionTokenExpired, ErrSessionTokenUser,
	}
	f.Fuzz(func(t *testing.T, token string) {
		_, err := VerifySessionToken(token, []ed25519.PublicKey{pub}, "sess-1", "ubuntu", now)
		if err == nil {
			return
		}
		known := false
		for _, s := range sentinels {
			if err == s {
				known = true
				break
			}
		}
		if !known {
			t.Fatalf("error %v is not one of the sentinels", err)
		}
		if len(token) >= 8 && strings.Contains(err.Error(), token) {
			t.Fatalf("error %q echoes the input", err)
		}
	})
}
