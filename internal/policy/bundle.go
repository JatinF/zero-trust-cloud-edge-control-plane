// Package policy signs and verifies immutable policy snapshots.
// The signature covers the canonical JSON bytes. OPA evaluates the Rego.
// OPA bundle signing and an external key service were not used.
package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
	"github.com/open-policy-agent/opa/v1/rego"
)

type Bundle struct {
	TenantID       string `json:"tenant_id"`
	PolicyID       string `json:"policy_id"`
	Revision       uint64 `json:"revision"`
	Risk           string `json:"risk"`
	NotBeforeUnix  int64  `json:"not_before_unix"`
	NotAfterUnix   int64  `json:"not_after_unix"`
	AccessRego     string `json:"access_rego"`
	PrivilegedRego string `json:"privileged_rego"`
	Rollback       bool   `json:"rollback"`
}

type Signed struct {
	Bundle    Bundle
	Payload   []byte
	Signature []byte
	Digest    string
}

type Signer struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func NewSigner() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{private: priv, public: pub}, nil
}

func (s *Signer) Public() ed25519.PublicKey {
	return s.public
}

func Canonical(b Bundle) ([]byte, error) {
	return json.Marshal(b)
}

func (s *Signer) Sign(b Bundle) (Signed, error) {
	if err := Validate(b.AccessRego, b.PrivilegedRego); err != nil {
		return Signed{}, err
	}
	payload, err := Canonical(b)
	if err != nil {
		return Signed{}, err
	}
	sum := sha256.Sum256(payload)
	return Signed{
		Bundle:    b,
		Payload:   payload,
		Signature: ed25519.Sign(s.private, payload),
		Digest:    hex.EncodeToString(sum[:]),
	}, nil
}

func Verify(pub ed25519.PublicKey, payload, signature []byte) (Bundle, error) {
	if len(signature) == 0 {
		return Bundle{}, apperr.New("signature_missing", "policy bundle has no signature", 422)
	}
	if !ed25519.Verify(pub, payload, signature) {
		return Bundle{}, apperr.New("signature_invalid", "policy bundle signature did not verify", 422)
	}
	var bundle Bundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return Bundle{}, apperr.New("policy_format", "policy bundle is not valid JSON", 422)
	}
	again, err := Canonical(bundle)
	if err != nil {
		return Bundle{}, err
	}
	if sha256.Sum256(payload) != sha256.Sum256(again) {
		return Bundle{}, apperr.New("policy_format", "policy bundle is not canonical", 422)
	}
	return bundle, nil
}

func Digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func SignatureText(sig []byte) string {
	return base64.StdEncoding.EncodeToString(sig)
}

// Validate compiles both modules and rejects a policy that allows an empty input.
func Validate(accessRego, privilegedRego string) error {
	if !strings.Contains(accessRego, "package zt.authz") {
		return apperr.New("policy_format", "access module package must be zt.authz", 422)
	}
	if !strings.Contains(privilegedRego, "package zt.privileged") {
		return apperr.New("policy_format", "privileged module package must be zt.privileged", 422)
	}
	if strings.Contains(accessRego, "default allow := true") || strings.Contains(privilegedRego, "default allow := true") {
		return apperr.New("policy_format", "default allow must be false", 422)
	}
	accessAllow, privAllow, err := Eval(context.Background(), accessRego, privilegedRego, map[string]any{})
	if err != nil {
		return apperr.New("policy_format", "policy did not compile", 422)
	}
	if accessAllow || privAllow {
		return apperr.New("policy_format", "empty input must be denied", 422)
	}
	return nil
}

func Eval(ctx context.Context, accessRego, privilegedRego string, input map[string]any) (bool, bool, error) {
	access, err := allow(ctx, "data.zt.authz.allow", "access.rego", accessRego, input)
	if err != nil {
		return false, false, err
	}
	priv, err := allow(ctx, "data.zt.privileged.allow", "privileged.rego", privilegedRego, input)
	if err != nil {
		return false, false, err
	}
	return access, priv, nil
}

func allow(ctx context.Context, query, name, module string, input map[string]any) (bool, error) {
	prepared, err := rego.New(
		rego.Query(query),
		rego.Module(name, module),
	).PrepareForEval(ctx)
	if err != nil {
		return false, err
	}
	results, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, err
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return false, nil
	}
	value, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, apperr.New("policy_format", "allow decision was not a boolean", 422)
	}
	return value, nil
}
