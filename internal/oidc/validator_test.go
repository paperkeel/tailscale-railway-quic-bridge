package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidateGenericPolicy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var jwksRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		jwksRequests.Add(1)
		response.Header().Set("Cache-Control", "max-age=60")
		_ = json.NewEncoder(response).Encode(map[string]any{"keys": []map[string]string{{"kid": "test", "kty": "RSA", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer server.Close()
	sha := fmt.Sprintf("%040d", 1)
	policy := Policy{ID: "github", Issuer: "https://issuer.example", JWKSURL: server.URL, Audiences: []string{"tailbridge-enrollment"}, MaxTokenAge: 5 * time.Minute, ProjectIDClaim: "repo_property_project", EnvironmentClaim: "environment", RepositoryIDClaim: "repository_id", RepositoryClaim: "repository", WorkflowRefClaim: "job_workflow_ref", WorkflowSHAClaim: "job_workflow_sha", RunIDClaim: "run_id", RunAttemptClaim: "run_attempt", RequiredClaims: map[string]string{"repository_owner_id": "123"}, OneOfClaims: map[string][]string{"job_workflow_ref": {"org/workflows/.github/workflows/enroll.yml@" + sha}}}
	validator, err := New([]Policy{policy}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	validator.now = func() time.Time { return now }
	claims := map[string]any{"iss": policy.Issuer, "aud": policy.Audiences[0], "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "jti": "unique", "repo_property_project": "railway-project", "environment": "preview-1", "repository_owner_id": "123", "repository_id": "456", "repository": "org/repo", "job_workflow_ref": "org/workflows/.github/workflows/enroll.yml@" + sha, "job_workflow_sha": sha, "run_id": "10", "run_attempt": "1"}
	token := signedToken(t, key, claims)
	identity, err := validator.Validate(context.Background(), "github", token, Request{ProjectID: "railway-project", EnvironmentName: "preview-1"})
	if err != nil || identity.RepositoryID != "456" || identity.JTI != "unique" {
		t.Fatalf("Validate() = %#v, %v", identity, err)
	}
	claims["repo_property_project"] = "other"
	if _, err := validator.Validate(context.Background(), "github", signedToken(t, key, claims), Request{ProjectID: "railway-project", EnvironmentName: "preview-1"}); err == nil {
		t.Fatal("Validate() accepted the wrong project binding")
	}
	claims["repo_property_project"] = "railway-project"
	claims["iat"] = now.Add(-10 * time.Minute).Unix()
	if _, err := validator.Validate(context.Background(), "github", signedToken(t, key, claims), Request{ProjectID: "railway-project", EnvironmentName: "preview-1"}); err == nil {
		t.Fatal("Validate() accepted an old token")
	}
	claims["iat"] = now.Unix()
	claims["aud"] = []any{"another", policy.Audiences[0]}
	if _, err := validator.Validate(context.Background(), "github", signedToken(t, key, claims), Request{ProjectID: "railway-project", EnvironmentName: "preview-1"}); err != nil {
		t.Fatalf("Validate() rejected an audience list: %v", err)
	}
	invalidCases := []struct {
		name  string
		claim string
		value any
	}{
		{name: "issuer", claim: "iss", value: "other"},
		{name: "audience", claim: "aud", value: "other"},
		{name: "expiry", claim: "exp", value: now.Add(-time.Minute).Unix()},
		{name: "not before", claim: "nbf", value: now.Add(time.Minute).Unix()},
		{name: "replay identity", claim: "jti", value: ""},
		{name: "owner", claim: "repository_owner_id", value: "other"},
		{name: "workflow", claim: "job_workflow_ref", value: "other"},
		{name: "environment", claim: "environment", value: "other"},
		{name: "workflow sha", claim: "job_workflow_sha", value: strings.Repeat("b", 40)},
		{name: "audit claim", claim: "run_id", value: ""},
	}
	claims["aud"] = policy.Audiences[0]
	for _, test := range invalidCases {
		t.Run(test.name, func(t *testing.T) {
			original := claims[test.claim]
			claims[test.claim] = test.value
			defer func() { claims[test.claim] = original }()
			if _, err := validator.Validate(context.Background(), "github", signedToken(t, key, claims), Request{ProjectID: "railway-project", EnvironmentName: "preview-1"}); err == nil {
				t.Fatalf("Validate() accepted invalid claim %q", test.claim)
			}
		})
	}
	if _, err := validator.Validate(context.Background(), "unknown", token, Request{}); err == nil {
		t.Fatal("Validate() accepted an unknown provider")
	}
	if _, err := validator.Validate(context.Background(), "github", "invalid", Request{}); err == nil {
		t.Fatal("Validate() accepted an invalid token")
	}
	for range 2 {
		if _, err := validator.Validate(context.Background(), "github", signedTokenWithKID(t, key, claims, "unknown"), Request{ProjectID: "railway-project", EnvironmentName: "preview-1"}); err == nil {
			t.Fatal("Validate() accepted an unknown signing key")
		}
	}
	if requests := jwksRequests.Load(); requests != 1 {
		t.Fatalf("unknown key ids caused %d JWKS requests, want 1", requests)
	}
}

func TestNewRejectsUnsafePolicies(t *testing.T) {
	if _, err := New([]Policy{{ID: "test", Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/jwks", Audiences: []string{"audience"}, Algorithms: []string{"none"}, MaxTokenAge: time.Minute}}, nil); err == nil {
		t.Fatal("New() accepted an unsupported algorithm")
	}
	if _, err := New([]Policy{{ID: "test", Issuer: "https://issuer.example", JWKSURL: "http://issuer.example/jwks", Audiences: []string{"audience"}, MaxTokenAge: time.Minute, ProjectIDClaim: "project", EnvironmentClaim: "environment"}}, nil); err == nil {
		t.Fatal("New() accepted an insecure JWKS URL")
	}
}

func TestOIDCHelpers(t *testing.T) {
	if _, ok := numericTime("invalid"); ok {
		t.Fatal("numericTime() accepted text")
	}
	if value, ok := numericTime(float64(10)); !ok || value.Unix() != 10 {
		t.Fatalf("numericTime() = %v, %v", value, ok)
	}
	if matchesAudience([]any{"one", "two"}, []string{"three"}) || matchesAudience(42, []string{"42"}) {
		t.Fatal("matchesAudience() accepted an unrelated audience")
	}
	if got := stringClaim(map[string]any{"number": json.Number("12")}, "number"); got != "12" {
		t.Fatalf("stringClaim() = %q", got)
	}
	if got := cacheMaxAge(`public, max-age="60"`); got != time.Minute {
		t.Fatalf("cacheMaxAge() = %v", got)
	}
	if got := cacheMaxAge("invalid"); got != 0 {
		t.Fatalf("invalid cacheMaxAge() = %v", got)
	}
}

func signedToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	return signedTokenWithKID(t, key, claims, "test")
}

func signedTokenWithKID(t *testing.T, key *rsa.PrivateKey, claims map[string]any, kid string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}
