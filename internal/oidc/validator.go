package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

var ErrInvalidToken = errors.New("the OIDC token is not valid")

type Policy struct {
	ID                string              `json:"id"`
	Issuer            string              `json:"issuer"`
	JWKSURL           string              `json:"jwksUrl"`
	Audiences         []string            `json:"audiences"`
	Algorithms        []string            `json:"algorithms"`
	MaxTokenAge       time.Duration       `json:"-"`
	MaxTokenAgeText   string              `json:"maxTokenAge"`
	RequiredClaims    map[string]string   `json:"requiredClaims"`
	OneOfClaims       map[string][]string `json:"oneOfClaims"`
	ProjectIDClaim    string              `json:"projectIdClaim"`
	EnvironmentClaim  string              `json:"environmentClaim"`
	ReplayClaim       string              `json:"replayClaim"`
	RepositoryIDClaim string              `json:"repositoryIdClaim"`
	RepositoryClaim   string              `json:"repositoryClaim"`
	WorkflowRefClaim  string              `json:"workflowRefClaim"`
	WorkflowSHAClaim  string              `json:"workflowShaClaim"`
	RunIDClaim        string              `json:"runIdClaim"`
	RunAttemptClaim   string              `json:"runAttemptClaim"`
}

type Request struct {
	ProjectID       string
	EnvironmentName string
}

type Identity struct {
	ProviderID   string
	JTI          string
	ExpiresAt    time.Time
	RepositoryID string
	Repository   string
	WorkflowRef  string
	WorkflowSHA  string
	RunID        string
	RunAttempt   string
	Claims       map[string]any
}

type Validator struct {
	policies map[string]Policy
	client   *http.Client
	now      func() time.Time
	skew     time.Duration
	mu       sync.Mutex
	keys     map[string]cachedKeys
	fetch    singleflight.Group
}

type cachedKeys struct {
	byID      map[string]*rsa.PublicKey
	expiresAt time.Time
	fetchedAt time.Time
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KID string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func New(policies []Policy, client *http.Client) (*Validator, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	validator := &Validator{policies: make(map[string]Policy, len(policies)), client: client, now: time.Now, skew: 30 * time.Second, keys: make(map[string]cachedKeys)}
	for _, policy := range policies {
		if policy.ID == "" || policy.Issuer == "" || policy.JWKSURL == "" || len(policy.Audiences) == 0 {
			return nil, errors.New("OIDC policy id, issuer, JWKS URL, and audience are required")
		}
		parsedJWKS, err := url.Parse(policy.JWKSURL)
		if err != nil || parsedJWKS.Scheme != "https" || parsedJWKS.Host == "" {
			return nil, fmt.Errorf("OIDC policy %q requires an absolute HTTPS JWKS URL", policy.ID)
		}
		if len(policy.Algorithms) == 0 {
			policy.Algorithms = []string{"RS256"}
		}
		for _, algorithm := range policy.Algorithms {
			if algorithm != "RS256" {
				return nil, fmt.Errorf("OIDC policy %q uses unsupported algorithm %q", policy.ID, algorithm)
			}
		}
		if policy.MaxTokenAge == 0 {
			var err error
			policy.MaxTokenAge, err = time.ParseDuration(policy.MaxTokenAgeText)
			if err != nil || policy.MaxTokenAge <= 0 {
				return nil, fmt.Errorf("OIDC policy %q maxTokenAge is not valid", policy.ID)
			}
		}
		if policy.ReplayClaim == "" {
			policy.ReplayClaim = "jti"
		}
		if policy.ProjectIDClaim == "" || policy.EnvironmentClaim == "" {
			return nil, fmt.Errorf("OIDC policy %q requires project and environment binding claims", policy.ID)
		}
		if _, exists := validator.policies[policy.ID]; exists {
			return nil, fmt.Errorf("OIDC policy id %q occurs more than once", policy.ID)
		}
		validator.policies[policy.ID] = policy
	}
	return validator, nil
}

func (v *Validator) Validate(ctx context.Context, providerID, raw string, request Request) (Identity, error) {
	if request.ProjectID == "" || request.EnvironmentName == "" {
		return Identity{}, invalid("request_binding", errors.New("project id and environment name are required"))
	}
	policy, ok := v.policies[providerID]
	if !ok {
		return Identity{}, invalid("provider", errors.New("unknown OIDC provider"))
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > 32*1024 {
		return Identity{}, invalid("format", nil)
	}
	headerPayload, err := decodeJSON(parts[0])
	if err != nil {
		return Identity{}, invalid("header", err)
	}
	algorithm, _ := headerPayload["alg"].(string)
	kid, _ := headerPayload["kid"].(string)
	if kid == "" || !slices.Contains(policy.Algorithms, algorithm) {
		return Identity{}, invalid("algorithm", nil)
	}
	key, err := v.key(ctx, policy, kid, false)
	if errors.Is(err, errUnknownKey) {
		key, err = v.key(ctx, policy, kid, true)
	}
	if err != nil {
		return Identity{}, invalid("jwks", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Identity{}, invalid("signature", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return Identity{}, invalid("signature", err)
	}
	claims, err := decodeJSON(parts[1])
	if err != nil {
		return Identity{}, invalid("claims", err)
	}
	now := v.now().UTC()
	issuer, _ := claims["iss"].(string)
	if issuer != policy.Issuer || !matchesAudience(claims["aud"], policy.Audiences) {
		return Identity{}, invalid("issuer_or_audience", nil)
	}
	expiresAt, ok := numericTime(claims["exp"])
	if !ok || !expiresAt.After(now.Add(-v.skew)) {
		return Identity{}, invalid("expired", nil)
	}
	issuedAt, ok := numericTime(claims["iat"])
	if !ok || issuedAt.After(now.Add(v.skew)) || now.Sub(issuedAt) > policy.MaxTokenAge+v.skew {
		return Identity{}, invalid("issued_at", nil)
	}
	if rawNBF, exists := claims["nbf"]; exists {
		notBefore, ok := numericTime(rawNBF)
		if !ok || notBefore.After(now.Add(v.skew)) {
			return Identity{}, invalid("not_before", nil)
		}
	}
	for claim, expected := range policy.RequiredClaims {
		if value, _ := claims[claim].(string); value != expected {
			return Identity{}, invalid("required_claim", fmt.Errorf("claim %q does not match", claim))
		}
	}
	for claim, allowed := range policy.OneOfClaims {
		value, _ := claims[claim].(string)
		if !slices.Contains(allowed, value) {
			return Identity{}, invalid("allowed_claim", fmt.Errorf("claim %q is not allowed", claim))
		}
	}
	if value, _ := claims[policy.ProjectIDClaim].(string); value == "" || value != request.ProjectID {
		return Identity{}, invalid("project_binding", nil)
	}
	if value, _ := claims[policy.EnvironmentClaim].(string); value == "" || value != request.EnvironmentName {
		return Identity{}, invalid("environment_binding", nil)
	}
	jti, _ := claims[policy.ReplayClaim].(string)
	if jti == "" {
		return Identity{}, invalid("replay_claim", nil)
	}
	identity := Identity{
		ProviderID:   policy.ID,
		JTI:          jti,
		ExpiresAt:    expiresAt,
		RepositoryID: stringClaim(claims, policy.RepositoryIDClaim),
		Repository:   stringClaim(claims, policy.RepositoryClaim),
		WorkflowRef:  stringClaim(claims, policy.WorkflowRefClaim),
		WorkflowSHA:  stringClaim(claims, policy.WorkflowSHAClaim),
		RunID:        stringClaim(claims, policy.RunIDClaim),
		RunAttempt:   stringClaim(claims, policy.RunAttemptClaim),
		Claims:       claims,
	}
	if identity.RepositoryID == "" || identity.WorkflowRef == "" || identity.WorkflowSHA == "" || identity.RunID == "" || identity.RunAttempt == "" {
		return Identity{}, invalid("audit_claim", nil)
	}
	if !workflowSHAMatches(identity.WorkflowRef, identity.WorkflowSHA) {
		return Identity{}, invalid("workflow_sha", nil)
	}
	return identity, nil
}

var errUnknownKey = errors.New("the OIDC key id is unknown")

func (v *Validator) key(ctx context.Context, policy Policy, kid string, force bool) (*rsa.PublicKey, error) {
	v.mu.Lock()
	now := v.now().UTC()
	cached := v.keys[policy.ID]
	if cached.byID != nil && cached.expiresAt.After(now) && !force {
		if key := cached.byID[kid]; key != nil {
			v.mu.Unlock()
			return key, nil
		}
		v.mu.Unlock()
		return nil, errUnknownKey
	}
	if force && !cached.fetchedAt.IsZero() && now.Sub(cached.fetchedAt) < time.Minute {
		v.mu.Unlock()
		return nil, errUnknownKey
	}
	v.mu.Unlock()
	value, err, _ := v.fetch.Do(policy.ID, func() (any, error) {
		return v.fetchKeys(ctx, policy)
	})
	if err != nil {
		return nil, err
	}
	cached = value.(cachedKeys)
	v.mu.Lock()
	v.keys[policy.ID] = cached
	v.mu.Unlock()
	if key := cached.byID[kid]; key != nil {
		return key, nil
	}
	return nil, errUnknownKey
}

func (v *Validator) fetchKeys(ctx context.Context, policy Policy) (cachedKeys, error) {
	now := v.now().UTC()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, policy.JWKSURL, nil)
	if err != nil {
		return cachedKeys{}, err
	}
	response, err := v.client.Do(request)
	if err != nil {
		return cachedKeys{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return cachedKeys{}, fmt.Errorf("JWKS endpoint returned %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 256*1024))
	var document jwksDocument
	if err := decoder.Decode(&document); err != nil {
		return cachedKeys{}, err
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, candidate := range document.Keys {
		if candidate.KID == "" || candidate.Kty != "RSA" || candidate.Use != "sig" || candidate.Alg != "RS256" {
			continue
		}
		key, err := rsaKey(candidate)
		if err != nil {
			continue
		}
		keys[candidate.KID] = key
	}
	maxAge := cacheMaxAge(response.Header.Get("Cache-Control"))
	if maxAge <= 0 || maxAge > time.Hour {
		maxAge = time.Hour
	}
	return cachedKeys{byID: keys, expiresAt: now.Add(maxAge), fetchedAt: now}, nil
}

func rsaKey(value jwk) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(value.N)
	if err != nil || len(modulus) < 256 {
		return nil, errors.New("RSA modulus is not valid")
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(value.E)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return nil, errors.New("RSA exponent is not valid")
	}
	exponent := 0
	for _, part := range exponentBytes {
		exponent = exponent<<8 | int(part)
	}
	if exponent < 3 {
		return nil, errors.New("RSA exponent is too small")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
}

func decodeJSON(value string) (map[string]any, error) {
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("JSON object is missing")
	}
	return result, nil
}

func numericTime(value any) (time.Time, bool) {
	var seconds int64
	switch candidate := value.(type) {
	case json.Number:
		parsed, err := candidate.Int64()
		if err != nil {
			return time.Time{}, false
		}
		seconds = parsed
	case float64:
		seconds = int64(candidate)
	default:
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}

func matchesAudience(value any, allowed []string) bool {
	switch candidate := value.(type) {
	case string:
		return slices.Contains(allowed, candidate)
	case []any:
		for _, item := range candidate {
			if text, ok := item.(string); ok && slices.Contains(allowed, text) {
				return true
			}
		}
	}
	return false
}

func stringClaim(claims map[string]any, name string) string {
	if name == "" {
		return ""
	}
	switch value := claims[name].(type) {
	case string:
		return value
	case json.Number:
		return value.String()
	default:
		return ""
	}
}

func workflowSHAMatches(reference, sha string) bool {
	separator := strings.LastIndexByte(reference, '@')
	return len(sha) == 40 && separator >= 0 && reference[separator+1:] == sha
}

func cacheMaxAge(header string) time.Duration {
	for _, directive := range strings.Split(header, ",") {
		key, raw, found := strings.Cut(strings.TrimSpace(directive), "=")
		if found && strings.EqualFold(key, "max-age") {
			seconds, err := strconv.ParseInt(strings.Trim(raw, `"`), 10, 64)
			if err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return 0
}

func invalid(code string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", ErrInvalidToken, code)
	}
	return fmt.Errorf("%w: %s: %v", ErrInvalidToken, code, err)
}
