package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	goredis "github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/julienschmidt/httprouter"
)

// ManagementRevStore checks JWT revocation for Management API bearer tokens.
type ManagementRevStore interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
	RevokeJTI(ctx context.Context, jti string, duration time.Duration) error
}

// ManagementClientStore is the minimal store interface the Management API needs.
type ManagementClientStore interface {
	GetClientOrgID(ctx context.Context, clientID string) (*string, error)
	ListCustomClaims(ctx context.Context, clientID string) ([]postgres.ClaimDefinition, error)
	SetCustomClaimsAdmin(ctx context.Context, clientID string, defs []postgres.ClaimDefinition) error
	PatchCustomClaimAdmin(ctx context.Context, clientID string, def postgres.ClaimDefinition) error
}

// ManagementHandler serves the Management REST API (Bearer JWT, management audience).
type ManagementHandler struct {
	keyStore    *crypto.KeyStore
	revStore    ManagementRevStore
	clientStore ManagementClientStore
	mgmtAud     string // required aud claim value
	appURL      string // required iss claim value
	rdb         *goredis.Client
}

// WithTokenIndex enables blocklisting outstanding access tokens after claim updates.
func (h *ManagementHandler) WithTokenIndex(rdb *goredis.Client) *ManagementHandler {
	h.rdb = rdb
	return h
}

func NewManagementHandler(
	keyStore *crypto.KeyStore,
	revStore ManagementRevStore,
	clientStore ManagementClientStore,
	mgmtAud string,
) *ManagementHandler {
	return &ManagementHandler{
		keyStore:    keyStore,
		revStore:    revStore,
		clientStore: clientStore,
		mgmtAud:     mgmtAud,
	}
}

// WithIssuer sets the expected iss claim value for token validation.
func (h *ManagementHandler) WithIssuer(issuer string) *ManagementHandler {
	h.appURL = issuer
	return h
}

// managementClaimInput is the JSON shape accepted by PUT /api/v1/clients/:id/claims.
type managementClaimInput struct {
	Key          string `json:"key"`
	Type         string `json:"type"`
	Value        string `json:"value"`
	Destinations string `json:"destinations,omitempty"`
	ScopeGate    string `json:"scope_gate,omitempty"`
	SourceKind   string `json:"source_kind,omitempty"`
}

// managementClaimOutput is the JSON shape returned by GET /api/v1/clients/:id/claims.
// Uses "type" (not "value_type") so GET responses can be round-tripped directly as PUT inputs.
type managementClaimOutput struct {
	Key          string `json:"key"`
	Type         string `json:"type"`
	Value        string `json:"value"`
	Destinations string `json:"destinations"`
	ScopeGate    string `json:"scope_gate,omitempty"`
	SourceKind   string `json:"source_kind"`
}

// GetClientClaims handles GET /api/v1/clients/:id/claims.
func (h *ManagementHandler) GetClientClaims(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	claims, err := h.verifyManagementToken(r, "read:client_claims")
	if err != nil {
		h.writeAuthError(w, err)
		return
	}

	clientID := ps.ByName("id")
	if err := h.checkOwnership(r.Context(), claims, clientID); err != nil {
		if errors.Is(err, errOwnershipDenied) {
			tokenOrgID, _ := claims["org_id"].(string)
			if tokenOrgID == "" {
				h.writeError(w, http.StatusForbidden, "management API requires a service account token with org_id claim")
			} else {
				h.writeError(w, http.StatusForbidden, "access denied")
			}
		} else {
			// Return 403 (not 404) to prevent client ID enumeration.
			h.writeError(w, http.StatusForbidden, "access denied")
		}
		return
	}

	defs, err := h.clientStore.ListCustomClaims(r.Context(), clientID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to load claims")
		return
	}

	out := managementDefsToOutput(defs)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"claims": out})
}

// PutClientClaims handles PUT /api/v1/clients/:id/claims.
func (h *ManagementHandler) PutClientClaims(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	claims, err := h.verifyManagementToken(r, "update:client_claims")
	if err != nil {
		h.writeAuthError(w, err)
		return
	}

	clientID := ps.ByName("id")
	if err := h.checkOwnership(r.Context(), claims, clientID); err != nil {
		if errors.Is(err, errOwnershipDenied) {
			tokenOrgID, _ := claims["org_id"].(string)
			if tokenOrgID == "" {
				h.writeError(w, http.StatusForbidden, "management API requires a service account token with org_id claim")
			} else {
				h.writeError(w, http.StatusForbidden, "access denied")
			}
		} else {
			// Return 403 (not 404) to prevent client ID enumeration.
			h.writeError(w, http.StatusForbidden, "access denied")
		}
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var body struct {
		Claims []managementClaimInput `json:"claims"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusUnprocessableEntity, "invalid JSON body")
		return
	}

	defs, err := validateManagementClaims(body.Claims)
	if err != nil {
		h.writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	if err := h.clientStore.SetCustomClaimsAdmin(r.Context(), clientID, defs); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to save claims")
		return
	}
	h.blocklistClientTokens(r.Context(), clientID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"operation": "replace_all",
		"count":     len(defs),
		"claims":    managementDefsToOutput(defs),
	})
}

// PatchClientClaim handles PATCH /api/v1/clients/:id/claims/:key.
func (h *ManagementHandler) PatchClientClaim(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	claims, err := h.verifyManagementToken(r, "update:client_claims")
	if err != nil {
		h.writeAuthError(w, err)
		return
	}

	clientID := ps.ByName("id")
	if err := h.checkOwnership(r.Context(), claims, clientID); err != nil {
		if errors.Is(err, errOwnershipDenied) {
			tokenOrgID, _ := claims["org_id"].(string)
			if tokenOrgID == "" {
				h.writeError(w, http.StatusForbidden, "management API requires a service account token with org_id claim")
			} else {
				h.writeError(w, http.StatusForbidden, "access denied")
			}
		} else {
			h.writeError(w, http.StatusForbidden, "access denied")
		}
		return
	}

	key := strings.TrimSpace(strings.TrimPrefix(ps.ByName("key"), "/"))
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	var body managementClaimInput
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusUnprocessableEntity, "invalid JSON body")
		return
	}
	if strings.TrimSpace(body.Key) == "" {
		body.Key = key
	}
	if body.Key != key {
		h.writeError(w, http.StatusUnprocessableEntity, "claim key in path and body must match")
		return
	}

	defs, err := validateManagementClaims([]managementClaimInput{body})
	if err != nil {
		h.writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if len(defs) != 1 {
		h.writeError(w, http.StatusUnprocessableEntity, "claim key is required")
		return
	}

	if err := h.clientStore.PatchCustomClaimAdmin(r.Context(), clientID, defs[0]); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to save claim")
		return
	}
	h.blocklistClientTokens(r.Context(), clientID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"operation": "patch",
		"claim":     managementDefsToOutput(defs)[0],
	})
}

func (h *ManagementHandler) blocklistClientTokens(ctx context.Context, clientID string) {
	if h.rdb == nil || h.revStore == nil {
		return
	}
	key := "oauth:client-tokens:" + clientID
	jtis, err := h.rdb.SMembers(ctx, key).Result()
	if err != nil {
		return
	}
	for _, jti := range jtis {
		_ = h.revStore.RevokeJTI(ctx, jti, 2*time.Hour)
	}
	_ = h.rdb.Del(ctx, key).Err()
}

var errOwnershipDenied = errors.New("ownership denied")

// verifyManagementToken parses and validates the Bearer JWT, checks the management
// audience, revocation state, and required scope. Returns the token claims on success.
func (h *ManagementHandler) verifyManagementToken(r *http.Request, requiredScope string) (jwt.MapClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") || len(authHeader) == len("Bearer ") {
		return nil, errors.New("missing or malformed Authorization header")
	}
	tokenStr := authHeader[len("Bearer "):]

	parsed, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, errors.New("unexpected signing method")
			}
			kid, _ := token.Header["kid"].(string)
			if kid != h.keyStore.KeyID {
				return nil, errors.New("unknown kid")
			}
			return h.keyStore.PublicKey, nil
		},
		jwt.WithValidMethods([]string{"RS256"}),
	)
	if err != nil || !parsed.Valid {
		if err != nil {
			msg := err.Error()
			switch {
			case strings.Contains(msg, "expired"):
				return nil, errors.New("token_expired")
			case strings.Contains(msg, "unknown kid"):
				return nil, errors.New("unknown_kid")
			case strings.Contains(msg, "unexpected signing method"):
				return nil, errors.New("invalid_signature")
			}
		}
		return nil, errors.New("invalid token")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	// Issuer must match the server's own URL.
	if h.appURL != "" {
		iss, _ := claims["iss"].(string)
		if iss != h.appURL {
			return nil, errors.New("invalid token")
		}
	}

	// Audience must exactly match the management audience (string or single-element array).
	var aud string
	switch v := claims["aud"].(type) {
	case string:
		aud = v
	case []interface{}:
		if len(v) == 1 {
			aud, _ = v[0].(string)
		}
	}
	if aud != h.mgmtAud {
		return nil, errors.New("invalid token")
	}

	// Check revocation (fail closed).
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, errors.New("missing jti")
	}
	revoked, revErr := h.revStore.IsRevoked(r.Context(), jti)
	if revErr != nil || revoked {
		return nil, errors.New("token revoked")
	}

	// Scope check — opaque error to avoid leaking scope names.
	scope, _ := claims["scope"].(string)
	if !scopeHasWord(scope, requiredScope) {
		return nil, errors.New("insufficient scope")
	}

	return claims, nil
}

// checkOwnership verifies the token's org_id matches the client's org_id.
func (h *ManagementHandler) checkOwnership(ctx context.Context, claims jwt.MapClaims, clientID string) error {
	tokenOrgID, _ := claims["org_id"].(string)
	if tokenOrgID == "" {
		return errOwnershipDenied
	}

	clientOrgID, err := h.clientStore.GetClientOrgID(ctx, clientID)
	if err != nil || clientOrgID == nil {
		return errors.New("client not found")
	}
	if *clientOrgID != tokenOrgID {
		return errOwnershipDenied
	}
	return nil
}

// validateManagementClaims validates claim definitions received from the Management API.
// Unlike validateClaims (which handles form arrays), this accepts the JSON struct slice
// and also allows scope_gate (Management API is the intended DX for scope-gated claims).
func validateManagementClaims(inputs []managementClaimInput) ([]postgres.ClaimDefinition, error) {
	if len(inputs) > 20 {
		return nil, errors.New("maximum 20 claims per client")
	}

	defs := make([]postgres.ClaimDefinition, 0, len(inputs))
	seen := make(map[string]bool, len(inputs))
	approxSize := 2
	for _, inp := range inputs {
		k := strings.TrimSpace(inp.Key)
		if k == "" {
			continue
		}
		if len(k) > 100 {
			return nil, errors.New("claim key must be 100 characters or fewer")
		}
		if !claimKeyRegex.MatchString(k) {
			return nil, errors.New("claim key \"" + k + "\" contains invalid characters")
		}
		if _, reserved := reservedClaimKeys[strings.ToLower(k)]; reserved {
			return nil, errors.New("\"" + k + "\" is a reserved claim name and cannot be overridden")
		}
		if !strings.HasPrefix(k, "https://") {
			return nil, errors.New("claim key \"" + k + "\" must be namespaced with an https:// prefix (e.g. https://example.com/tier)")
		}
		if seen[k] {
			return nil, errors.New("duplicate claim key \"" + k + "\"")
		}
		seen[k] = true

		rawVal := strings.TrimSpace(inp.Value)
		var valueType, storedVal string
		switch inp.Type {
		case "string":
			valueType, storedVal = "string", rawVal
			approxSize += len(k) + len(rawVal) + 6
		case "number":
			lower := strings.ToLower(rawVal)
			if lower == "nan" || lower == "inf" || lower == "+inf" || lower == "-inf" || lower == "infinity" || lower == "-infinity" {
				return nil, errors.New("claim \"" + k + "\": number value must be finite")
			}
			var f float64
			if _, err := fmt.Sscanf(rawVal, "%g", &f); err != nil {
				return nil, errors.New("claim \"" + k + "\": invalid number value")
			}
			valueType, storedVal = "number", fmt.Sprintf("%g", f)
			approxSize += len(k) + len(storedVal) + 4
		case "boolean":
			if rawVal != "true" && rawVal != "false" {
				return nil, errors.New("claim \"" + k + "\": boolean value must be \"true\" or \"false\"")
			}
			valueType, storedVal = "boolean", rawVal
			approxSize += len(k) + 7
		default:
			return nil, errors.New("claim \"" + k + "\": type must be string, number, or boolean")
		}

		if approxSize > 4096 {
			return nil, errors.New("total claim payload too large (approx 4 KB max)")
		}

		sourceKind := strings.TrimSpace(inp.SourceKind)
		if sourceKind == "" {
			sourceKind = "static"
		}
		if sourceKind != "static" && sourceKind != "user_attribute" && sourceKind != "expression" {
			return nil, errors.New("claim \"" + k + "\": source_kind must be static, user_attribute, or expression")
		}
		if sourceKind == "user_attribute" && !validClaimAttribute[storedVal] {
			return nil, errors.New("claim \"" + k + "\": unsupported user_attribute value")
		}

		dest := strings.TrimSpace(inp.Destinations)
		if dest == "" {
			dest = "token"
		}
		dest = normalizeDestinationsHandler(dest)
		if !validDestinations[dest] {
			return nil, errors.New("claim \"" + k + "\": invalid destinations value \"" + dest + "\"")
		}

		scopeGate := strings.TrimSpace(inp.ScopeGate)
		if scopeGate != "" {
			if len(scopeGate) > 64 {
				return nil, errors.New("claim \"" + k + "\": scope_gate must be 64 characters or fewer")
			}
			if strings.ContainsAny(scopeGate, " \t\n\r") {
				return nil, errors.New("claim \"" + k + "\": scope_gate must be a single scope identifier (no spaces)")
			}
		}

		defs = append(defs, postgres.ClaimDefinition{
			Key:          k,
			ValueType:    valueType,
			Value:        storedVal,
			Destinations: dest,
			ScopeGate:    scopeGate,
			SourceKind:   sourceKind,
		})
	}
	return defs, nil
}

func managementDefsToOutput(defs []postgres.ClaimDefinition) []managementClaimOutput {
	out := make([]managementClaimOutput, len(defs))
	for i, d := range defs {
		out[i] = managementClaimOutput{
			Key:          d.Key,
			Type:         d.ValueType,
			Value:        d.Value,
			Destinations: d.Destinations,
			ScopeGate:    d.ScopeGate,
			SourceKind:   d.SourceKind,
		}
		if out[i].SourceKind == "" {
			out[i].SourceKind = "static"
		}
	}
	return out
}

var validClaimAttribute = map[string]bool{
	"user.id":       true,
	"user.email":    true,
	"user.name":     true,
	"user.username": true,
	"org.id":        true,
	"org.role":      true,
}

func (h *ManagementHandler) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeAuthError returns a 401 with RFC 6750 error fields. The error detail from
// verifyManagementToken is mapped to opaque codes so internal details don't leak.
func (h *ManagementHandler) writeAuthError(w http.ResponseWriter, err error) {
	msg := err.Error()
	code := "invalid_token"
	desc := "token validation failed"
	switch msg {
	case "missing or malformed Authorization header":
		// RFC 6750 §3.1: realm-only challenge when no credentials are present; no error= parameter.
		w.Header().Set("WWW-Authenticate", `Bearer realm="anekdote-auth"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "Authorization header is required",
		})
		return
	case "token revoked":
		desc = "token has been revoked"
	case "token_expired":
		desc = "token has expired"
	case "unknown_kid":
		desc = "token header references an unknown key id"
	case "invalid_signature":
		desc = "token signature algorithm is invalid"
	case "missing jti":
		desc = "token validation failed"
	case "insufficient scope":
		code = "insufficient_scope"
		desc = "token does not have the required scope"
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s" error_description="%s"`, code, desc))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	body := map[string]string{
		"error":             code,
		"error_description": desc,
	}
	if msg == "token_expired" || msg == "unknown_kid" || msg == "invalid_signature" {
		body["error_subcode"] = msg
	}
	json.NewEncoder(w).Encode(body)
}

// scopeHasWord reports whether scope contains the exact word target.
func scopeHasWord(scope, target string) bool {
	return strings.Contains(" "+scope+" ", " "+target+" ")
}

// normalizeDestinationsHandler sorts comma-separated destination parts alphabetically
// so that "id_token,access_token" and "access_token,id_token" resolve to the same canonical form.
func normalizeDestinationsHandler(d string) string {
	parts := strings.Split(d, ",")
	trimmed := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			trimmed = append(trimmed, s)
		}
	}
	// simple insertion sort (always ≤5 elements)
	for i := 1; i < len(trimmed); i++ {
		for j := i; j > 0 && trimmed[j] < trimmed[j-1]; j-- {
			trimmed[j], trimmed[j-1] = trimmed[j-1], trimmed[j]
		}
	}
	return strings.Join(trimmed, ",")
}
