package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/julienschmidt/httprouter"
)

// ManagementRevStore checks JWT revocation for Management API bearer tokens.
type ManagementRevStore interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// ManagementClientStore is the minimal store interface the Management API needs.
type ManagementClientStore interface {
	GetClientOrgID(ctx context.Context, clientID string) (*string, error)
	ListCustomClaims(ctx context.Context, clientID string) ([]postgres.ClaimDefinition, error)
	SetCustomClaimsAdmin(ctx context.Context, clientID string, defs []postgres.ClaimDefinition) error
}

// ManagementHandler serves the Management REST API (Bearer JWT, management audience).
type ManagementHandler struct {
	keyStore    *crypto.KeyStore
	revStore    ManagementRevStore
	clientStore ManagementClientStore
	mgmtAud     string // required aud claim value
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

// managementClaimInput is the JSON shape accepted by PUT /api/v1/clients/:id/claims.
type managementClaimInput struct {
	Key          string `json:"key"`
	Type         string `json:"type"`
	Value        string `json:"value"`
	Destinations string `json:"destinations,omitempty"`
	ScopeGate    string `json:"scope_gate,omitempty"`
}

// managementClaimOutput is the JSON shape returned by GET /api/v1/clients/:id/claims.
type managementClaimOutput struct {
	Key          string `json:"key"`
	Type         string `json:"value_type"`
	Value        string `json:"value"`
	Destinations string `json:"destinations"`
	ScopeGate    string `json:"scope_gate,omitempty"`
}

// GetClientClaims handles GET /api/v1/clients/:id/claims.
func (h *ManagementHandler) GetClientClaims(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	claims, err := h.verifyManagementToken(r, "read:client_claims")
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	clientID := ps.ByName("id")
	if err := h.checkOwnership(r.Context(), claims, clientID); err != nil {
		if errors.Is(err, errOwnershipDenied) {
			h.writeError(w, http.StatusForbidden, "token org_id does not match client org")
			return
		}
		h.writeError(w, http.StatusNotFound, "client not found")
		return
	}

	defs, err := h.clientStore.ListCustomClaims(r.Context(), clientID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to load claims")
		return
	}

	out := make([]managementClaimOutput, 0, len(defs))
	for _, d := range defs {
		out = append(out, managementClaimOutput{
			Key:          d.Key,
			Type:         d.ValueType,
			Value:        d.Value,
			Destinations: d.Destinations,
			ScopeGate:    d.ScopeGate,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"claims": out})
}

// PutClientClaims handles PUT /api/v1/clients/:id/claims.
func (h *ManagementHandler) PutClientClaims(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	claims, err := h.verifyManagementToken(r, "update:client_claims")
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	clientID := ps.ByName("id")
	if err := h.checkOwnership(r.Context(), claims, clientID); err != nil {
		if errors.Is(err, errOwnershipDenied) {
			h.writeError(w, http.StatusForbidden, "token org_id does not match client org")
			return
		}
		h.writeError(w, http.StatusNotFound, "client not found")
		return
	}

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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"claims": managementDefsToOutput(defs)})
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
		return nil, errors.New("invalid token")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	// Audience must exactly match the management audience.
	aud, _ := claims["aud"].(string)
	if aud != h.mgmtAud {
		return nil, fmt.Errorf("token audience %q does not match management audience", aud)
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

	// Scope check.
	scope, _ := claims["scope"].(string)
	if !scopeHasWord(scope, requiredScope) {
		return nil, fmt.Errorf("token missing required scope %q", requiredScope)
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

		dest := strings.TrimSpace(inp.Destinations)
		if dest == "" {
			dest = "token"
		}
		dest = normalizeDestinationsHandler(dest)
		if !validDestinations[dest] {
			return nil, errors.New("claim \"" + k + "\": invalid destinations value \"" + dest + "\"")
		}

		scopeGate := strings.TrimSpace(inp.ScopeGate)

		defs = append(defs, postgres.ClaimDefinition{
			Key:          k,
			ValueType:    valueType,
			Value:        storedVal,
			Destinations: dest,
			ScopeGate:    scopeGate,
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
		}
	}
	return out
}

func (h *ManagementHandler) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="anekdote-auth"`)
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
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
