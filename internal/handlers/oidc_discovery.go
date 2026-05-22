package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

// OIDCConfig represents the OpenID Connect discovery document
type OIDCConfig struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethods          []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// OpenIDConfiguration serves the OIDC discovery document
func (h *DiscoveryHandler) OpenIDConfiguration(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	baseURL := h.appURL

	config := OIDCConfig{
		Issuer:                           baseURL,
		AuthorizationEndpoint:            baseURL + "/authorize",
		TokenEndpoint:                    baseURL + "/token",
		UserinfoEndpoint:                 baseURL + "/userinfo",
		JwksURI:                          baseURL + "/.well-known/jwks.json",
		RevocationEndpoint:               baseURL + "/revoke",
		ResponseTypesSupported:           []string{"code"},
		ResponseModesSupported:           []string{"query"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "jti", "scope",
			"name", "updated_at", "email", "email_verified",
			"org_id", "org_role", "at_hash",
		},
		GrantTypesSupported:          []string{"authorization_code"},
		TokenEndpointAuthMethods:     []string{"client_secret_post", "none"},
		CodeChallengeMethodsSupported: []string{"S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}
