package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

// OIDCConfig represents the OpenID Connect discovery document
type OIDCConfig struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	RevocationEndpoint               string   `json:"revocation_endpoint,omitempty"`
}

// OpenIDConfiguration serves the OIDC discovery document
func (h *DiscoveryHandler) OpenIDConfiguration(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	baseURL := "http://" + r.Host // In prod, determine HTTPS appropriately

	config := OIDCConfig{
		Issuer:                           baseURL,
		AuthorizationEndpoint:            baseURL + "/authorize",
		TokenEndpoint:                    baseURL + "/token",
		JwksURI:                          baseURL + "/.well-known/jwks.json",
		RevocationEndpoint:               baseURL + "/revoke",
		ResponseTypesSupported:           []string{"code", "token", "id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}
