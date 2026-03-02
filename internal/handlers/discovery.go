package handlers

import (
	"encoding/json"
	"math/big"
	"net/http"

	"encoding/base64"

	"github.com/iabhishekrajput/anekdote-auth/internal/crypto"
	"github.com/julienschmidt/httprouter"
)

type DiscoveryHandler struct {
	keyStore *crypto.KeyStore
}

func NewDiscoveryHandler(ks *crypto.KeyStore) *DiscoveryHandler {
	return &DiscoveryHandler{keyStore: ks}
}

// JWK represents a single JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

// JWKS represents the set of JSON Web Keys
type JWKS struct {
	Keys []JWK `json:"keys"`
}

func (h *DiscoveryHandler) WellKnownJWKS(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pubKey := h.keyStore.PublicKey

	// Convert the RSA Exponent integer to bytes and base64url encode them
	eBytes := big.NewInt(int64(pubKey.E)).Bytes()
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	// Convert the RSA Modulus to bytes and base64url encode them
	nStr := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())

	jwks := JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Kid: "anekdote-key-1",
				Use: "sig",
				N:   nStr,
				E:   eStr,
				Alg: "RS256",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
