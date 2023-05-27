package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func GenerateRSAKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func MakeJWKS(raw *rsa.PrivateKey) string {
	key, err := jwk.FromRaw(raw)
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return ""
	}
	if _, ok := key.(jwk.RSAPrivateKey); !ok {
		fmt.Printf("expected jwk.SymmetricKey, got %T\n", key)
		return ""
	}

	jwks := jwk.NewSet()
	if err := jwks.AddKey(key); err != nil {
		fmt.Printf("failed to add key to set: %s", err)
		return ""
	}

	marshalled, err := json.Marshal(jwks)
	if err != nil {
		fmt.Printf("failed to marshal JWKS: %s", err)
		return ""
	}
	return string(marshalled)
}
