package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"text/template"

	"github.com/jameshiew/fake-jwt-server/internal"
	"github.com/jameshiew/fake-jwt-server/internal/config"
	"github.com/jameshiew/fake-jwt-server/internal/server"
	log "github.com/sirupsen/logrus"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Errorf("failed to load config: %v", err)
		return
	}
	log.Infof("Loaded config: %+v", cfg)

	var key *rsa.PrivateKey
	if cfg.GenerateRSAKey {
		log.Info("Generating new RSA key")
		key, err = internal.GenerateRSAKey()
		if err != nil {
			log.Errorf("failed to generate new RSA private key: %s", err)
			return
		}
	} else {
		log.Info("Using existing RSA key")
		data, err := os.ReadFile("private.pem")
		if err != nil {
			log.Errorf("failed to read private.pem file: %s", err)
			return
		}

		block, _ := pem.Decode(data)
		if block == nil {
			log.Errorf("failed to decode PEM")
			return
		}

		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Errorf("failed to parse PKCS8 private key: %s", err)
			return
		}

		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			log.Errorf("key is not an RSA private key")
			return
		}
	}

	n := base64.StdEncoding.EncodeToString(key.N.Bytes())
	log.Info("Got RSA key: ", n)

	jwks := internal.MakeJWKS(key)
	if jwks == "" {
		fmt.Println("failed to make JWKS")
		return
	}

	tmpl := template.Must(template.ParseFiles("form.html"))

	srv, err := server.New("0.0.0.0:8080", cfg, key, tmpl, jwks)
	if err != nil {
		log.Errorf("failed to create server: %s", err)
		return
	}

	log.Infof("Listening on %s", srv.Addr)
	mux := srv.ServeMux()
	log.Fatal(mux.ListenAndServe())
}
