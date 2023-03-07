package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"text/template"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/spf13/viper"

	log "github.com/sirupsen/logrus"
)

type JwtForm struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	// right now only one audience, but we could have more than one in the future
	Audience         string `json:"aud"`
	AuthorizingParty string `json:"azp"`
	Scope            string `json:"scope"`
	IssuedAt         int64  `json:"iat"`
	Expiry           int64  `json:"exp"`
}

func main() {
	viper.SetDefault("issuer", "http://localhost:8080")
	viper.SetDefault("subject", "fb8618e6-8639-454d-9f94-4496b0b224a8")
	viper.SetDefault("audience", "http://localhost:3000")
	viper.SetDefault("scope", "openid profile email")
	viper.SetDefault("authorizing_party", "example-azp")
	viper.SetDefault("callback_uri", "http://localhost:3000/auth/callback")

	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Info("No config found, will use defaults")
		} else {
			panic(fmt.Errorf("fatal error config file: %w", err))
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate new RSA private key: %s\n", err)
		return
	}

	jwks := makeJWKS(key)
	if jwks == "" {
		fmt.Println("failed to make JWKS")
		return
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Infof("%s %s", r.Method, r.URL.Path)
		http.Redirect(w, r, "/authorize", http.StatusSeeOther)
	})

	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		log.Infof("%s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, jwks)
	})

	tmpl := template.Must(template.ParseFiles("form.html"))

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		log.Infof("%s %s", r.Method, r.URL.Path)
		if r.Method == "GET" {
			audience := r.FormValue("audience")
			if audience == "" {
				audience = viper.GetString("audience")
			}

			authorizing_party := r.FormValue("client_id")
			if authorizing_party == "" {
				authorizing_party = viper.GetString("authorizing_party")
			}

			scope := r.FormValue("scope")
			if scope == "" {
				scope = viper.GetString("scope")
			}

			issuedAt := time.Now()
			expiry := issuedAt.Add(time.Minute * 5)

			jwt := JwtForm{
				Issuer:           viper.GetString("issuer"),
				Subject:          viper.GetString("subject"),
				Audience:         audience,
				AuthorizingParty: authorizing_party,
				Scope:            scope,
				IssuedAt:         issuedAt.Unix(),
				Expiry:           expiry.Unix(),
			}
			w.Header().Set("Content-Type", "text/html")
			tmpl.Execute(w, jwt)
			return
		}
		if r.Method == "POST" {
			r.ParseMultipartForm(1024 * 1024)
			if r.MultipartForm == nil {
				log.Warn("No form data")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			log.Info("Got form data: ", r.MultipartForm.Value)
			iat, err := strconv.Atoi(r.MultipartForm.Value["iat"][0])
			if err != nil {
				log.Warn("Failed to parse iat: ", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			exp, err := strconv.Atoi(r.MultipartForm.Value["exp"][0])
			if err != nil {
				log.Warn("Failed to parse exp: ", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			jwt := JwtForm{
				Issuer:           r.MultipartForm.Value["iss"][0],
				Subject:          r.MultipartForm.Value["sub"][0],
				Audience:         r.MultipartForm.Value["aud"][0],
				AuthorizingParty: r.MultipartForm.Value["azp"][0],
				Scope:            r.MultipartForm.Value["scope"][0],
				IssuedAt:         int64(iat),
				Expiry:           int64(exp),
			}

			hdrs := jws.NewHeaders()
			hdrs.Set(jws.TypeKey, "JWT")
			hdrs.Set(jws.KeyIDKey, "123")
			jwtJson, err := json.Marshal(jwt)
			if err != nil {
				log.Warn("failed to marshal JWT", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			buf, err := jws.Sign(jwtJson, jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(hdrs)))
			if err != nil {
				log.Warn("failed to sign payload", err)
				return
			}
			log.Debug("Signed JWT: ", string(buf))

			callback_uri := viper.GetString("callback_uri")
			callback_uri = callback_uri + "#access_token=" + string(buf)

			http.Redirect(w, r, callback_uri, http.StatusSeeOther)
		}
	})

	addr := "0.0.0.0:8080"
	log.Infof("Listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func makeJWKS(raw *rsa.PrivateKey) string {
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
