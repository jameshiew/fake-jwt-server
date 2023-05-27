package server

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"text/template"
	"time"

	"github.com/jameshiew/fake-jwt-server/internal/config"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
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

type Server struct {
	Addr     string
	Config   config.Config
	Key      *rsa.PrivateKey
	Template *template.Template
	JWKS     string
}

func New(addr string, cfg config.Config, key *rsa.PrivateKey, tmpl *template.Template, jwks string) (*Server, error) {
	if addr == "" {
		return nil, fmt.Errorf("addr cannot be empty")
	}
	if key == nil {
		return nil, fmt.Errorf("key cannot be nil")
	}
	if tmpl == nil {
		return nil, fmt.Errorf("tmpl cannot be nil")
	}
	if jwks == "" {
		return nil, fmt.Errorf("jwks cannot be empty")
	}
	return &Server{
		Addr:     addr,
		Config:   cfg,
		Key:      key,
		Template: tmpl,
		JWKS:     jwks,
	}, nil
}

func (s *Server) ServeMux() http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc(rootPath, s.defaultHandler)
	mux.HandleFunc(jwksPath, s.jwksHandler)
	mux.HandleFunc(authorizePath, s.authorizeHandler)
	return http.Server{
		Addr:    s.Addr,
		Handler: mux,
	}
}

const (
	rootPath      = "/"
	jwksPath      = "/.well-known/jwks.json"
	authorizePath = "/authorize"
)

func (s *Server) defaultHandler(w http.ResponseWriter, r *http.Request) {
	log.Infof("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	http.Redirect(w, r, "/authorize", http.StatusSeeOther)
}

func (s *Server) jwksHandler(w http.ResponseWriter, r *http.Request) {
	log.Infof("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, s.JWKS)
}

func (s *Server) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	log.Infof("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	if r.Method == "GET" {
		audience := r.FormValue("audience")
		if audience == "" {
			audience = s.Config.DefaultAudience
		}

		authorizing_party := r.FormValue("client_id")
		if authorizing_party == "" {
			authorizing_party = s.Config.DefaultAuthorizingParty
		}

		scope := r.FormValue("scope")
		if scope == "" {
			scope = s.Config.DefaultScope
		}

		issuedAt := time.Now()
		expiry := issuedAt.Add(time.Hour * 24 * 365)

		jwt := JwtForm{
			Issuer:           s.Config.DefaultIssuer,
			Subject:          s.Config.DefaultSubject,
			Audience:         audience,
			AuthorizingParty: authorizing_party,
			Scope:            scope,
			IssuedAt:         issuedAt.Unix(),
			Expiry:           expiry.Unix(),
		}
		w.Header().Set("Content-Type", "text/html")
		s.Template.Execute(w, jwt)
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
		buf, err := jws.Sign(jwtJson, jws.WithKey(jwa.RS256, s.Key, jws.WithProtectedHeaders(hdrs)))
		if err != nil {
			log.Warn("failed to sign payload", err)
			return
		}
		log.Debug("Signed JWT: ", string(buf))

		redirect_uri := r.FormValue("redirect_uri")
		if redirect_uri == "" {
			// if no redirect is specifed, we just return the JWT
			w.Header().Set("Content-Type", "text/plain")
			w.Write(buf)
			return
		}
		redirect_uri = redirect_uri + "#access_token=" + string(buf)
		http.Redirect(w, r, redirect_uri, http.StatusSeeOther)
	}
}
