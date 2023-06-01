package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"

	"github.com/jameshiew/fake-jwt-server/internal"
	"github.com/jameshiew/fake-jwt-server/internal/config"
	"github.com/stretchr/testify/require"
)

func mustNewFakeServer(t *testing.T) Server {
	rsaKey, err := internal.GenerateRSAKey()
	require.NoError(t, err)
	tmpl := template.Must(template.ParseFiles("../../form.html"))
	s, err := New("localhost:8080", config.Default(), rsaKey, tmpl, internal.MakeJWKS(rsaKey))
	require.NoError(t, err)
	return *s
}

func TestDefaultHandler(t *testing.T) {
	s := mustNewFakeServer(t)

	req, err := http.NewRequest(http.MethodGet, rootPath, nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.defaultHandler)

	handler.ServeHTTP(rr, req)

	require.Equal(t, rr.Code, http.StatusSeeOther)
	require.Equal(t, rr.Header().Get("Location"), authorizePath)
}

func TestJwksHandler(t *testing.T) {
	s := mustNewFakeServer(t)

	req, err := http.NewRequest(http.MethodGet, jwksPath, nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.jwksHandler)

	handler.ServeHTTP(rr, req)

	require.Equal(t, rr.Code, http.StatusOK)
	require.Equal(t, rr.Body.String(), s.JWKS)
}
