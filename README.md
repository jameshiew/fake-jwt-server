# fake-jwt-server [![Docker Hub pulls](https://img.shields.io/docker/pulls/jameshiew/fake-jwt-server?style=flat-square)](https://hub.docker.com/r/jameshiew/fake-jwt-server/tags)

:warning: This service is for local/development use only.

Small HTTP service that is meant to approximate some parts of the [Auth0 browser based authentication flow](https://auth0.com/docs/api/authentication#database-ad-ldap-passive-) for generating [JSON Web Tokens (JWTs)](https://en.wikipedia.org/wiki/JSON_Web_Token), to make development easier.

- can use either the provided RSA key in `private.pem` for signing JWTs, or one randomly generated at startup
- serves a JSON Web Key Set (JWKS) at `/.well-known/jwks.json`
- `/authorize` offers up a HTML form for generating JWTs, that can also be prefilled with values from query parameters
- `POST`ing to `/authorize` will respond with the signed JWT
- `POST`ing to `/authorize?redirect_uri=...` will redirect to the specified `redirect_uri` with the JWT in the `access_token` field of the `location.hash`

## Quickstart

```shell
go run cmd/fake-jwt-server/main.go
```

The server will listen on <http://0.0.0.0:8080>. To use a newly generated RSA key for the JWKS:

```shell
FAKE_JWT_SERVER_GENERATE_RSA_KEY=true go run cmd/fake-jwt-server/main.go
```

You could get a signed JWT that expires in ~1 year like so.

```shell
curl -X POST \
     -H "Content-Type: multipart/form-data" \
     -F "sub=auth0|fb8618e6-8639-454d-9f94-4496b0b224a8" \
     -F "scope=openid profile email" \
     -F "iat=$(date +%s)" \
     -F "exp=$(($(date +%s) + 31536000))" \
     -F "iss=http://localhost:8080" \
     -F "azp=example-azp" \
     -F "aud=http://localhost:3000" \
     http://localhost:8080/authorize
```
