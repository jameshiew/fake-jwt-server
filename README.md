# fake-jwt-server

Small HTTP service that is meant to approximate some parts of the [Auth0 browser based authentication flow](https://auth0.com/docs/api/authentication#database-ad-ldap-passive-) for generating [JSON Web Tokens (JWTs)](https://en.wikipedia.org/wiki/JSON_Web_Token), to make development easier.

- generates a random RSA key at startup to use for signing JWTs
- serves a JSON Web Key Set (JWKS) at `/.well-known/jwks.json`
- `/authorize` offers up a HTML form for generating JWTs, that can also be prefilled with values from query parameters
- `POST`ing to `/authorize` will cause a redirect to the callback URL (`http://locahost:3000/auth/callback` by default) with the JWT in the `access_token` field of the `location.hash`

## Quickstart

```shell
go run main.go
```

The server will listen on <http://0.0.0.0:8080>.
