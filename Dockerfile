FROM golang:1.20-alpine3.17 AS builder
WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download -x

COPY cmd/ cmd/
RUN go build -o fake-jwt-server cmd/fake-jwt-server/main.go

FROM alpine:3.17

WORKDIR /app
COPY private.pem .
COPY form.html .
COPY --from=builder /build/fake-jwt-server .

CMD [ "./fake-jwt-server" ]
