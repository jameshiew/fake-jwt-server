FROM golang:1.20-alpine3.17 AS builder
WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download -x

COPY main.go .
RUN go build -o fake-jwt-server

FROM alpine:3.17

WORKDIR /app
COPY private.pem .
COPY form.html .
COPY --from=builder /build/fake-jwt-server .

CMD [ "./fake-jwt-server" ]
