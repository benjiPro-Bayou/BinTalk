# Stage 1: Build (keep in step with the go/toolchain lines in go.mod)
FROM golang:1.27-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o api-server ./cmd/api-server

# Stage 2: Runtime
FROM alpine:3.24

RUN apk --no-cache add ca-certificates tzdata \
 && addgroup -S -g 10001 app \
 && adduser -S -D -H -u 10001 -G app app \
 && mkdir -p /data/uploads \
 && chown app:app /data/uploads \
 && chmod 700 /data/uploads

WORKDIR /app
COPY --from=builder /app/api-server /app/api-server

# TLS certificates and the Vault token are mounted at runtime (see docker-compose.yml).
USER app
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=3 \
  CMD wget -q -O /dev/null --no-check-certificate https://127.0.0.1:8000/ready || exit 1

CMD ["/app/api-server"]
