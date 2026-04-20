# ── Stage 1: build ──────────────────────────────
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache upx ca-certificates

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o waptly . \
    && upx --best --lzma waptly

# ── Stage 2: minimal runtime image ──────────────
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/waptly /waptly

ENTRYPOINT ["/waptly"]
