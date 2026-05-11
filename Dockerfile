# syntax=docker/dockerfile:1.7

# ----------------------------------------------------------------------------
# Stage: assets — build the Tailwind CSS bundle.
# ----------------------------------------------------------------------------
FROM node:22-alpine AS assets
WORKDIR /app

COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci

COPY tailwind.config.js ./
COPY web/static/tailwind.css ./web/static/tailwind.css
COPY web/ui ./web/ui

RUN npx @tailwindcss/cli -c tailwind.config.js \
    -i ./web/static/tailwind.css \
    -o ./web/static/app.css \
    --minify

# ----------------------------------------------------------------------------
# Stage: gobuilder — generate templ files and cross-compile auth-server.
# ----------------------------------------------------------------------------
FROM golang:1.26-alpine AS gobuilder
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go tool templ generate ./...

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/auth-server \
        ./cmd/auth-server

# ----------------------------------------------------------------------------
# Stage: migratebuilder — cross-compile a pinned goose binary.
# ----------------------------------------------------------------------------
FROM golang:1.26-alpine AS migratebuilder
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH

ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/pressly/goose/v3/cmd/goose@v3.21.1 \
    && mkdir -p /out \
    && if [ -x "/go/bin/${GOOS}_${GOARCH}/goose" ]; then \
           cp "/go/bin/${GOOS}_${GOARCH}/goose" /out/goose; \
       else \
           cp /go/bin/goose /out/goose; \
       fi

# ----------------------------------------------------------------------------
# Stage: runtime — distroless image running auth-server.
# ----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
WORKDIR /app

COPY --from=gobuilder /out/auth-server /app/auth-server
COPY web/static/tailwind.css /app/web/static/tailwind.css
COPY --from=assets /app/web/static/app.css /app/web/static/app.css

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/auth-server"]

# ----------------------------------------------------------------------------
# Stage: migrate — distroless image running goose against ./migrations.
# ----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS migrate
WORKDIR /app

COPY --from=migratebuilder /out/goose /usr/local/bin/goose
COPY migrations /app/migrations

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/goose", "-dir", "/app/migrations", "postgres"]
