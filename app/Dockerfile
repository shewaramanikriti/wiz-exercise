# syntax=docker/dockerfile:1
#
# Rebuild of the Tasky sample app (github.com/jeffthorne/tasky) for the Wiz exercise.
# Changes vs upstream: modern Go toolchain, patched dependencies, non-root user,
# and /app/wizexercise.txt baked in at build time.

ARG GO_VERSION=1.26
ARG ALPINE_VERSION=3.22

# ---------- build stage ----------
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY src/go.mod src/go.sum ./
RUN go mod download
COPY src/ ./

# Upstream pins 2021-2022 dependencies with known fixed CVEs. Bumping them here
# is the remediation for findings raised by the Trivy gate in CI.
ARG PATCH_DEPS=true
RUN if [ "$PATCH_DEPS" = "true" ]; then \
      go get golang.org/x/crypto@latest golang.org/x/net@latest golang.org/x/text@latest \
             github.com/gin-gonic/gin@latest go.mongodb.org/mongo-driver@v1 && \
      go mod tidy ; \
    fi
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tasky .

# ---------- runtime stage ----------
FROM alpine:${ALPINE_VERSION}
RUN apk upgrade --no-cache && \
    addgroup -S -g 10001 tasky && adduser -S -D -H -u 10001 -G tasky tasky
WORKDIR /app
COPY --from=build /out/tasky /app/tasky
COPY --from=build /src/assets /app/assets

# Exercise requirement: wizexercise.txt containing the candidate's name.
# It is a reviewed, version-controlled file copied in at build time.
COPY wizexercise.txt /app/wizexercise.txt
RUN chmod 0444 /app/wizexercise.txt

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/app/tasky"]
