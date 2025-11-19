# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM docker.io/library/golang:latest AS builder

ARG TARGETARCH
ARG VERSION

WORKDIR /src
COPY bin ./bin
# Run make to cache hermit (make) download
RUN ./bin/make --version

# Cache module and hermit (go) downloads
COPY go.mod go.sum .
RUN ./bin/go mod download

COPY Makefile *.go .
RUN ./bin/make build CGO_ENABLED=0 GOARCH=${TARGETARCH} VERSION=${VERSION}

FROM scratch
ARG TARGETARCH
ARG VERSION

LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/foxygoat/flapjak"
LABEL org.opencontainers.image.vendor="foxygoat"
LABEL org.opencontainers.image.version="${VERSION}"

COPY --from=builder /src/out/flapjak_${TARGETARCH} /app/flapjak
ENTRYPOINT ["/app/flapjak"]
EXPOSE 10389
