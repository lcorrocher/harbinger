FROM golang:1.26-bookworm AS builder

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       build-essential pkg-config libyara-dev ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

# layer caching optimisation
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# go-yara uses cgo
ENV CGO_ENABLED=1
ENV GOOS=linux

# Reduce binary size - strip debug info & symbols
RUN go build -trimpath -ldflags "-s -w" -o /out/harbinger ./cmd/server


FROM debian:bookworm-slim

# runtime deps: install libyara-dev
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libyara-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/harbinger /usr/local/bin/harbinger

WORKDIR /app

COPY core/scan /app/core/scan
ENV HARBINGER_RULES_DIR=/app/core/scan


EXPOSE 8080

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/harbinger"]

