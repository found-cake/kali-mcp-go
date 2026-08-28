ARG KALI_BASE_IMAGE=kalilinux/kali-last-release

FROM golang:1.27-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o /out/kali-server ./cmd/kali-server \
    && CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o /out/mcp-client ./cmd/mcp-client

FROM ${KALI_BASE_IMAGE}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        dirb \
        enum4linux \
        gobuster \
        gzip \
        hydra \
        john \
        metasploit-framework \
        nikto \
        nmap \
        sqlmap \
        tshark \
        unzip \
        wpscan \
        wordlists \
    && if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gzip -d /usr/share/wordlists/rockyou.txt.gz; \
    fi \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/kali-server /out/mcp-client /usr/local/bin/
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
