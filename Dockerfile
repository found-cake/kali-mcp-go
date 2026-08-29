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

ARG TARGETARCH

# Nmap cannot exec when its NET_ADMIN file capability exceeds Docker's default bounding set.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        chromium \
        curl \
        dirb \
        enum4linux \
        feroxbuster \
        ffuf \
        gobuster \
        gzip \
        hydra \
        iproute2 \
        jq \
        john \
        libcap2-bin \
        metasploit-framework \
        nikto \
        nmap \
        nodejs \
        npm \
        nuclei \
        openssl \
        python3 \
        python3-venv \
        sqlmap \
        tar \
        tshark \
        unzip \
        whatweb \
        wpscan \
        wordlists \
    && setcap -r /usr/lib/nmap/nmap \
    && nmap --version >/dev/null \
    && if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gzip -d /usr/share/wordlists/rockyou.txt.gz; \
    fi \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) dalfox_arch="x86_64"; osv_arch="amd64" ;; \
        arm64) dalfox_arch="aarch64"; osv_arch="arm64" ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    dalfox_release_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' https://github.com/hahwul/dalfox/releases/latest)"; \
    dalfox_tag="$(basename "$dalfox_release_url")"; \
    test -n "$dalfox_tag"; \
    dalfox_asset="dalfox-${dalfox_tag}-linux-${dalfox_arch}-musl.tar.gz"; \
    curl -fsSL "https://github.com/hahwul/dalfox/releases/download/${dalfox_tag}/${dalfox_asset}" -o "/tmp/${dalfox_asset}"; \
    curl -fsSL "https://github.com/hahwul/dalfox/releases/download/${dalfox_tag}/${dalfox_asset}.sha256" -o "/tmp/${dalfox_asset}.sha256"; \
    echo "$(awk '{print $1}' "/tmp/${dalfox_asset}.sha256")  /tmp/${dalfox_asset}" | sha256sum -c -; \
    dalfox_dir="${dalfox_asset%.tar.gz}"; \
    tar -xzf "/tmp/${dalfox_asset}" -C /usr/local/bin --strip-components=1 "${dalfox_dir}/dalfox"; \
    osv_asset="osv-scanner_linux_${osv_arch}"; \
    curl -fsSL "https://github.com/google/osv-scanner/releases/latest/download/${osv_asset}" -o "/usr/local/bin/osv-scanner"; \
    curl -fsSL "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_SHA256SUMS" -o /tmp/osv-scanner_SHA256SUMS; \
    osv_checksum="$(grep " ${osv_asset}$" /tmp/osv-scanner_SHA256SUMS | awk '{print $1}')"; \
    echo "${osv_checksum}  /usr/local/bin/osv-scanner" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/dalfox /usr/local/bin/osv-scanner; \
    rm -f "/tmp/${dalfox_asset}" "/tmp/${dalfox_asset}.sha256" /tmp/osv-scanner_SHA256SUMS

RUN set -eux; \
    mkdir -p /opt/jwt_tool; \
    jwt_release_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' https://github.com/ticarpi/jwt_tool/releases/latest)"; \
    jwt_tag="$(basename "$jwt_release_url")"; \
    test -n "$jwt_tag"; \
    curl -fsSL "https://github.com/ticarpi/jwt_tool/archive/refs/tags/${jwt_tag}.tar.gz" \
        | tar -xz --strip-components=1 -C /opt/jwt_tool; \
    python3 -m venv /opt/jwt_tool/.venv; \
    /opt/jwt_tool/.venv/bin/pip install --no-cache-dir -r /opt/jwt_tool/requirements.txt; \
    mkdir -p /opt/jwt_tool-seed; \
    HOME=/opt/jwt_tool-seed /opt/jwt_tool/.venv/bin/python /opt/jwt_tool/jwt_tool.py \
        eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJzZWVkIn0. >/dev/null 2>&1 \
        || test -f /opt/jwt_tool-seed/.jwt_tool/jwtconf.ini; \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install -g \
        playwright \
        retire

COPY --from=build /out/kali-server /out/mcp-client /usr/local/bin/
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY browser-check.cjs /usr/local/lib/kali-mcp/browser-check.cjs
COPY jwt-tool.sh /usr/local/bin/jwt_tool

RUN set -eux; \
    printf '#!/usr/bin/env sh\nexec node /usr/local/lib/kali-mcp/browser-check.cjs "$@"\n' > /usr/local/bin/browser-check; \
    chmod 0755 /usr/local/bin/browser-check /usr/local/bin/jwt_tool; \
    dalfox --version; \
    ffuf -V; \
    feroxbuster --version; \
    jq --version; \
    nuclei -version; \
    osv-scanner --version; \
    playwright --version; \
    retire --version; \
    whatweb --version

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
