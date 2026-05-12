FROM golang:1.25-bookworm AS go-builder

ENV GOPATH=/go
ENV GOBIN=/go/bin
ENV PATH=$PATH:/go/bin
ENV CGO_ENABLED=1
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=off
ENV GOTOOLCHAIN=auto
ENV GODEBUG=netdns=cgo

RUN apt-get update -qq \
  && apt-get install -y -qq --no-install-recommends \
    git ca-certificates gcc libc6-dev libpcap-dev make \
  && rm -rf /var/lib/apt/lists/*

# Force IPv4 preference — local VMs often lack IPv6 connectivity,
# causing Go module downloads to fail with "network is unreachable".
RUN echo 'precedence ::ffff:0:0/96 100' >> /etc/gai.conf

# ── ProjectDiscovery & Recon Tools (Go) ──────────────────────────────────────
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/tomnomnom/assetfinder@latest
RUN go install github.com/tomnomnom/anew@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest || echo "Warning: gau build failed (non-fatal)"
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Web discovery & fingerprinting (Go)
RUN go install github.com/OJ/gobuster/v3@latest
RUN go install github.com/rverton/webanalyze/cmd/webanalyze@latest
# Amass (optional — heavy but installed for availability)
RUN go install github.com/owasp-amass/amass/v4/...@latest || echo "Warning: Amass build failed (non-fatal)"

# ── Runtime Image ────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

LABEL maintainer="PentestBot Team"
LABEL description="PentestBot v2 - Automated Penetration Testing Engine"
LABEL version="2.0.0"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV HOME=/home/pentestbot
ENV PENTESTBOT_DATA_DIR=/app/data
ENV PENTESTBOT_LOGS_DIR=/app/logs
ENV PENTESTBOT_REPORTS_DIR=/app/reports
ENV PENTESTBOT_WORK_DIR=/app/data/work
ENV PENTESTBOT_DB_PATH=/app/data/pentestbot.db
ENV NUCLEI_TEMPLATES=/home/pentestbot/.config/nuclei/templates

# ── System Dependencies ──────────────────────────────────────────────────────
RUN apt-get update -qq \
  && apt-get install -y -qq --no-install-recommends \
    bsdextrautils ca-certificates curl dnsutils git gosu jq \
    libpcap-dev libssl-dev \
    libjson-perl libjson-xs-perl libnet-ssleay-perl libxml-writer-perl \
    nmap perl procps wget \
    # Ruby for WhatWeb and WPScan
    ruby ruby-dev build-essential \
  # Joomscan dependencies (Perl modules)
    libwww-perl libcrypt-ssleay-perl liburi-perl \
    # Gowitness dependencies
    chromium \
  && rm -rf /var/lib/apt/lists/*

# ── Copy Go binaries ────────────────────────────────────────────────────────
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/assetfinder /usr/local/bin/
COPY --from=go-builder /go/bin/anew /usr/local/bin/
COPY --from=go-builder /go/bin/dnsx /usr/local/bin/
COPY --from=go-builder /go/bin/naabu /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/katana /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /go/bin/gobuster /usr/local/bin/
COPY --from=go-builder /go/bin/webanalyze /usr/local/bin/
# gau + Amass (may not exist if build failed — soft-copy to avoid failure)
COPY --from=go-builder /go/bin/ /tmp/go-bins/
RUN cp /tmp/go-bins/gau /usr/local/bin/gau 2>/dev/null || echo "gau not available" \
  && cp /tmp/go-bins/amass /usr/local/bin/amass 2>/dev/null || echo "Amass not available" \
  && rm -rf /tmp/go-bins

# ── testssl.sh ───────────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
  && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
  && chmod +x /opt/testssl.sh/testssl.sh

# ── Nikto ────────────────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
  && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
  && chmod +x /opt/nikto/program/nikto.pl

# ── WhatWeb (Ruby) ──────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
  && cd /opt/whatweb \
  && bundle install --without development test 2>/dev/null || gem install json addressable 2>/dev/null || true \
  && ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb \
  && chmod +x /opt/whatweb/whatweb

# ── WPScan (Ruby gem) ──────────────────────────────────────────────────────
RUN gem install wpscan --no-document 2>/dev/null \
  || echo "Warning: WPScan gem installation failed (non-fatal)"

# ── Joomscan (Perl) ─────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/OWASP/joomscan.git /opt/joomscan \
  && ln -sf /opt/joomscan/joomscan.pl /usr/local/bin/joomscan \
  && chmod +x /opt/joomscan/joomscan.pl

# ── Dirsearch (Python) ─────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch \
  && ln -sf /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch \
  && chmod +x /opt/dirsearch/dirsearch.py

# ── Gowitness ──────────────────────────────────────────────────────────────
RUN wget -O /usr/local/bin/gowitness https://github.com/sensepost/gowitness/releases/download/2.5.1/gowitness-2.5.1-linux-amd64 \
  && chmod +x /usr/local/bin/gowitness

# ── Python Application ──────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

# Reinstall the ProjectDiscovery httpx binary after pip installs the unrelated
# Python `httpx` console script into /usr/local/bin/httpx.
COPY --from=go-builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=go-builder /go/bin/httpx /usr/local/bin/pd-httpx

COPY . .

RUN useradd -r -u 1001 -m -d /home/pentestbot -s /bin/sh pentestbot \
  && mkdir -p /app/data/work /app/logs /app/reports /home/pentestbot/.config/nuclei/templates \
  && chown -R pentestbot:pentestbot /app /home/pentestbot \
  && chmod +x /app/docker/entrypoint.sh

# Create default GAU config to suppress "config not found" warning
RUN echo '# GAU default config\nthreads = 2\nblacklist = []\nproviders = ["wayback","commoncrawl","otx"]' \
  > /home/pentestbot/.gau.toml \
  && chown pentestbot:pentestbot /home/pentestbot/.gau.toml

# Download webanalyze technologies.json as pentestbot user (must be after user creation)
RUN gosu pentestbot webanalyze -update 2>&1 | tail -3 || echo "Warning: webanalyze -update failed (will retry at runtime)"

ENTRYPOINT ["/app/docker/entrypoint.sh"]

EXPOSE 8000

VOLUME ["/app/data", "/app/logs", "/app/reports", "/home/pentestbot/.config/nuclei"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health > /dev/null || exit 1

CMD ["python3", "main.py", "--api-only"]
