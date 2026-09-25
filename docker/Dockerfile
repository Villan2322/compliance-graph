FROM python:3.12-slim

ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
ARG OSV_SCANNER_VERSION=2.6.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

# Pinned scanner binaries (bump versions deliberately; see docs/ROADMAP.md).
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) GL=x64;   OSV=amd64 ;; \
      arm64) GL=arm64; OSV=arm64 ;; \
      *) echo "unsupported arch ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL}.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    curl -fsSL -o /usr/local/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${OSV}"; \
    chmod +x /usr/local/bin/osv-scanner; \
    gitleaks version; osv-scanner --version

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir ".[scan,llm]" \
 && mkdir -p /app/out /app/state /app/sources/raw && chmod -R a+rwX /app/out /app/state /app/sources/raw
# Compose runs this as the host user (CG_UID/CG_GID) so bind-mounted outputs
# stay owned by you on Linux. HOME=/tmp gives Semgrep a writable cache dir.
ENV CGRAPH_ROOT=/app PYTHONUNBUFFERED=1 HOME=/tmp
EXPOSE 8765
CMD ["cgraph", "mcp", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8765"]
