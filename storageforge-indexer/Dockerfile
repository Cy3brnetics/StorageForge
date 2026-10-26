# syntax=docker/dockerfile:1.7
# StorageForge: multi-stage build, non-root slim runtime.
#   docker build -t storageforge:0.2.0 .
#   docker build --build-arg EXTRAS=postgres -t storageforge:0.2.0-pg .
ARG PYTHON_IMAGE=python:3.13-slim-bookworm

# ── build: resolve wheels into an isolated virtualenv ──────────────────────────
FROM ${PYTHON_IMAGE} AS build
ARG EXTRAS=""
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY storageforge_index ./storageforge_index
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install ".${EXTRAS:+[$EXTRAS]}" \
 && /opt/venv/bin/python -m compileall -q /opt/venv \
 && find /opt/venv -name '*.dist-info' -path '*pip*' -prune -exec rm -rf {} + \
 && rm -rf /opt/venv/bin/pip* /opt/venv/lib/python*/site-packages/pip

# ── test: run the suite against the built package (docker build --target test .) ─
FROM build AS test
COPY tests ./tests
COPY examples ./examples
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client util-linux \
 && /opt/venv/bin/python -m unittest discover -s tests

# ── runtime ───────────────────────────────────────────────────────────────────
FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="StorageForge" \
      org.opencontainers.image.description="Encrypted SSH key vault, agentless file indexer and storage graph" \
      org.opencontainers.image.version="0.2.0"
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sqlite3 tini ca-certificates \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
 && groupadd --system --gid 10001 storageforge \
 && useradd --system --uid 10001 --gid storageforge --home-dir /app/data/home --no-create-home \
            --shell /usr/sbin/nologin storageforge \
 && install -d -o 10001 -g 10001 -m 0700 /app /app/data /run/storageforge \
 && rm -f /usr/bin/ssh-keyscan /usr/bin/scp /usr/bin/sftp
COPY --from=build /opt/venv /opt/venv
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/storageforge-entrypoint
ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HOME=/app/data/home \
    STORAGEFORGE_DB=/app/data/index.db \
    STORAGEFORGE_DATA_DIR=/app/data \
    STORAGEFORGE_RUNTIME_DIR=/run/storageforge \
    STORAGEFORGE_LISTEN=0.0.0.0 \
    STORAGEFORGE_PORT=8080
WORKDIR /app
USER 10001:10001
VOLUME ["/app/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["storageforge-index", "healthcheck"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/storageforge-entrypoint"]
CMD ["serve"]
