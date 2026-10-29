# syntax=docker/dockerfile:1.7
# StorageForge: multi-stage build, non-root slim runtime.
#   docker build -t storageforge:0.2.0 .
#   docker build --build-arg EXTRAS=postgres -t storageforge:0.2.0-pg .
# The base image is pinned by digest and every Python package by hash (docker/requirements*.lock), so a rebuild of
# the same commit gets the same bytes. README "Updating dependencies" has the commands that refresh both.
ARG PYTHON_IMAGE=python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f

# ── build: resolve wheels into an isolated virtualenv ──────────────────────────
FROM ${PYTHON_IMAGE} AS build
ARG EXTRAS=""
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY docker/requirements.lock docker/requirements-postgres.lock ./docker/
COPY storageforge_index ./storageforge_index
RUN lock="docker/requirements${EXTRAS:+-$EXTRAS}.lock" \
 && { [ -f "$lock" ] || { echo "no $lock: EXTRAS is empty or postgres" >&2; exit 1; }; } \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps -r "$lock" \
 && /opt/venv/bin/pip install --no-deps --no-build-isolation --no-index . \
 && /opt/venv/bin/pip uninstall -q -y setuptools \
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
 && install -d -o 10001 -g 10001 -m 0700 /app /app/data /app/backups /run/storageforge \
 && rm -f /usr/bin/ssh-keyscan /usr/bin/scp /usr/bin/sftp \
 && rm -rf /usr/local/bin/pip* /usr/local/lib/python3*/site-packages/pip /usr/local/lib/python3*/site-packages/pip-* \
           /usr/local/lib/python3*/ensurepip      # nothing installs packages at runtime
COPY --from=build /opt/venv /opt/venv
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/storageforge-entrypoint
ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HOME=/app/data/home \
    STORAGEFORGE_DB=/app/data/index.db \
    STORAGEFORGE_DATA_DIR=/app/data \
    SQLITE_TMPDIR=/app/data/tmp \
    STORAGEFORGE_BACKUP_DIR=/app/backups \
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
