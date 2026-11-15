# syntax=docker/dockerfile:1.7
# StorageForge: multi-stage build, non-root minimal runtime on Wolfi.
#   docker build -t storageforge:0.3.2 .
#   docker build --build-arg EXTRAS=postgres -t storageforge:0.3.2-pg .
# The base images are pinned by digest and every Python package by hash (docker/requirements*.lock). Wolfi packages
# are not: a rebuild picks up the latest security updates. README "Updating dependencies" has the commands that refresh the pins.
# Wolfi, not Debian: it ships fixes as upstream releases them and publishes a security feed Trivy and Grype both read, so
# the scanners report what is actually unfixed. Debian slim carried 130-odd findings with no fix available.
ARG BASE_IMAGE=cgr.dev/chainguard/wolfi-base@sha256:833c48f1faf32c90e6f9501a2410a9aa28ceb2c594102edd4470053c30efa089

# ── build: resolve wheels into an isolated virtualenv ──────────────────────────
FROM ${BASE_IMAGE} AS build
ARG EXTRAS=""
RUN apk add --no-cache python-3.14
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY docker/requirements.lock docker/requirements-postgres.lock ./docker/
COPY storageforge_index ./storageforge_index
RUN lock="docker/requirements${EXTRAS:+-$EXTRAS}.lock" \
 && { [ -f "$lock" ] || { echo "no $lock: EXTRAS is empty or postgres" >&2; exit 1; }; } \
 && python3.14 -m venv /opt/venv \
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
COPY docker ./docker
# The suite runs the scripts StorageForge puts on target hosts, so it needs what a target host has: bash, GNU tools and
# util-linux, not busybox (whose flock has no -w, for one).
RUN apk add --no-cache openssh-client openssh-keygen util-linux flock rsync git tzdata \
                       bash coreutils findutils grep sed gawk diffutils gnutar gzip procps posix-libc-utils \
 && /opt/venv/bin/python -m unittest discover -s tests

# ── openssh: the ssh client, built with no Kerberos, PKCS#11 or security key support, so those libraries are not in the image.
# (Built from source since Debian 13 shipped 10.0, with CVE-2026-60002 (critical) and CVE-2026-106583 unpatched.)
# Scanners cannot see a binary built here: when bumping, read the OpenSSH release notes. README "Updating dependencies".
FROM ${BASE_IMAGE} AS openssh
ARG OPENSSH_VERSION=10.6p1
ADD --checksum=sha256:a9dc9565dffe8640f64d863cd29a32bc4a3dbdec0566a7fc44c5d6ee767d5f39 \
    https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz /src/openssh.tar.gz
RUN apk add --no-cache build-base openssl-dev zlib-dev \
 && tar -xzf /src/openssh.tar.gz -C /src --strip-components=1 \
 && cd /src \
 && ./configure --prefix=/usr --sysconfdir=/etc/ssh --without-pam --without-selinux --without-kerberos5 --without-libedit \
                --disable-pkcs11 --disable-security-key \
 && make -j"$(nproc)" ssh ssh-add ssh-agent ssh-keygen sshd sshd-session sshd-auth \
 && strip ssh ssh-add ssh-agent ssh-keygen sshd sshd-session sshd-auth \
 && install -d /out /out-server \
 && install -m 0755 ssh ssh-add ssh-agent ssh-keygen contrib/ssh-copy-id /out/ \
 && install -m 0755 sshd sshd-session sshd-auth ssh-keygen /out-server/

# ── nmap: Wolfi's free repository stops at 7.94, which has CVE-2026-58058. Built here with only what netscan.py runs
# (connect scans, --top-ports): no ncat, nping, OpenSSL or zenmap, and no NSE scripts (7.991 needs Lua to compile, but
# without nse_main.lua and scripts/ copied in, NSE cannot run). Scanners cannot see a binary built here:
# when bumping, read the nmap changelog and verify the tarball's signature. README "Updating dependencies".
FROM ${BASE_IMAGE} AS nmap
ARG NMAP_VERSION=7.991
ADD --checksum=sha256:a5d507f29437bef3bedd4771ff9aaa8fc1c2a109ddba1f5b1cf12027456929be \
    https://nmap.org/dist/nmap-${NMAP_VERSION}.tar.bz2 /src/nmap.tar.bz2
RUN apk add --no-cache build-base linux-headers \
 && tar -xjf /src/nmap.tar.bz2 -C /src --strip-components=1 \
 && cd /src \
 && ./configure --prefix=/usr --without-zenmap --without-ndiff --without-nping --without-ncat --without-nmap-update \
                --with-liblua=included --without-libssh2 --without-openssl --without-libz \
                --with-libpcap=included --with-libpcre=included --with-libdnet=included --with-liblinear=included \
 && make -j"$(nproc)" nmap \
 && strip nmap \
 && install -D -m 0755 nmap /out/usr/bin/nmap \
 && install -d /out/usr/share/nmap \
 && install -m 0644 nmap-services nmap-protocols nmap-rpc nmap-mac-prefixes /out/usr/share/nmap/

# ── proxy: nginx with its config inside, so a deploy does not need the repo's files on the Docker host ─
FROM nginxinc/nginx-unprivileged:1.30-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03 AS proxy
USER 0
RUN apk upgrade --no-cache && apk del --no-cache curl      # nginx does not use it
USER 101
COPY docker/nginx.conf /etc/nginx/nginx.conf

# ── tunnel: sshd for remote nodes that dial in (docker-compose.remote.yml), and nothing that could serve a shell ─
FROM ${BASE_IMAGE} AS tunnel
# The libraries the openssh stage linked against; the sshd -V below fails the build if they move to a new soname.
RUN apk add --no-cache so:libcrypto.so.4 so:libz.so.1 \
 && echo 'sftunnel:x:10002:' >> /etc/group \
 && echo 'sftunnel:x:10002:10002::/nonexistent:/bin/false' >> /etc/passwd \
 && echo 'sftunnel:*::0:::::' >> /etc/shadow \
 && install -d -o 10002 -g 10002 -m 0755 /var/lib/sf-tunnel \
 && install -d -m 0755 /run/sf-tunnel-keys /etc/ssh /usr/libexec
COPY --from=openssh /out-server/sshd /usr/sbin/sshd
COPY --from=openssh /out-server/sshd-session /out-server/sshd-auth /usr/libexec/
COPY --from=openssh /out-server/ssh-keygen /usr/bin/ssh-keygen
RUN ["/usr/sbin/sshd", "-V"]
COPY docker/tunnel/sshd_config /etc/ssh/sshd_config
COPY docker/tunnel/entrypoint.sh /usr/local/bin/storageforge-tunnel
USER 10002:10002
ENTRYPOINT ["/usr/local/bin/storageforge-tunnel"]

# ── runtime (last, so a plain docker build makes this one) ─────────────────────
FROM ${BASE_IMAGE} AS runtime
LABEL org.opencontainers.image.title="StorageForge" \
      org.opencontainers.image.description="Encrypted SSH key vault, agentless file indexer and storage graph" \
      org.opencontainers.image.version="0.3.2"
# tzdata: the scheduler's zoneinfo would otherwise fall back to UTC for every schedule. The so: names are the libraries
# the openssh and nmap stages linked against; the -V checks below fail the build if a soname moves.
RUN apk add --no-cache python-3.14 tini ca-certificates-bundle tzdata openssl so:libcrypto.so.4 so:libz.so.1 \
                       so:libstdc++.so.6 so:libgcc_s.so.1 \
 && echo 'storageforge:x:10001:' >> /etc/group \
 && echo 'storageforge:x:10001:10001::/app/data/home:/sbin/nologin' >> /etc/passwd \
 && echo 'storageforge:!::0:::::' >> /etc/shadow \
 && install -d -o 10001 -g 10001 -m 0700 /app /app/data /app/backups /run/storageforge \
 && apk del --no-cache wolfi-base apk-tools \
 && rm -rf /var/cache/apk /etc/apk/cache      # nothing installs packages at runtime; the apk database stays as the record scanners read
COPY --from=build /opt/venv /opt/venv
COPY --from=openssh /out/ /usr/bin/
COPY --from=nmap /out/ /
RUN ["/usr/bin/ssh", "-V"]
RUN ["/usr/bin/nmap", "--version"]
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/storageforge-entrypoint
COPY --chmod=0755 docker/init-volumes.sh /usr/local/bin/storageforge-init-volumes
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
