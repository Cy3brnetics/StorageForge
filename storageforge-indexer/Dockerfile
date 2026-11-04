# syntax=docker/dockerfile:1.7
# StorageForge: multi-stage build, non-root slim runtime.
#   docker build -t storageforge:0.3.2 .
#   docker build --build-arg EXTRAS=postgres -t storageforge:0.3.2-pg .
# The base images are pinned by digest and every Python package by hash (docker/requirements*.lock). Debian packages
# are not: a rebuild picks up the latest security updates. README "Updating dependencies" has the commands that refresh the pins.
ARG PYTHON_IMAGE=python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

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
COPY docker ./docker
RUN apt-get update --error-on=any && apt-get install -y --no-install-recommends openssh-client util-linux rsync git \
 && /opt/venv/bin/python -m unittest discover -s tests

# ── openssh: the ssh client, newer than Debian ships. Debian 13 has 10.0, with CVE-2026-60002 (critical) and CVE-2026-106583
# unpatched. Built here with no Kerberos, PKCS#11 or security key support, so those libraries are not in the image.
# Scanners cannot see a binary built here: when bumping, read the OpenSSH release notes. README "Updating dependencies".
FROM ${PYTHON_IMAGE} AS openssh
ARG OPENSSH_VERSION=10.6p1
ADD --checksum=sha256:a9dc9565dffe8640f64d863cd29a32bc4a3dbdec0566a7fc44c5d6ee767d5f39 \
    https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz /src/openssh.tar.gz
RUN apt-get update --error-on=any \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends gcc make libc6-dev libssl-dev zlib1g-dev \
 && tar -xzf /src/openssh.tar.gz -C /src --strip-components=1 \
 && cd /src \
 && ./configure --prefix=/usr --sysconfdir=/etc/ssh --without-pam --without-selinux --without-kerberos5 --without-libedit \
                --disable-pkcs11 --disable-security-key \
 && make -j"$(nproc)" ssh ssh-add ssh-agent ssh-keygen sshd sshd-session sshd-auth \
 && strip ssh ssh-add ssh-agent ssh-keygen sshd sshd-session sshd-auth \
 && install -d /out /out-server \
 && install -m 0755 ssh ssh-add ssh-agent ssh-keygen contrib/ssh-copy-id /out/ \
 && install -m 0755 sshd sshd-session sshd-auth ssh-keygen /out-server/

# ── proxy: nginx with its config inside, so a deploy does not need the repo's files on the Docker host ─
FROM nginxinc/nginx-unprivileged:1.30-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03 AS proxy
USER 0
RUN apk upgrade --no-cache && apk del --no-cache curl      # nginx does not use it
USER 101
COPY docker/nginx.conf /etc/nginx/nginx.conf

# ── tunnel: sshd for remote nodes that dial in (docker-compose.remote.yml), and nothing that could serve a shell ─
FROM ${PYTHON_IMAGE} AS tunnel
RUN groupadd --system --gid 10002 sftunnel \
 && useradd --system --uid 10002 --gid sftunnel --home-dir /nonexistent --no-create-home --shell /bin/false -p '*' sftunnel \
 && install -d -o 10002 -g 10002 -m 0755 /var/lib/sf-tunnel \
 && install -d -m 0755 /run/sf-tunnel-keys /etc/ssh /usr/libexec
COPY --from=openssh /out-server/sshd /usr/sbin/sshd
COPY --from=openssh /out-server/sshd-session /out-server/sshd-auth /usr/libexec/
COPY --from=openssh /out-server/ssh-keygen /usr/bin/ssh-keygen
COPY docker/tunnel/sshd_config /etc/ssh/sshd_config
COPY docker/tunnel/entrypoint.sh /usr/local/bin/storageforge-tunnel
USER 10002:10002
ENTRYPOINT ["/usr/local/bin/storageforge-tunnel"]

# ── runtime (last, so a plain docker build makes this one) ─────────────────────
FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="StorageForge" \
      org.opencontainers.image.description="Encrypted SSH key vault, agentless file indexer and storage graph" \
      org.opencontainers.image.version="0.3.2"
RUN apt-get update --error-on=any \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends tini ca-certificates nmap \
 && groupadd --system --gid 10001 storageforge \
 && useradd --system --uid 10001 --gid storageforge --home-dir /app/data/home --no-create-home \
            --shell /usr/sbin/nologin storageforge \
 && install -d -o 10001 -g 10001 -m 0700 /app /app/data /app/backups /run/storageforge \
 && rm -rf /usr/local/bin/pip* /usr/local/lib/python3*/site-packages/pip /usr/local/lib/python3*/site-packages/pip-* \
           /usr/local/lib/python3*/ensurepip \
 && rm -f /var/lib/dpkg/info/*.prerm /var/lib/dpkg/info/*.postrm \
 && dpkg --purge --force-remove-essential --force-remove-protected --force-depends \
      apt libapt-pkg7.0 sqv debian-archive-keyring adduser debconf libdebconfclient0 init-system-helpers \
      perl-base bash tar gzip diffutils sysvinit-utils ncurses-bin ncurses-base libncursesw6 libtinfo6 \
      libreadline8t64 readline-common libdb5.3t64 libgdbm6t64 \
      util-linux bsdutils mount login login.defs passwd liblastlog2-2 libmount1 libblkid1 libsmartcols1 libuuid1 \
      libpam-modules libpam-modules-bin libpam-runtime libpam0g libsemanage2 libsemanage-common libsepol2 \
      libaudit1 libaudit-common libcap-ng0 libseccomp2 libudev1 liblz4-1 libxxhash0 \
      libgssapi-krb5-2 libkrb5-3 libk5crypto3 libkrb5support0 libkeyutils1 libcom-err2 \
 && rm -rf /var/lib/apt /var/cache/apt /var/cache/debconf /var/log/apt      # nothing installs packages at runtime; dpkg stays as the record scanners read
COPY --from=build /opt/venv /opt/venv
COPY --from=openssh /out/ /usr/bin/
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
