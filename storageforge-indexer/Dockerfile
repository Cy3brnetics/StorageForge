# syntax=docker/dockerfile:1.7
# StorageForge: multi-stage build, non-root minimal runtime on Wolfi.
#   docker build -t storageforge:0.6.5 .
#   docker build --build-arg EXTRAS=postgres -t storageforge:0.6.5-pg .
# The base images are pinned by digest and every Python package by hash (docker/requirements*.lock). Wolfi packages
# are not: a rebuild picks up the latest security updates. README "Updating dependencies" has the commands that refresh the pins.
# Wolfi, not Debian: it ships fixes as upstream releases them and publishes a security feed Trivy and Grype both read, so
# the scanners report what is actually unfixed. Debian slim carried 130-odd findings with no fix available.
ARG BASE_IMAGE=cgr.dev/chainguard/wolfi-base@sha256:833c48f1faf32c90e6f9501a2410a9aa28ceb2c594102edd4470053c30efa089
# rust 1.100.0 on Alpine 3.24, the image enclave/image/build.sh builds in: the two must make the same bytes
ARG ENCLAVE_BUILD_IMAGE=rust@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33

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

# the link of the StorageForge network (the sfnet stage below), written out of the package so that there is one copy of it
RUN install -d /out \
 && /opt/venv/bin/python -c "import sys; from storageforge_index import sfcontroller; sys.stdout.write(sfcontroller.LINK)" > /out/storageforge-sfnet-link

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

# ── nginx: built from source, with the modules docker/nginx.conf uses and no others. Wolfi's nginx-mainline was at 1.31.8
# on the day 1.31.9 fixed CVE-2026-123007 and CVE-2026-123633 (memory corruption in HTTP/2, reachable before any login),
# and its package carries forty modules this proxy never loads (mail, stream, perl, xslt, image filter, HTTP/3 …).
# Position-independent with full RELRO, so the address space is randomized: what those two bugs need is to know it.
# Scanners cannot see a binary built here: when bumping, read nginx.org/en/security_advisories.html and verify the
# tarball's signature. README "Updating dependencies".
FROM ${BASE_IMAGE} AS nginx
ARG NGINX_VERSION=1.31.9
ADD --checksum=sha256:a11c5eeee2e257f4478f0e649f84b0040787d277d2d3e5233952aa6b6dcb80ad \
    https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz /src/nginx.tar.gz
RUN apk add --no-cache build-base openssl-dev pcre2-dev \
 && tar -xzf /src/nginx.tar.gz -C /src --strip-components=1 \
 && cd /src \
 && ./configure --prefix=/var/lib/nginx --sbin-path=/usr/bin/nginx --conf-path=/etc/nginx/nginx.conf \
                --pid-path=/tmp/nginx.pid --lock-path=/tmp/nginx.lock --error-log-path=stderr --http-log-path=/dev/null \
                --http-client-body-temp-path=/tmp/client_temp --http-proxy-temp-path=/tmp/proxy_temp \
                --user=nginx --group=nginx --with-http_ssl_module --with-http_v2_module \
                --without-http_gzip_module --without-http_ssi_module --without-http_userid_module --without-http_access_module \
                --without-http_auth_basic_module --without-http_mirror_module --without-http_autoindex_module \
                --without-http_geo_module --without-http_map_module --without-http_split_clients_module \
                --without-http_referer_module --without-http_fastcgi_module --without-http_uwsgi_module \
                --without-http_scgi_module --without-http_grpc_module --without-http_memcached_module \
                --without-http_limit_conn_module --without-http_limit_req_module --without-http_empty_gif_module \
                --without-http_browser_module --without-http_charset_module --without-http_upstream_hash_module \
                --without-http_upstream_ip_hash_module --without-http_upstream_least_conn_module \
                --without-http_upstream_random_module --without-http_upstream_keepalive_module \
                --without-http_upstream_zone_module --without-http-cache \
                --with-cc-opt='-O2 -fPIE -fstack-protector-strong -fstack-clash-protection -fcf-protection -D_FORTIFY_SOURCE=3' \
                --with-ld-opt='-pie -Wl,-z,relro,-z,now,-z,noexecstack' \
 && make -j"$(nproc)" \
 && strip objs/nginx \
 && install -D -m 0755 objs/nginx /out/usr/bin/nginx

# ── enclave: the key enclave's micro VM image, a kernel and an initramfs holding one static program (docs/security.md, "Key
# enclave"). The steps are enclave/image/inside.sh, the ones enclave/image/build.sh runs: the versions and the time below are
# that script's, and SHA256SUMS from either is the same, which is how a build of one's own is compared with a release's.
FROM ${ENCLAVE_BUILD_IMAGE} AS enclave
ARG ENCLAVE_EPOCH=1794960000
ARG ENCLAVE_KERNEL=6.18.65
ARG ENCLAVE_KERNEL_SHA256=c92606f956f09dc50b5a0e2af9e86763fce27ada1647de97f8d1ac8cfc95801d
ENV SRC=/ws/enclave WORKSPACE=/ws OUT=/out EPOCH=${ENCLAVE_EPOCH} KERNEL=${ENCLAVE_KERNEL} KERNEL_SHA256=${ENCLAVE_KERNEL_SHA256}
# the kernel first, from its two files alone: a change to the program does not build it again
COPY enclave/image/inside.sh enclave/image/kernel.config /ws/enclave/image/
RUN mkdir /out && JOBS="$(nproc)" sh /ws/enclave/image/inside.sh kernel
# the program is one member of the Cargo workspace (Cargo.toml): cargo wants every member there, and builds only this one
COPY Cargo.toml Cargo.lock /ws/
COPY wire /ws/wire
COPY agent /ws/agent
COPY enclave /ws/enclave
RUN sh /ws/enclave/image/inside.sh program && sh /ws/enclave/image/inside.sh initramfs && sh /ws/enclave/image/inside.sh sums

# ── agent-build: storageforge-agent and storageforge-agentctl, static, for x86_64 and arm64 (docs/agent.md). The steps are
# agent/inside.sh, the ones agent/build.sh runs, in the enclave's build container: SHA256SUMS from either is the same.
# AGENT_RELEASE_SIGNERS names the signers file compiled into both: the keys whose signature makes a plugin an official one.
FROM ${ENCLAVE_BUILD_IMAGE} AS agent-build
ARG AGENT_EPOCH=1794960000
ARG AGENT_RELEASE_SIGNERS=agent/release_signers
ENV WORKSPACE=/ws OUT=/out EPOCH=${AGENT_EPOCH} STORAGEFORGE_RELEASE_SIGNERS=/release_signers
COPY Cargo.toml Cargo.lock /ws/
COPY wire /ws/wire
COPY enclave /ws/enclave
COPY agent /ws/agent
COPY ${AGENT_RELEASE_SIGNERS} /release_signers
RUN mkdir /out && sh /ws/agent/inside.sh x86_64 && sh /ws/agent/inside.sh aarch64 && sh /ws/agent/inside.sh sums

# ── agent-root: the agent image's files, laid out here because the image itself has nothing that could lay them out.
# Wolfi's base layout and nothing else of Wolfi: no libc, no shell, no package manager. The package database stays as the
# record scanners read. sfagent is 10003:10003, an id of its own beside the server's 10001 and the tunnel's 10002.
FROM ${BASE_IMAGE} AS agent-root
RUN apk add --no-cache --initdb --root /rootfs --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories wolfi-baselayout \
 && echo 'sfagent:x:10003:' >> /rootfs/etc/group \
 && echo 'sfagent:x:10003:10003::/nonexistent:/sbin/nologin' >> /rootfs/etc/passwd \
 && install -d -m 0755 /rootfs/etc/storageforge-agent /rootfs/var/lib/storageforge-agent /rootfs/var/lib/storageforge-agent/manifest /rootfs/host /rootfs/usr/bin \
 && install -d -m 0700 -o 10003 -g 10003 /rootfs/var/lib/storageforge-agent/state \
 && install -d -m 1777 /rootfs/tmp \
 && rm -rf /rootfs/var/cache/apk /rootfs/etc/apk/cache \
 && ! ls /rootfs/bin/sh /rootfs/bin/busybox /rootfs/usr/bin/apk /rootfs/sbin/apk 2>/dev/null

# ── agent: the one image the optional agent runs from on every host (docker build --target agent .). One static program, run
# as sfagent: no shell, no interpreter, no OpenSSL, no libc, no package manager, no plugin built in. The runtime gives it a
# read-only root filesystem, no capabilities and no network (storageforge-agentctl makes the container).
FROM scratch AS agent
ARG TARGETARCH=amd64
LABEL org.opencontainers.image.title="StorageForge agent" \
      org.opencontainers.image.description="The optional StorageForge agent: one static program that runs signed plugins and reads its host"
COPY --from=agent-root /rootfs/ /
COPY --from=agent-build /out/${TARGETARCH}/storageforge-agent /usr/bin/storageforge-agent
USER 10003:10003
ENTRYPOINT ["/usr/bin/storageforge-agent"]
CMD ["run"]

# ── firecracker: what runs that VM in the container. A static program, pinned by the checksum its release publishes; the
# project does not sign releases. When bumping, read its release notes and security advisories. README "Updating dependencies".
FROM ${BASE_IMAGE} AS firecracker
ARG FIRECRACKER_VERSION=v1.18.0
ADD --checksum=sha256:1ac8eec866dd5eea14efecf6323e22b23eea24054545338a5b34bc5bca6623cd \
    https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-x86_64.tgz /src/firecracker.tgz
RUN tar -xzf /src/firecracker.tgz -C /src --strip-components=1 \
 && install -D -m 0755 /src/firecracker-${FIRECRACKER_VERSION}-x86_64 /out/usr/bin/firecracker

# ── tailscale: the stack's own place on a tailnet (docker-compose.yml, service tailscale). Static programs, pinned by the
# checksum pkgs.tailscale.com publishes beside each tarball. When bumping, read tailscale.com/changelog and its security
# bulletins (tailscale.com/security-bulletins), and take the new .sha256 from the same place. README "Updating dependencies".
FROM ${BASE_IMAGE} AS tailscale-bin
ARG TAILSCALE_VERSION=1.104.7
ADD --checksum=sha256:e56693ff74a64f2591b7e819c280635a100aae1ddfb0ef058fcd052b7cd8d16c \
    https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VERSION}_amd64.tgz /src/tailscale.tgz
RUN tar -xzf /src/tailscale.tgz -C /src --strip-components=1 \
 && install -D -m 0755 /src/tailscaled /out/usr/bin/tailscaled \
 && install -D -m 0755 /src/tailscale /out/usr/bin/tailscale

FROM ${BASE_IMAGE} AS tailscale
# nft for the one table the entrypoint keeps on tailscale0 (iptables from Wolfi defaults to the legacy backend, which a host on
# nftables does not have); busybox stays for the entrypoint's shell.
RUN apk add --no-cache nftables \
 && rm -rf /var/cache/apk /etc/apk/cache
COPY --from=tailscale-bin /out/ /
COPY docker/tailscale/entrypoint.sh /usr/local/bin/storageforge-tailscale
RUN ["/usr/bin/tailscale", "version"]
ENTRYPOINT ["/usr/local/bin/storageforge-tailscale"]

# ── proxy: nginx with its config inside, so a deploy does not need the repo's files on the Docker host ─
FROM ${BASE_IMAGE} AS proxy
# uid 101 is the one docker-compose.yml and init-volumes.sh already give the TLS files and the /tmp tmpfs to.
# The so: names are the libraries the nginx stage linked against; the -V below fails the build if a soname moves.
RUN apk add --no-cache so:libssl.so.4 so:libcrypto.so.4 so:libpcre2-8.so.0 \
 && echo 'nginx:x:101:' >> /etc/group \
 && echo 'nginx:x:101:101::/nonexistent:/sbin/nologin' >> /etc/passwd \
 && echo 'nginx:!::0:::::' >> /etc/shadow \
 && install -d -m 0755 /etc/nginx /var/lib/nginx \
 && rm -rf /var/cache/apk /etc/apk/cache \
 && cp /bin/busybox /tmp/busybox \
 && apk del --no-cache wolfi-base apk-tools busybox \
 && for l in /usr/bin/*; do if [ "$(/tmp/busybox readlink "$l")" = /bin/busybox ]; then /tmp/busybox rm "$l"; fi; done \
 && /tmp/busybox rm /tmp/busybox
# No shell and no package manager from here on: apk del leaves busybox's links behind, so the loop takes them out.
# The apk database stays as the record scanners read.
COPY --from=nginx /out/ /
RUN ["/usr/bin/nginx", "-V"]
COPY docker/nginx.conf /etc/nginx/nginx.conf
EXPOSE 8443
STOPSIGNAL SIGQUIT
USER 101:101
# -e: nginx opens its error log before it reads the config, and the only place this container may write is /tmp.
ENTRYPOINT ["/usr/bin/nginx", "-e", "/dev/stderr", "-g", "daemon off;"]

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

# ── sfnet: the controller's end of StorageForge's own network (docker-compose.sfnet.yml). It runs as root with NET_ADMIN and
# nothing else, in the server's network namespace: it makes the WireGuard interface and keeps the private key, which the
# server never sees. bash, wg and ip are all it runs.
FROM ${BASE_IMAGE} AS sfnet
RUN apk add --no-cache bash coreutils grep iproute2 wireguard-tools \
 && install -d -m 0700 /etc/wireguard \
 && install -d -m 0755 /run/storageforge-sfnet/want /run/storageforge-sfnet/state \
 && rm -rf /var/cache/apk /etc/apk/cache
COPY --from=build --chmod=0755 /out/storageforge-sfnet-link /usr/local/bin/storageforge-sfnet-link
RUN ["/usr/bin/wg", "--version"]
ENTRYPOINT ["/usr/local/bin/storageforge-sfnet-link", "run"]

# ── runtime (last, so a plain docker build makes this one) ─────────────────────
FROM ${BASE_IMAGE} AS runtime
# kept equal to the package and the compose image tags by tests/test_bughunt_rest_a.py
ARG VERSION=0.6.5
LABEL org.opencontainers.image.title="StorageForge" \
      org.opencontainers.image.description="Encrypted SSH key vault, agentless file indexer and storage graph" \
      org.opencontainers.image.version="${VERSION}"
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
COPY --from=firecracker /out/ /
COPY --from=enclave /out/vmlinux /out/bzImage /out/initramfs.cpio.gz /out/SHA256SUMS /usr/share/storageforge/enclave/
# storageforge-agentctl for both kinds of machine: the server sends it to a host when the agent is set up there (docs/agent.md)
COPY --from=agent-build /out/x86_64/storageforge-agentctl /usr/share/storageforge/agent/x86_64/storageforge-agentctl
COPY --from=agent-build /out/aarch64/storageforge-agentctl /usr/share/storageforge/agent/aarch64/storageforge-agentctl
COPY --from=agent-build /out/SHA256SUMS /usr/share/storageforge/agent/SHA256SUMS
# the official plugins, unsigned until the release key's holder signs them (agent/plugins.sh sign): a plugin without its signature
# is not offered, and no host would run it
COPY --from=agent-build /out/plugins/ /usr/share/storageforge/agent/plugins/
RUN ["/usr/bin/firecracker", "--version"]
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
    STORAGEFORGE_ENCLAVE_IMAGE_DIR=/usr/share/storageforge/enclave \
    STORAGEFORGE_AGENT_DIR=/usr/share/storageforge/agent \
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
