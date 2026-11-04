# Sysadmin Toolbox Catalog: Deploy Scripts & GUI Integration Roadmap

A roadmap for a catalog of **deploy scripts for common sysadmin tools** (VPNs, zero trust, identity, reverse proxies, intrusion prevention, vulnerability scanning, monitoring, backup, secrets, DNS, provisioning) and for how each one **ties back into a graphical interface**, either its own UI or a StorageForge panel built on its API.

This extends [Workload Platform Roadmap](workload-platform-roadmap.md). The catalog format, plan step types, report-then-apply flow and IaC export from that document are reused unchanged. It also relies on the MAC, firewall and compliance engines in the [Ransomware Defense Roadmap](ransomware-defense-roadmap.md).

Status: **planned**. Nothing here is built yet.

---

## 1. Goals and Non-Goals

### 1.1 Goals
1. **One catalog, one format**: every tool is a signed data entry (YAML), not bespoke code. Operators can add, fork and sign their own.
2. **Every deploy goes through the staging toolbox**: Plan → Report (read-only) → Apply (signed runner), and every deploy exports as Bash, Terraform, Puppet or Ansible.
3. **Secure by default**: loopback or management-network exposure, vaulted credentials, firewall rules and MAC labels generated in the same plan.
4. **Bundles**: several tools deployed as one plan ("Hardened homelab") with ordering, shared secrets and a single Report.
5. **GUI tie-back**: for each tool, either link to its own UI (with SSO if possible), or show a native StorageForge panel (status, health, key actions) fed by that tool's API.
6. **Uninstall and upgrade are first-class**: pinned versions, diff on upgrade, rollback, and removal that keeps data by default.

### 1.2 Non-Goals
- Not re-implementing these tools' UIs. StorageForge deploys, secures and surfaces them, and only builds a panel where integration adds value (status, keys, alerts, storage context).
- No tool is installed on the StorageForge server itself unless the entry says so. Everything targets managed hosts.
- No silent exposure to the internet. Public exposure is always an explicit, separately reported step.

---

## 2. Catalog Entry Format

Each entry is a signed YAML file.

```yaml
id: headscale
name: Headscale
category: vpn
summary: Self-hosted Tailscale control server
install:
  methods:                       # first supported method wins, operator can override
    - { kind: quadlet,  image: ghcr.io/juanfont/headscale, digest: sha256:..., rootless: true }
    - { kind: compose,  file: headscale.compose.yml.j2 }
    - { kind: package,  debian: headscale, rhel: headscale }
    - { kind: binary,   url: ..., sha256: ..., signature: ... }
requires:    { ports: [8080/tcp], volumes: [config, data], caps: [], runtimes: [podman|docker|host] }
exposure:    { default: loopback, public_optional: true, behind: reverse-proxy }
secrets:     [ { name: admin_api_key, generate: true, vault: true } ]
firewall:    { allow: [{ port: 443/tcp, from: any, optional: true }] }
mac:         { selinux: container_t, apparmor: default, notes: "mount :Z" }
health:      { url: http://127.0.0.1:8080/health, expect: 200 }
backup:      { paths: [data], consistency: stop-snapshot }
gui:
  native: { url_template: "https://{host}/admin", sso: oidc|none, port: 8080 }
  panel:  { level: status+actions, api: headscale-grpc, widgets: [nodes, routes, preauth-keys] }
upgrade:     { strategy: recreate, rollback_on_unhealthy: true }
risk:        [ "holds node enrolment keys" ]
compliance:  [ cis-docker-5.x ]
```

- **Risk labels** (shown in the Report): mounts the Docker socket, privileged, host network, publishes 80/443, runs as root, holds credentials, opens a listener to the internet.
- **Install methods** are tried in order of safety: rootless container, distro package, then verified binary. The Report shows which was chosen and why.
- **GUI levels**: `none`, `link` (opens the tool's own UI), `sso-link` (opens it already signed in via the SSO provider), `status` (read-only tiles), `status+actions` (tiles plus safe actions), `full` (a complete StorageForge panel).
- **Trust**: official catalog signed by the project, user catalogs signed by the operator's own key. Unsigned entries need an explicit override and a warning banner.

---

## 3. Tool Catalog

GUI column: **Own UI** = the tool ships a web UI to link to. **SF panel** = StorageForge shows status/actions through the tool's API. **CLI-only** = no UI exists, so StorageForge provides one.

### 3.1 VPN and overlay networks
| Tool | Deploy | GUI tie-back | StorageForge integration |
| :--- | :--- | :--- | :--- |
| **WireGuard** | package + `wg-quick`/`systemd-networkd`; generated peer configs | **CLI-only** → SF panel (full): peers, QR codes, handshake age, transfer, key rotation | Keys in the vault, firewall allow rule per peer, peer subnets feed the fencing matrix |
| **Headscale** | Quadlet/compose | Own UI (headscale-ui/headplane) + SF panel (status) via gRPC/API: nodes, routes, pre-auth keys | Pre-auth keys generated into the vault. Enrol-managed-hosts step |
| **Tailscale** (client) | package + `tailscale up` with auth key | Own UI (admin console, SaaS) + SF status via `tailscale status --json` | ACL tags per host role, MagicDNS names shown on host cards |
| **NetBird** | compose (management, signal, relay, dashboard, coturn) | Own UI (dashboard) + SF status | SSO via the identity provider, route/ACL summary |
| **Netmaker** | compose | Own UI | Network and ingress-gateway status |
| **OpenVPN** | package + easy-rsa/PKI script | **CLI-only** → SF panel: clients, cert expiry, revoke | CRL management, client profile download |
| **strongSwan (IPsec)** | package + `swanctl` templates | CLI-only → SF panel (status): tunnels up/down | Site-to-site templates |

### 3.2 Zero trust and access
| Tool | Deploy | GUI tie-back | StorageForge integration |
| :--- | :--- | :--- | :--- |
| **OpenZiti** | controller + router containers | Own UI (ZAC) | Service and identity listing |
| **Pomerium** | container + config | CLI-only → SF panel: routes, policies | Policies generated from catalog `exposure` blocks, so each deployed panel gets a route |
| **Cloudflare Tunnel** | `cloudflared` package/container with tunnel token | Own UI (SaaS dashboard) + SF status | Token in the vault. Makes a panel reachable with no inbound port |
| **Teleport** | package/container | Own UI (web UI) + SSO | Session recordings volume on a WORM-protected dataset |
| **HashiCorp Boundary** | containers | Own UI | Targets generated from the host inventory |
| **SSH CA** (step-ssh / `ssh-keygen`) | script: CA key in the vault, `TrustedUserCAKeys`, `AuthorizedPrincipalsFile` | CLI-only → SF panel: issue short-lived certs, principals, expiry | Replaces long-lived scan/deploy keys where hosts support it |

### 3.3 Identity and SSO
| Tool | Deploy | GUI tie-back | StorageForge integration |
| :--- | :--- | :--- | :--- |
| **Authentik** | compose (server, worker, PostgreSQL, Redis) | Own UI | Pre-wired OIDC applications for catalog panels, with `sso-link` buttons |
| **Keycloak** | container + PostgreSQL | Own UI | Realm and client templates |
| **Authelia** | container + file/LDAP backend | CLI-only config → SF panel (status) | Forward-auth for the reverse proxy |
| **Kanidm** | package/container | Own UI | Light option for small shops |
| **LLDAP** | container | Own UI | Simple LDAP back end for Authelia and Samba |
| **Samba AD DC / FreeIPA** | package + provisioning script | CLI/own UI (FreeIPA) | Ties to the identity-anomaly work in the MAC panel |

### 3.4 Reverse proxy, TLS and DNS
| Tool | Deploy | GUI tie-back | StorageForge integration |
| :--- | :--- | :--- | :--- |
| **Caddy** | package/container, generated Caddyfile | CLI-only → SF panel (full): sites, upstreams, cert state | One entry per deployed panel, loopback upstream, automatic TLS, optional forward-auth |
| **Traefik** | container with provider labels | Own UI (dashboard) | Docker/Podman label discovery shown as routes |
| **nginx Proxy Manager** | compose | Own UI | Link only |
| **step-ca** (internal CA) | container/package | CLI-only → SF panel: issued certs, expiry | Internal TLS for lab and VPN-only panels |
| **Pi-hole / AdGuard Home** | container | Own UI | Local DNS records generated from the host inventory |
| **Unbound / CoreDNS / dnsmasq** | package + config | CLI-only → SF panel (status) | Split-horizon names for VPN and panels |
| **Chrony with NTS** | package + config | CLI-only → SF panel: offset, sources | Same source the Clock Guard trusts |

### 3.5 Intrusion prevention, detection and scanning
| Tool | Deploy | GUI tie-back | StorageForge integration |
| :--- | :--- | :--- | :--- |
| **CrowdSec** | package + firewall bouncer (nftables) | Own UI (Console, SaaS) + SF panel (status+actions): decisions, alerts, allowlist | Decisions appear in the Quarantine Pool. Bans reconcile with firewall rules |
| **fail2ban** | package + jails | CLI-only → SF panel (status): banned IPs, jails | Same quarantine pool view |
| **Suricata** | package + rules (ET Open) | CLI-only → SF panel (status): alerts via EVE JSON | Alerts feed the SOC Command Center |
| **Zeek** | package | CLI-only | Log feed |
| **Trivy / Grype** | binary/container, scheduled scans | CLI-only → SF panel (full): CVEs per host, image and workload | Findings join the workload index, fixable ones become change plans |
| **OpenSCAP** | package + SCAP content | Report HTML → SF panel | Complements the Lynis and compliance panels |
| **Falco** | package/eBPF driver | Own UI (Falcosidekick UI) + SF panel | Already planned in the ransomware roadmap |
| **Wazuh** | compose/agents | Own UI (dashboard) | Optional fleet-level SIEM link |

### 3.6 Monitoring, logging and alerting
| Tool | Deploy | GUI tie-back | StorageForge integration |
| :--- | :--- | :--- | :--- |
| **Prometheus + node_exporter** | containers + exporters on hosts | Own UI | Targets auto-generated from the host inventory |
| **Grafana** | container | Own UI (`sso-link`) | Provisioned dashboards, including a StorageForge dashboard (pool health, SMART, backup age) |
| **Loki + Promtail/Alloy** | containers/agents | Via Grafana | Audit-log and auditd shipping |
| **Uptime Kuma** | container | Own UI | Monitors generated for every deployed panel |
| **Beszel / Netdata** | container/agent | Own UI | Light alternative to Prometheus |
| **smartd / smartctl_exporter** | package + exporter | SF panel (full): disk health | Hooks into the existing capacity and disk views |
| **ntfy / Gotify / Apprise** | container | Own UI | Notification targets for SOC, backup and update alerts |

### 3.7 Backup and recovery
| Tool | Deploy | GUI tie-back | StorageForge integration |
| :--- | :--- | :--- | :--- |
| **Restic / Borg / Kopia** | package + `systemd` timer script | Kopia has an own UI. Restic and Borg are CLI-only → SF panel (full): repos, last run, size, check status | Fits the existing job and snapshot system, repo creds in the vault |
| **Proxmox Backup Server** | VM template | Own UI | Datastore on a WORM-protected dataset |
| **Restore-test automation** | script: restore to a scratch dataset, hash and compare | SF panel (full): last verified restore | Feeds the 3-2-1 verification already in the index |
| **rclone / rsync jobs** | already in the sync engine | existing panels | None new |

### 3.8 Secrets and certificates
| Tool | Deploy | GUI tie-back | StorageForge integration |
| :--- | :--- | :--- | :--- |
| **OpenBao / Vault** | container/package + init, unseal-key split | Own UI | Optional backend for the key vault. Unseal shares follow the adaptive quorum model |
| **sops + age** | binary + key setup | CLI-only | Used by IaC exports for secrets by reference |
| **Vaultwarden** | container | Own UI | Team password store, link only |

### 3.9 Provisioning and platform
| Tool | Deploy | GUI tie-back | StorageForge integration |
| :--- | :--- | :--- | :--- |
| **Packer** | binary + templates | CLI-only → SF panel: image builds | Builds the golden cloud images that VM templates use |
| **PXE/iPXE/netboot.xyz** | container/package | Own UI (netboot.xyz) | Bare-metal provisioning path |
| **Forgejo / Gitea** | container | Own UI | Git source for compose, Puppet and Terraform |
| **Container registry (Zot/Harbor)** | container | Own UI | Mirror for catalog images, so airgapped installs work |
| **Renovate / image-update watcher** | container | CLI-only → SF panel: pending updates | Feeds the "update image" plan step |
| **Ansible/Puppet/Terraform runners** | binary/packages | CLI-only | Optional external runners for exported artifacts |

### 3.10 Storage-facing apps
Samba, NFS, MinIO/Garage, Nextcloud, Syncthing, Jellyfin. These are catalog entries whose main value is **storage-aware placement**: dataset choice, snapshot/WORM policy, share fencing and canaries wired in at deploy time.

---

## 4. GUI Tie-Back Model

### 4.1 Four levels of integration
1. **Link**: a button to the tool's own UI, built from `gui.native.url_template`. Works for any tool with a web UI. The Report checks the URL is reachable from where the operator is.
2. **SSO link**: when the identity provider is deployed, the plan also registers an OIDC client for the tool and the link signs the operator in. If the tool has no OIDC, put it behind a forward-auth proxy instead.
3. **Status tiles**: a read-only card per tool on the host and Workloads views (version, health, last check, key counts), fed by a small collector adapter that calls the tool's API or CLI JSON over the existing SSH scan. No new agent, no new listeners.
4. **Panel with actions**: for CLI-only tools, StorageForge builds the interface. Actions are staged plan steps with a Report, for example "revoke WireGuard peer", "add Caddy route", "unban IP", "issue SSH certificate", "run restore test".

### 4.2 Tool adapters
A **tool adapter** is a small module with up to five functions: `detect`, `status`, `actions`, `links`, `metrics`. It lets the catalog stay data-only while the GUI remains consistent.
- Adapters are read-only by default. Anything that changes state is exposed as an action that creates a plan step.
- Adapters never store tool credentials in the index. They use vault references and short-lived tokens.
- A failed adapter shows "status unavailable" and never blocks a scan.

### 4.3 Customization
- **Custom dashboards**: tool tiles join the draggable widget grids from the ransomware roadmap's customization model.
- **Custom entries**: a built-in editor with YAML validation, a Report-style dry run and a signing step for the operator's own key.
- **Overrides without forks**: change a port, volume, image tag or exposure through an override layer that survives catalog updates.
- **Bundles** (see §5), **role profiles** (default tool sets per host role, such as `edge`, `nas`, `hypervisor`) and **per-host exclusions**.
- **Deep links**: `/#host=gw-01&tab=toolbox&tool=wireguard`, `…&tool=crowdsec&subtab=decisions`, `…&panel=catalog&category=vpn`.

---

## 5. Bundles

A bundle is an ordered list of catalog entries with shared parameters. It is one plan, one Report, one Apply, with rollback of the whole bundle on failure.

| Bundle | Contents | Result |
| :--- | :--- | :--- |
| **Private access** | WireGuard or Headscale + Caddy + Authelia | Management panels reachable only over the VPN, behind SSO |
| **Hardened homelab** | Private access + CrowdSec + Chrony/NTS + Uptime Kuma + restic | Sensible baseline for a small site |
| **Container host** | Podman rootless + Caddy + Komodo/Dockge + Trivy + Prometheus node_exporter | Managed container host with scanning |
| **Hypervisor** | libvirt + Cockpit + WireGuard + backup (PBS/restic) + smartd | KVM host with remote console over VPN |
| **Observability** | Prometheus + Grafana + Loki + ntfy + smartctl_exporter | Metrics, logs and alerts with StorageForge dashboards |
| **Zero-trust gateway** | Authentik + Pomerium or OpenZiti + step-ca | Identity-aware access to internal apps |
| **Backup & recovery** | restic/Kopia + restore-test + WORM dataset | Verified backups, tied to the Snapshot Vault |

Bundle rules: dependency ordering (identity before the apps that use it), shared generated secrets, a single firewall change set, conflict checks (two tools wanting 443), and a summary of everything that will be exposed.

---

## 6. Security and Safety Rules (apply to every entry)

1. **Pinned and verified**: images by digest, binaries by checksum and signature (cosign or minisign where published). A scheduled check reports available upgrades but never applies them silently.
2. **Least exposure**: the default bind is loopback or the management network. Public exposure is a separate step that also stages the firewall rule and a TLS route.
3. **Least privilege**: rootless where supported, no socket mounts without the socket-proxy option, capabilities dropped, read-only root filesystems where the tool allows it.
4. **MAC and firewall**: each entry declares SELinux/AppArmor expectations and firewall needs, which reuse the workload roadmap's §8 audits. A tool that fails them is shown in the Report before apply.
5. **Secrets**: generated, vaulted, shown once, never in plans, logs or exports.
6. **Data kept on uninstall**: volumes are kept by default. Deleting them uses the destructive gate, and quorum if on a WORM-protected dataset.
7. **Audit**: install, upgrade, config change and removal are written to the hash-chained audit log with the signed plan and Report.
8. **Compliance**: each entry lists the benchmark controls it affects, so the Compliance Center can show "this tool satisfies/needs waiver for X".
9. **Supply-chain checks**: catalog entries are reviewed against the tool's published checksums by a CI job, and image CVE scan results (Trivy) are shown before first deploy.

---

## 7. API & Data Model

### 7.1 Endpoints (`/api/toolbox/...`)
| Method | Endpoint | Description | Guarded |
| :--- | :--- | :--- | :---: |
| `GET` | `/api/toolbox/catalog` | Entries with category, risk labels, GUI level | No |
| `GET` | `/api/toolbox/catalog/{id}` | Full entry and signature status | No |
| `POST` | `/api/toolbox/catalog/validate` | Validate a custom entry (schema, signature, lint) | No |
| `POST` | `/api/toolbox/catalog/sign` | Sign a user entry with the operator key | **Yes** |
| `GET` | `/api/toolbox/installed` | Installed tools per host with status | No |
| `GET` | `/api/toolbox/installed/{host}/{id}/status` | Adapter status tiles, links and metrics | No |
| `POST` | `/api/toolbox/stage` | Stage install/upgrade/remove into a plan | **Yes** |
| `POST` | `/api/toolbox/bundles/stage` | Stage a bundle | **Yes** |
| `GET` | `/api/toolbox/bundles` | Bundles, built-in and user | No |
| `GET` | `/api/toolbox/{host}/{id}/actions` | Adapter actions available | No |
| `POST` | `/api/toolbox/{host}/{id}/actions/{action}` | Stage an adapter action as a plan step | **Yes** |
| `GET` | `/api/toolbox/updates` | Available upgrades and CVE deltas | No |
| `GET` | `/api/toolbox/exposure` | What each tool exposes, and to whom | No |

### 7.2 Tables
- **`toolbox_catalog`**: `id`, `version`, `category`, `spec_yaml`, `signed_by`, `signature_ok`, `user_defined`.
- **`toolbox_installs`**: `id`, `host_name`, `tool_id`, `version`, `method`, `image_digest`, `params_json`, `status`, `installed_plan_id`, `managed_by`.
- **`toolbox_status`**: `install_id`, `checked_at`, `health`, `version_running`, `tiles_json`, `error`.
- **`toolbox_bundles`**: `id`, `name`, `entries_json`, `params_json`, `user_defined`.
- **`toolbox_overrides`**: `host_name`, `tool_id`, `override_yaml`.

---

## 8. Delivery Phases

| Phase | Deliverables | Modules touched | Estimated effort |
| :--- | :--- | :--- | :---: |
| **T1** | **Catalog engine**<br>• Entry schema, signing, validation, override layer<br>• Install methods (Quadlet, compose, package, verified binary)<br>• Risk labels in the Report, uninstall that keeps data | `blueprint.py`<br>`payloads.py`<br>`deploy.py` | **5–6 days** |
| **T2** | **Adapter framework and GUI levels**<br>• `detect/status/actions/links/metrics`<br>• Link, SSO-link, status tiles<br>• Toolbox rail and host cards | `scanner.py`<br>`server.py`<br>`canvas.py` | **5–6 days** |
| **T3** | **Access layer**<br>• WireGuard (with peer manager panel), Headscale, Tailscale, NetBird<br>• Caddy/Traefik with generated routes<br>• Authelia/Authentik SSO wiring | `shares.py`<br>`keyinstall.py`<br>`blueprint.py` | **7–9 days** |
| **T4** | **Defense tools**<br>• CrowdSec + nftables bouncer, fail2ban<br>• Trivy/Grype scanning feeding workload findings<br>• Suricata alert feed to SOC | `alerts.py`<br>`clamav.py`<br>`preflight.py` | **6–7 days** |
| **T5** | **Monitoring and alerting**<br>• Prometheus/Grafana/Loki/Uptime Kuma<br>• ntfy/Apprise targets<br>• smartd/smartctl_exporter panel | `health.py`<br>`alerts.py`<br>`capacity.py` | **5–6 days** |
| **T6** | **Backup tools and restore tests**<br>• restic/Borg/Kopia deploys with panel<br>• Automated restore verification | `backup.py`<br>`jobs.py`<br>`protection.py` | **5–6 days** |
| **T7** | **Zero trust and secrets**<br>• Pomerium/OpenZiti/Cloudflare Tunnel/Teleport<br>• SSH CA panel and short-lived certs<br>• OpenBao with quorum-style unseal | `authkeys.py`<br>`hostkeys.py`<br>`confirm.py` | **7–9 days** |
| **T8** | **Bundles and role profiles**<br>• Bundle planner with ordering, shared secrets and one firewall change set<br>• Built-in bundle library<br>• Custom dashboards for tool tiles | `planner.py`<br>`reports.py` | **4–5 days** |
| **T9 (later)** | **Provisioning and platform**<br>• Packer, PXE, Forgejo, registry mirror for airgap<br>• Image-update watcher, DNS/DHCP panels | TBD | **TBD** |

Dependencies: T1 builds on workload roadmap W3–W6 (runtime install and the panel catalog). T3's firewall integration relies on the ransomware roadmap's Firewall engine, and T4 on its alert/SOC pipeline.

---

## 9. Verification (KVM Lab Gauntlet)

1. **Entry validation**: signed entries load. Tampered, unsigned or digest-mismatched entries are refused with the reason.
2. **Deploy matrix**: every catalog entry installs on Debian, Ubuntu, Fedora, Rocky, Alma, openSUSE and Arch lab VMs (rootless Podman where it is the declared method), passes its health check, and uninstalls leaving data intact.
3. **Report is read-only**: no changes between Report and Apply. A changed plan is refused with 409.
4. **Exposure defaults**: after each install, the exposure audit shows no listener outside loopback or the management network unless the plan staged it.
5. **VPN path**: deploy WireGuard between two lab VMs, confirm peers handshake, the panel shows it, and revoking a peer drops traffic. Then check panels reachable only over the tunnel.
6. **SSO**: deploy Authentik plus Caddy plus one panel. The `sso-link` signs in, and a direct hit to the panel's port from another host fails.
7. **CrowdSec/fail2ban**: simulate SSH brute force, confirm the ban appears in the Quarantine Pool and in nftables, and unban from the GUI.
8. **Trivy**: scan a deliberately vulnerable image and confirm the finding reaches the workload view and produces a fixable plan.
9. **Backup**: restic backup, then the restore test passes. Corrupt the repository and confirm the test fails loudly.
10. **Bundles**: "Private access" deploys in dependency order. A forced failure in step 3 rolls the whole bundle back.
11. **Exports**: each tool's plan exports to Terraform, Puppet and Ansible, and the exported run gives the same state as the Bash apply.
12. **Adapters**: stopping a tool shows "unavailable" in the panel and never breaks a scan.

---

## 10. Open Questions

1. **Which tools first?** Proposed order: WireGuard, Caddy, CrowdSec, Trivy, restic, Prometheus/Grafana.
2. **Own panel vs link**: for tools that already have a good UI (Authentik, Grafana), is the SSO link plus status tiles enough?
3. **Catalog hosting**: ship entries in the repo, or fetch updates from a signed remote index (with an airgap mirror option)?
4. **Windows and macOS clients**: generate VPN client configs and installers for them, or Linux peers only?
5. **Licensing review**: some tools (Teleport, Vault, Boundary) have source-available licences. Include them as entries, or prefer OpenBao-style forks?
6. **Scope of SIEM**: link to Wazuh/Graylog only, or build a minimal alert viewer for Suricata and Falco in the SOC panel?
