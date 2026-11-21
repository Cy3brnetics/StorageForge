# Toolbox

The Toolbox installs common tools on managed hosts from a catalog of signed entries, and shows each one at the level it supports: a link to its own UI, status tiles, or a panel with actions. An install, a removal and every action is a change plan, checked against the index, reported first and run when the plan is deployed, like any other plan. This page covers the engine that came in 0.5.12 and its first three entries. All of it is built, not lab-tested: lab tier 29 (`tests/lab/tiers_toolbox.py`, see [KVM lab](kvm-lab.md)) is written and has not run, and every entry says *not lab-tested* in the catalog until a tier run passes for it.

What is here:

- [The catalog](#the-catalog): what an entry is, and the three that ship with 0.5.12.
- [Signatures and trust](#signatures-and-trust): the release key, operator keys, unsigned entries, and catalog updates.
- [Installing](#installing): methods in order of safety, exposure, overrides, risk labels, and what the step checks when it runs.
- [Removing](#removing): the program goes, the data stays.
- [Adapters and GUI levels](#adapters-and-gui-levels): status, actions, links, and the WireGuard peer manager.
- [Custom entries](#custom-entries): the editor, the dry run, and signing on your own machine.
- [The view and the API](#the-view-and-the-api).
- [What the signature protects](#what-the-signature-protects), and what it does not.
- [Not built yet](#not-built-yet).

## The catalog

An entry is a YAML file, data and never code. It says how the tool can be installed, what it needs, how it is exposed by default, where its data is, how to reach its UI and which adapter reads its status:

```yaml
format: 1
id: uptime-kuma
revision: 1                 # raised with every change to the entry
name: Uptime Kuma
app_version: 2.0.2
category: monitoring
summary: Watches websites, ports and services and says when one goes down.
install:
  methods:
    - kind: container       # rootless Podman, under an account of its own
      image: docker.io/louislam/uptime-kuma:2.0.2@sha256:4c364ef9...
      ports: ["3001:3001/tcp"]
      volumes: {data: /app/data}
requires: {ports: [3001/tcp], volumes: [data]}
exposure: {default: loopback, behind: reverse-proxy}
health: {url: http://127.0.0.1:3001/, expect: 200}
backup: {paths: [data], consistency: stop-snapshot}
gui:
  native: {url_template: "http://{host}:{port}/", port: 3001}
  panel: {level: status, adapter: uptime-kuma}
risk: [holds-credentials]
```

The schema refuses what an entry may not ask for: an image that is not pinned by digest, a privileged container, the Docker socket, devices, host PID or IPC, a capability outside a short list (`NET_BIND_SERVICE`, `NET_ADMIN`, `NET_RAW`, `CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`, `FOWNER`, `KILL`), an environment value that looks like a secret (declare it under `secrets`, and it reaches the container as a file), a `%` in a value (systemd would expand it), a port with an address in it (the exposure decides the address), a health check anywhere but loopback, a binary without its SHA-256, an adapter this version does not have, and any field it does not know. Beside its install, an entry may add three named step kinds (`wg-interface`, `wg-peer` and `unit-state`, which refuses SSH, the network and the firewall), with values from its `inputs`, and each is checked as any plan step is. The list is short on purpose: each kind is a way an entry reaches a host.

The three entries of 0.5.12, which exercise the engine end to end:

| Entry | Method | Exposure | Shown as |
| :--- | :--- | :--- | :--- |
| **WireGuard** | `wireguard-tools` from the distribution, then a `wg-interface` step with the interface, address and port you give. The key is made on the host and never leaves it | any: a VPN listens to be reached | full: the peer manager |
| **Cockpit** | `cockpit` from the distribution, `cockpit.socket` enabled, and bound to the exposure's address with a drop-in (`/etc/systemd/system/cockpit.socket.d/storageforge-listen.conf`) | loopback | status and actions |
| **Uptime Kuma** | A rootless container (also a container of root's Podman, or a compose stack), from image 2.0.2 pinned by digest, its data in `/srv/toolbox/uptime-kuma/data` | loopback | status |

The rest of the catalog comes with 0.5.13.

## Signatures and trust

Each entry in the catalog carries one of these, shown beside it on the page and in the report:

| Trust | What it means |
| :--- | :--- |
| **release-signed** | The official catalog, with the release key's signature over its manifest (`catalog/catalog.json`, the SHA-256 of each entry, and a serial) |
| **packaged** | The official catalog as it came in the package, with no release signature: there is no release key in `catalog/release_signers` yet, so it is as trusted as the code it came with, and says so |
| **operator-signed** | A custom entry signed with one of the operator keys under *Operator keys* |
| **unsigned** | A custom entry with no signature. It can be staged only by someone who may run commands as root, who accepts it for one host behind a fresh password; the page and the report say so |
| **refused** | A file that is not the one the manifest lists, a manifest the release key did not sign (once a release key is in the package), a custom entry whose signature does not match its text, or a signer that was removed. A refused entry is not offered, and a plan staged from it is refused on the host |

Every read checks again, so an entry changed in the database or in the package is refused, not run.

**The release key** signs the official catalog: `python -m storageforge_index.toolbox manifest SERIAL` writes `catalog.json` for the YAML files, and its holder signs it with `ssh-keygen -Y sign -f <release key> -n storageforge-catalog catalog.json`, which writes `catalog.json.sig`. The controller verifies it with `ssh-keygen -Y verify` against `catalog/release_signers`, which ships in the package and cannot be changed through the web app. Until the owner adds the release key's public half there, the packaged catalog is labelled *packaged*.

**A catalog update** (`POST /api/toolbox/catalog/update`, with the manifest, its signature and the entries) is taken only when the release key signed the manifest and its serial is higher than the one in use, so an older catalog cannot be put back. With no release key in the package, no update can be taken. The controller fetches nothing: the update is a file someone brings to it.

**Operator keys** sign custom entries. Only the public half is kept on the controller (*Operator keys*, or `POST /api/toolbox/signers`); the entry is signed on the operator's machine, and the controller only verifies the signature it is given. Adding or removing a key takes `hosts.command` and a fresh password, and removing one makes the entries it signed refused until they are signed again.

## Installing

Open a tool from the catalog or from a host's card, choose the host at the top, and use **Show the plan and its report**, then **Save as a change plan**. Deploying that plan, from **Changes**, is what changes the host, report first.

**Methods, safest first.** The engine takes the safest method the host can take now, or the one you ask for, and the report says which and why:

1. **container**: rootless Podman. The step makes an account for the tool (`sf-<tool>`, no shell, home in `/var/lib/storageforge-tools/<tool>`), gives it subordinate ids, lets it linger, writes a Quadlet unit in its home and starts it. Its folders under `/srv/toolbox/<tool>` belong to that account. Podman 4.4 or later.
2. **package**: the distribution's packages, from the sources the host already has; no source is added. Units are enabled, and a socket is bound to the exposure's address.
3. **binary**: downloaded over HTTPS on the host, and installed in `/usr/local/bin` only when its SHA-256 is the entry's.
4. **quadlet**: the same unit run by root's Podman, from `/etc/containers/systemd`.
5. **compose**: a compose stack made from the entry's fields, through the [`stack` step](workloads.md#compose-stacks-lxc-containers-and-incus-instances), kept in `/srv/toolbox/<tool>/compose`.

A host whose last scan saw no Podman gets a `runtime-install` step before the install when only container methods fit, and the report says Podman is installed first. TrueNAS and XCP-ng are refused, as for every deploy.

**Exposure.** *loopback* (127.0.0.1: reach it through SSH, `ssh -L 3001:127.0.0.1:3001 host`, which the page shows, or through a reverse proxy), *management* (one address of the host, which you give) or *any* (every network the host is on, which the report warns about and labels *listens on the internet*). *Only these may reach it* adds a fence on input for a rootless container; a container of root's Podman publishes past the host firewall, so the report asks for one address instead.

**Overrides** change one tool on one host without forking its entry: `ports` (`{container-port: host-port}`), `bind`, `exposure`, `volumes` (`{name: /host/folder}`, never a system folder), `method`, and `image` (pinned by digest, and only with `hosts.command`, since it runs other code). They are kept apart from the entry (`toolbox_overrides`), so a catalog update leaves them, and the report lists each one in force.

**Risk labels**, each with what it means and what lessens it, in the catalog and in the report: *mounts the Docker socket*, *privileged*, *host network*, *publishes 80/443*, *runs as root* (every method but the rootless container), *holds credentials*, *listens on the internet*, *changes the network*.

**What the step checks when it runs.** The `tool-install` step holds the tool, the method, the SHA-256 of the entry it was staged from, the SHA-256 of the override, and the exposure. The image, the unit, the packages and the binary are taken from the catalog when the plan's script is written, and only from an entry that is still trusted, is still the one staged, with the same override, and (for an unsigned entry) was accepted for that host. Otherwise the host gets a conflict that says why, and nothing is done. A plan edited by hand to point at another image or package list has nothing to carry it. The plan's report is the same check, before anything changes.

## Removing

**Remove from host, keeping its data** saves a `tool-remove` plan. It stops the tool and takes away what its install made, from the install's record: the Quadlet unit, the compose stack (`down`, without its volumes), the packages (removed, not purged: configuration files stay), the drop-in, or the binary. The data folders stay, and the report and the confirmation list them. The tool's account stays too, with its images (`userdel -r sf-<tool>` takes them away).

Moving the data to the host's trash is a step of its own, `tool-data-remove`: destructive, so the tool's name is typed again and it runs only with `--apply --destructive`. It moves each folder into the host's one `.storageforge-trash`; nothing is deleted.

## Adapters and GUI levels

Each entry is shown at one level: **link** (its own UI, opened in a new tab), **sso-link**, **status** (read-only tiles: health, version, last reading, a few counts), **status+actions**, or **full** (a panel StorageForge builds for a tool with no UI of its own).

An **adapter** reads one tool, with up to five parts, all read-only: *detect* (is it there, installed by StorageForge or found), *status* (health, version, tiles), *actions*, *links* and *metrics*. Adapters read the infrastructure reading, the signed read-only run every host with deploy access gets; the probes they add are in the code (`tbadapters.py`) and only read unit states and version lines, and the loopback health checks of the tools installed on the host are added to the same run (the status code only). A tool whose entry names a [platform connection](api-connections.md) kind (`gui.panel.api`) is read through that connection instead, with that kind's permission guide; its token stays in the vault. An adapter that fails says **status unavailable**, and the reading, the scan and the other tools go on.

An **action** is never done by the adapter: it becomes ordinary plan steps, saved as a plan and deployed with its report. Cockpit's restart and stop are `unit-state` steps.

**The WireGuard peer manager** lists each interface and its peers, with their addresses, endpoints and the age of their last handshake, and how many are connected (a handshake in the last three minutes). Its actions are `wg-peer` steps (add a peer by its public key, revoke one) and `wg-rotate` steps (make the next key of an interface, switch to it). A private key is never made, sent or shown: a new peer makes its own key pair and gives you its public key.

**Links** follow the exposure: on loopback the link is to this machine's end of an SSH tunnel, with the command to open it; on the management network, to the address it is bound to. **sso-link** needs an identity provider from the catalog, which comes with 0.5.13: until one is installed, an entry that supports single sign-on gets a plain link, and the page says so.

## Custom entries

Under **Custom entries** in the Toolbox panel: write or paste an entry, **Check it** (the schema, the risk labels, the SHA-256 of the text, and whether a signature you pasted matches), **Dry run on the host** (the plan and its report, saving nothing), and **Save the entry**. A custom entry is root on the host by another name, so saving, signing, removing and staging one take `hosts.command`.

To sign it, save the text exactly as checked (the page offers it as a file), and on your own machine run the command it shows:

```sh
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n storageforge-catalog my-tool.yaml    # writes my-tool.yaml.sig
```

Paste the signature with the entry, or later through `POST /api/toolbox/catalog/sign`. The controller checks it against the operator keys and keeps it; it never signs anything itself. A custom entry cannot take the name of an official one: change ports, volumes or exposure with an override instead.

## The view and the API

**Toolbox** in the rail has a card for each host with the tools on it and their health, the catalog by category, one tool at a time, *Custom entries* and *Operator keys*. A deep link opens a tool on its host: `/#host=gw-01&tab=toolbox&tool=wireguard`, which the page tidies into `/#/topo/toolbox?host=gw-01&tool=wireguard`. A cancelled dialog sends nothing and leaves the page as it was.

The routes are under `/api/toolbox/` (catalog, validate, custom, sign, update, signers, installed, status, preview, stage, actions, overrides, updates, exposure): see [API reference](api-reference.md). Reads take `workloads.view`, and exposure `security.view`. Staging takes `plans.edit` and saves a plan; deploying it asks for the password again. Every write is in the audit log (`toolbox.*`).

**Updates** lists installs whose entry has a newer revision in the catalog, or whose entry is no longer trusted; an update is staged as an install again, and its report shows what changes. **Exposure** compares what each tool was staged to listen on with the addresses the last reading saw it listen on.

## What the signature protects

The catalog's signature decides which entries are offered without a warning, and a tool step runs only from an entry that is trusted at the moment its plan's script is written. What each case can make a host run:

**A malicious catalog update.** Without the release key's signature it is refused, whoever uploads it, and so is an older catalog signed by the key (the serial only goes up). An entry changed in the package or the database after it was signed is refused at every read. With the release key's signature, an update is as trusted as a release: then what its entries can make a host run is bounded by the step kinds they become, not by the signature. An image pinned by digest, run rootless where the entry has that method and never privileged, with no socket, no devices and a short list of capabilities; packages by name from the sources the host already has; a binary by its SHA-256 into `/usr/local/bin`; a few named step kinds with checked values; a Quadlet or compose file that StorageForge writes from those fields. A package or a binary runs as root, as does a container of root's Podman, and the report labels each *runs as root*. Nothing reaches a host until a person with `deploy.apply` deploys the plan after its report, behind a fresh password, and the plan is in the audit log.

**A taken-over web app** (someone with an admin's session and password, or with code running in the controller). With an admin's session it can add an operator key and sign entries with it, or accept an unsigned entry for a host: each takes `hosts.command` and a fresh password, and each is in the audit log, so it is no more than what the same account can already do with a raw command block or a change plan. It cannot forge the release key's signature, take an older catalog back, or change `catalog/release_signers`, which is in the package. With code running in the controller and the vault unlocked, it holds the deploy signing key and can run anything on enrolled hosts with or without the Toolbox: the catalog's signature does not change that, and is not meant to. What it does change is that a catalog entry, a database row or a staged plan altered behind StorageForge's back is refused rather than run.

**What it does not protect.** A compromised upstream image or package behind a digest or a name the release key signed; the sources a host already has; an operator key whose private half was stolen (remove it, and its entries are refused); an admin who accepts an unsigned entry.

## Not built yet

- **Bundles, role profiles and per-host exclusions, custom dashboards, feeds** (Trivy findings and CrowdSec decisions), and the `toolbox_bundles` table: 0.5.13, with the rest of the catalog.
- **sso-link** with a registered OIDC client: needs an identity provider entry (0.5.13). Until then it is a plain link.
- **CVE deltas** in updates: need the Trivy entry (0.5.13).
- **Image CVE scans before the first deploy** and the CI job that checks entries against published checksums.
- **QR codes** for WireGuard peer configurations.
- **Binaries in archives**: a binary method downloads the program itself; nothing is unpacked. Publisher signatures (cosign, minisign) beyond the SHA-256 the signed entry pins are not checked.
- **The release key**: the owner adds its public half to `catalog/release_signers` and signs `catalog/catalog.json`. Until then the official catalog is labelled *packaged*, and no catalog update can be taken.
