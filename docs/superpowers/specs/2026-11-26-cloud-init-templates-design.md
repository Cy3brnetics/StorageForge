# Cloud-init templates: one renderer, many deliveries

Date: 2026-11-26. The spec for [roadmap-0.7.0.md](../../../roadmap-0.7.0.md), section 0.6.10, items CT-01 to CT-14. Line numbers are
from HEAD `5552ba8`, as committed.

## Intent

The owner's words, 2026-11-26: "a cloud-init config manager so users can make simple templates for vms across all systems beyond what
speced".

A person makes a template once on the Workloads page: users, packages, files, commands, the network and so on. Then they name it in
any VM step, on any system StorageForge makes VMs on. The controller renders the cloud-init files once, and each system's step only
delivers them. Today every writer hands out one login account and one SSH key, and each writer does it its own way.

The owner's decisions, which this spec takes as given:

- The editor lives on the Workloads page, beside the VM steps.
- A template has plain fields, plus a checked *extra* block of raw cloud-config for what the fields do not cover.
- A template holds no secret. A password or a file's secret contents name a vault secret.
- What StorageForge makes on a host keeps working with the controller gone. No `phone_home`, and nothing on a host calls back.
- A plan made before templates existed renders today's login-only config. That config becomes the built-in template *Login only*.

"Beyond what speced" means the whole CT list is in scope for 0.6.10. Nothing in it is moved past 1.0 by this spec. Where a part needs
a security decision (CT-04, CT-09), the spec designs it and the major checkpoint decides. The feature freeze is at 0.8.0, so anything
new that this spec leaves out goes on the post-1.0 list at the end.

## Goals

- One module, `cloudinit.py`, renders user-data, meta-data, vendor-data and network-config from a template and a VM's values.
- The four writers that exist today become its callers. A plan with no template gives the same files as before, proven by golden
  files taken from HEAD.
- Templates are versioned. A saved plan pins one version and its hash, so editing a template never changes what an approved plan
  deploys.
- Delivery on libvirt, Proxmox VE, Incus, the OS install, host migration, Xen Orchestra and TrueNAS, and in the Terraform, OpenTofu,
  Ansible and Bash exports. Where a system cannot carry a field, the check says which field and why.
- Secrets come from the vault by name and never appear in a template, a plan, a script, an export, a log or an audit row.
- No template byte is ever placed into Bash text. It reaches the script as one base64 word.

## Non-goals

- `phone_home`, `reporting` webhooks, or anything on a host that calls the controller, now or later.
- Re-applying a template to a VM that exists. cloud-init runs once per instance. Later changes are ordinary plan steps.
- Windows (cloudbase-init), Ignition and Butane, Kickstart, autoinstall and answer files. The unattended ISO install stays deferred, as
  the [Workloads spec](2026-11-25-workloads-page-design.md#non-goals) says.
- Templates for VMs made from an ISO (`vm-iso`, `pve-vm` with source `iso`), plain LXC and `pve-ct`. None of them runs cloud-init
  through these steps.
- A delivered vendor-data file. The renderer returns the slot, and it stays empty.
- Any change to the secure channels, the enclave or the signed deploy run (rule 5, and the owner's 0.6.9 decision).

## Anti-goals (would make it a failure even if it works)

- An approved plan that deploys something else because a template or a vault key changed after it was saved.
- A template byte inside a `printf` format, a heredoc or a command line on the host.
- A blank YAML page as the main editor.
- A system that drops a template field without saying so.
- A second copy of a step's form. The wizard and Changes render the same field specs.

## What exists (HEAD `5552ba8`)

### The four writers

| Writer | What it writes | Where |
| :-- | :-- | :-- |
| `vm-create` (libvirt) | A `printf` of JSON into `user-data` and `meta-data`, then an ISO with volume id `cidata`, attached read-only on SATA | `steps_vm.py:198-223` |
| `os-install` | `90_storageforge.cfg` with `datasource_list: [NoCloud, None]`, then `meta-data`, `user-data` and `network-config` in `/var/lib/cloud/seed/nocloud` of the new root | `steps_osinstall.py:311`, `:325-345` |
| `pve-vm` | No file. `qm set --ide2 STORE:cloudinit --ciuser U --ipconfig0 ip=dhcp --serial0 socket --vga serial0`, then `--sshkeys` from a temporary file | `steps_proxmox.py:212-216` |
| Terraform export | `json.dumps` of hostname, `ssh_pwauth` and one user, in `libvirt_cloudinit_disk.user_data` | `wlexport.py:217-218` |

The details matter for the byte-for-byte proof.

- `vm-create`:
  - The comment at `steps_vm.py:198` says it: "JSON is YAML too". Every value passed the field checks, which allow no quote or
    backslash (`steps_vm.py:13-14`).
  - The packages list is joined with `IFS=,` (`steps_vm.py:206`). Alpine with `sudo=nopasswd` and the guest agent therefore writes
    `["sudo","qemu-guest-agent"]` with no space after the comma. The rest of the document has `", "` and `": "`.
  - The login is not locked. Its `hashed_passwd` is `$6$` and random characters from the host's `/dev/urandom`
    (`steps_vm.py:210-213`). OpenSSH without PAM, as on Alpine, refuses a key for a locked account (comment at `steps_vm.py:208-209`).
  - `meta-data` is `instance-id: sf-NAME-$STAMP` (`steps_vm.py:214`).
  - The seed is `$dir/$name-seed.iso` in the pool folder (`steps_vm.py:173`). It is written with the script's umask, which is probably
    0644. That is not proven.
- `os-install`:
  - Its user is locked (`lock_passwd: true`), with `shell: /bin/bash`, `preserve_hostname: false` and `growpart: {mode: off}`
    (`steps_osinstall.py:327`). Its images leave out Alpine (`steps_osinstall.py:48`).
  - `meta-data` is `instance-id: NAME-<epoch>`, with no `sf-` prefix (`steps_osinstall.py:326`).
  - Host facts are read and written on the host only: the SSH host private keys when `host_keys=same` (`:330-334`), the data mounts
    when `carry=mount` (`:336`), and the network for `network=same|fixed` (`:339-345`). The network options are `same`, `fixed` and
    `dhcp` (`steps_osinstall.py:65`). `fixed` means the host's current address, read on the host at run time by `sf_os_network`, so
    the controller never holds an address for this step.
  - `user-data` is chmod 0600 after it is written (`:338`). The folder is 0700 (`:325`).
- `pve-vm`:
  - The login fields are `user` (kind `name`, which allows `:` and `+`) and `ssh_key` (`steps_proxmox.py:477`).
  - The undo is `pve_vm_undo` (`steps_proxmox.py:178-185`).
- The Terraform export:
  - It always writes `sudo: ALL=(ALL) NOPASSWD:ALL` (`wlexport.py:217`). It never reads `p['sudo']` (`wlexport.py:96-98`), so a
    `sudo=none` step exports with passwordless sudo.
  - It writes no `hashed_passwd` and no `lock_passwd`, so cloud-init locks the account and an Alpine VM refuses the key.
  - It drops the guest agent package and its `runcmd`, and Alpine's `sudo` package (`steps_vm.py:201-207`).
  - `wlexport.py` has no `pve-vm` in `KINDS` (`wlexport.py:23`) and no Proxmox provider block.
  - `_refs` rewrites every `"@@ref X"` in the output into a bare reference (`wlexport.py:27-31`, called on the whole file at `:207`).
  - The roadmap has no item for these drifts. The fix (sudo, `lock_passwd` and the packages) is folded into CT-10, the exports item,
    as its own first commit **CT-10a** under rule 3, made early in the commit order so the Terraform golden is fixed before CT-01b.

### Incus, Xen Orchestra and TrueNAS

- **Incus** refuses the `user.*` keys cloud-init reads as labels. `RESERVED_INCUS` (`steps_workloads.py:38`) is checked by
  `_labels_check` (`:597`), called from the incus check (`:732`). The step has no login fields (`INCUS_ARGS`, `steps_workloads.py:43`).
  It already has an `args_of` hook, `_incus_extra` (`:793`). The script prints its full argv with
  `info "incus init $image $name ${args[*]}"` (`:265`) before `incus init` (`:267`).
- **Xen Orchestra** is read through its REST API at `/rest/v0` with a cookie (`apiconn.py:57`, `apixo.py:1-12`). It is not the JSON-RPC
  API whose method is `vm.create`. The guide offers two actions, `snapshot` and `power` (`apixo.py:52-54`).
- **TrueNAS** is read with a READONLY_ADMIN key (`apitruenas.py:59-60`). It offers one action, `snapshot` (`apitruenas.py:66-68`).
  StorageForge makes no VM on it.
- **No code writes through an API connection today.** `request()` and `call()` refuse every non-read unless an action is turned on
  (`apiconn.py:587`, `:812`). `set_actions` only stores the names (`apiconn.py:409-421`). Nothing in the package passes `action=`.

### What the design builds on

- **VM specs** are the model for pinning. "A step names a spec and its empty fields are filled from it when the plan is saved, so a
  saved plan says everything it does" (`steps_vm.py:8-11`). `expand()` (`steps_vm.py:338-353`) runs from `changes.PREPARE`
  (`steps_vm.py:447`, `changes.py:51-57`). The built-in specs are read-only (`steps_vm.py:102-109`). Your own sit in settings, at most
  200 (`steps_vm.py:301-335`).
- **`changes.prepare` runs in three places only:** `save_plan` (`changes.py:1014`), the check route (`server.py:2171`) and
  `osoffer.py:167`. `script()` (`changes.py:1145`) normalizes and checks, but never prepares.
- **Added fields keep old hashes.** `added=True` drops an empty field from `plan_hash` (`changes.py:75`, `_hashed` at `:977-983`), so
  the deploy's "ran" mark holds (`_ran_at`, `:986-990`). `guest_agent` is the precedent (`steps_vm.py:93`).
- **`args_of`** returns more words for a step's Bash function, worked out when the script is written (`changes.py:60-66`). `script()`
  appends them (`:1159-1160`). A step with `args_of` gets `ansible_of(task, conn)` (`:1906`). Every word is shlex-quoted.
- **Field checks.** `CHECKS` is a table of regexes (`changes.py:202-215`), matched in `normalize` (`:335-370`). A rule across fields
  goes in `VALIDATE`. `words_of` (`:317-320`) gives an absent field as an empty word. `shell_task`, `ansible_head` and `bash_fn`
  (`:300-333`) build the Ansible task, which carries the whole function.
- **Design versions** keep whole immutable JSON rows with limits (`design_versions.py:18-22`) and compare them in plain sentences
  (`compare`, `:243-271`). `_make_room` drops the oldest automatic version (`:88-97`). Templates do not copy that part.
- **Migrations.** The newest is `077_docker_settings.sql` in both `migrations/sqlite` and `migrations/postgres`. 0.6.5 to 0.6.9 may add
  more first, so CT-02 takes the next free number when it is committed.
- **Secrets.** `plan_secrets` finds a plan's secrets only from step fields of kind `secret`, or a field named `secret`
  (`secret_fields` and `plan_secrets`, `secretstore.py:202-226`). `stream()` releases each one for this host and this step kind
  (`:249-278`). A report carries none (`items_data`, `:281-287`). On the host, `sf_secrets_in` writes each to
  `/run/storageforge/secrets/NAME` under umask 077 and never removes it (`:291-313`). The values are never on a command line, in a plan,
  a script, a playbook, an export, deploy_runs output, a log line or an audit row, and the tests search all of those (`:14-16`).
- **Permissions.** `hosts.command` is "raw commands, which run as root" (`permissions.py:29`). A body-dependent check already exists:
  a command schedule calls `need('hosts.command')` (`routes_scheduler.py:34`). A Toolbox custom entry needs it because it "is root on
  the host by another name" (`permissions.py:137`). Every READ under `/api/workloads` maps to `workloads.view` (`permissions.py:133`).
- **The Proxmox node reading** already holds each storage's content types, parsed from `storage.cfg` (`inframeasure.py:101` into
  `pvenode.parse_node`, `pvenode.py:39-62`).
- **Host migration's first boot is `vm-create`.** `vm clone` builds a vm-create step with `steps_vm.image_for` and takes `--set k=v`
  (`cli.py:831-845`).
- **Dependencies** are cryptography, flask, flask-login, flask-limiter, pyyaml and waitress (`pyproject.toml:11`). There is no ISO
  writer and no sha512-crypt in them. Python's `crypt` module is gone in 3.13. hypothesis and shellcheck-py are test extras
  (`pyproject.toml:15`).

## The template

### What a template is

A named list of plain fields with a version number. The body is JSON, schema 1. Every field is checked the way a plan field is: with
an existing `CHECKS` kind, or with a new anchored regex, never free text where a word will do.

| Field | Shape and limit | Check |
| :-- | :-- | :-- |
| `note` | One line, at most 200 characters | `CHECKS['text']` |
| `hostname` | A pattern, default `{name}`, using only `{name}`, `{domain}` and declared parameters | After filling, a new `HOSTNAME` rule: RFC 1123 labels `[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?` joined by `.`, at most 253 characters. Never `HOST_RE` (below) |
| `users` | At most 16 | See below |
| `packages` | At most 200 names | `[A-Za-z0-9][A-Za-z0-9.+_:-]{0,99}` |
| `package_update`, `package_upgrade` | Yes or no. Defaults: update on, upgrade off | |
| `timezone` | `Area/City`, `UTC` or empty (the image's own) | `[A-Za-z0-9_+/-]{1,64}` |
| `locale` | Such as `en_GB.UTF-8` or `C.UTF-8`, or empty | `[A-Za-z0-9_.@-]{1,32}` |
| `ntp_servers` | At most 8 | `@` refused, then `HOST_RE` |
| `write_files` | At most 32 | See below |
| `runcmd` (first boot) | At most 32 commands | Each a list of words |
| `bootcmd` (every boot, early) | At most 32 commands | Each a list of words |
| `mounts` | At most 16: device, mount point, filesystem, options | `CHECKS['spec']`, `path`, `MOUNT_FS` (`changes.py:35`), `options` |
| `swap` | A size and a path (default `/swap.img`), or empty | `CHECKS['size']`, `path` |
| `growpart` | Yes or no, default yes | |
| `network` | `image` (leave it, the default: no network-config), `dhcp`, or `static` | See below |
| `power_state` | `none`, `poweroff` or `reboot`, a delay in minutes and a message of at most 200 characters | |
| `params` | At most 16 | See below |
| `extra` | Raw cloud-config, at most 32 KiB | See *The extra block* |

`HOST_RE` is `tasks.HOST_RE` (`tasks.py:31`, imported at `changes.py:29`), a plan's host-address rule. It accepts `user@`, `:`, `[`,
`]` and `_`, so `root@web-01` or `[::1]` would pass it. It is used only for NTP servers, after `@` is refused, and never for a host
name.

User and group names use a new check `username`, `[A-Za-z_][A-Za-z0-9_.-]{0,31}`: `CHECKS['user']` (`changes.py:204`) without its
numeric branch `\d{1,10}`, which suits a chown owner but not a cloud-init user or group. It is the rule `sshcerts.USER_NAME` already
holds (`sshcerts.py:40`).

A user has:

- `name`: `username`. It must differ from every other user in the template.
- `gecos`: at most 200 characters, no line break.
- `shell`: empty (the image's default), `/bin/bash` or `/bin/sh`.
- `groups`: at most 16 names, each `username`.
- `sudo`: `none` (the default), `nopasswd`, or `password`. `password` needs `password_secret`.
- `ssh_keys`: at most 8. Each is `{vault_key: NAME}` (a vault key's public half, by name) or `{pubkey: ...}` (`CHECKS['pubkey']`,
  `steps_vm.py:66-67`).
- `password_secret`: empty (no password), or a vault secret name (`CHECKS['secret']`, `secretstore.NAME` at `secretstore.py:33`).

A file to write has:

- `path`: `CHECKS['path']`. Refused: `/etc/shadow`, `/etc/gshadow`, `/etc/passwd`, `/etc/sudoers`, anything under `/root/.ssh`,
  `/home/*/.ssh/authorized_keys`, `/var/lib/cloud` and `/etc/cloud`.
- `owner`: `user:group`, each part `CHECKS['user']`.
- `mode`: `CHECKS['mode']`, default `0644`. It is always rendered as a string.
- Either `content` (text, at most 16 KiB, UTF-8, no NUL) or `content_secret` (a vault secret name). A secret file is rendered with mode
  0600 whatever mode is set. A vault step secret is one line of at most 4096 characters (`vault secret-add` refuses anything else,
  `cli.py:1373`), so a secret file's contents are one line: a token, a password, a key in one line. See *File secrets* for the
  trailing newline and for multi-line files.
- `append` and `defer` (written after the users are made): yes or no.

A command is a list of words, never a line of shell. At most 64 words, each at most 1024 characters, with no NUL and no line break. The
editor splits a pasted line into words and shows them to confirm.

The network, when `static`, has at most 4 interfaces. Each has:

- `match`: a name or a name glob (`enp*`), or a MAC.
- `addresses`: CIDRs, which may be parameters.
- `gateway4` and `gateway6`.
- `dns`: at most 3. `search`: at most 6.

It is rendered as network-config version 2. `dhcp` is DHCP on the first card that matches `en*` or `eth*`.

A parameter has:

- `name`: `[a-z][a-z0-9_]{0,31}`. `name` (the VM's name) and `domain` always exist and need no declaring.
- `label`: at most 80 characters.
- `kind`: one of the existing `CHECKS` kinds that fit a value (`text`, `number`, `path`, `label`), or a new `hostname` (the `HOSTNAME`
  rule above, not `CHECKS['host']`), `username`, `cidr` or `ip`, or a choice of up to 20 options. The kind is only the first check:
  see *Values* for the checks run again on the filled document.
- `default`, and `required`: yes or no.

Parameters are filled in `hostname`, `write_files` paths and contents, network addresses, gateways and DNS, and `mounts`. They are
never filled inside a command or the extra block. Filling uses `re.sub` over the fixed set of `{word}` names, never `str.format`:
`str.format` on a stored pattern would let `{name.__class__.__init__.__globals__}` walk Python objects. A `{word}` that is not declared
is refused at save, with "Declare address as a parameter?" in the editor.

### Limits

- A template body: at most 64 KiB of canonical JSON.
- The rendered user-data and network-config: at most 64 KiB together. The reason is the Ansible export: a step's whole function goes
  into one `ansible.builtin.shell` `cmd` (`changes.shell_task`), which Ansible runs as `/bin/bash -c CMD`, one argv string that the
  kernel caps at 128 KiB (`MAX_ARG_STRLEN`, as `sshcerts.py:38` notes). 64 KiB of files is about 87 KiB of base64, and the vm-create
  function adds about 11 KB, which leaves room under 120 KiB. A test renders the largest template the limits allow and asserts that
  its vm-create Ansible `cmd`, and the Incus one with its instance YAML word, are each under 120 KiB.
- At most 200 templates and 100 versions per template.
- The name: `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, the secret name rule (`secretstore.py:33`), unique without regard to case. It never
  holds `@` or `:`, which the step field uses. `login-only` is reserved.

### The extra block

The extra block takes cloud-config keys the fields do not cover. It is read with the PyYAML the controller already imports
(`steps_workloads.py:30`), in this order. Each refusal names the key and the reason.

1. **Size and form.** At most 32 KiB, UTF-8, no NUL. The first line is `#cloud-config` or nothing. Refused: `#include`,
   `#cloud-config-archive`, `#!`, `Content-Type` (MIME) and `## template: jinja`. Each fetches, runs or templates outside the renderer.
2. **Events before nodes.** `yaml.parse()` is walked first. Any alias, any anchor, any tag outside the default resolvers, and the `<<`
   merge key are refused. This blocks billion-laughs: `safe_load` shares aliased nodes, but `json.dumps` in the renderer would expand
   them. It also blocks `!!binary`, `!!set`, `!!timestamp` and `!!python/*`.
3. **Composing.** A `SafeLoader` subclass refuses duplicate keys (PyYAML keeps the last one silently) and keys that are not strings
   (YAML 1.1 reads `yes:` and `on:` as booleans). Depth at most 16, at most 5000 nodes. Scalars are strings, integers, booleans or
   null. The top level must be a mapping.
4. **Keys the fields own:** `users`, `ssh_authorized_keys`, `hostname`, `fqdn`, `manage_etc_hosts`, `preserve_hostname`, `packages`,
   `package_update`, `package_upgrade`, `write_files`, `bootcmd`, `runcmd`, `mounts`, `swap`, `growpart`, `timezone`, `locale`, `ntp`,
   `power_state`. Message: "extra: packages is a field of this template (Packages): put nginx there, so the preview and the comparison
   of versions show it". `mounts` matters twice: os-install appends its own `mounts` on the host (`steps_osinstall.py:336`).
5. **Keys that replace StorageForge's login or its key, or change merging:** `disable_root`, `ssh_pwauth`, `ssh_deletekeys`,
   `ssh_keys`, `ssh_genkeytypes`, `chpasswd`, `merge_how`, `merge_type`.
6. **Keys that call out or back:** `phone_home`, `reporting`, and `write_files` with `source`. Message: "extra: phone_home makes the VM
   call an address at first boot. What StorageForge makes keeps working with the controller gone, and nothing on a host calls back
   to it".
7. **Keys that carry a secret:** `password`, `passwd`, `hashed_passwd` and `plain_text_passwd` at any depth, `ubuntu_pro` and
   `ubuntu_advantage` tokens, `rh_subscription` passwords, `landscape`, and any key that matches `SECRETISH` (`steps_workloads.py:37`).
   Message: "extra: chpasswd sets passwords in the template's text, where everyone who reads the template sees them: give the user a
   password from the vault instead".
8. **Keys that change where cloud-init reads from:** `datasource`, `datasource_list`, `cloud_init_modules`, `cloud_config_modules`,
   `cloud_final_modules`.
9. **Configuration management that pulls from a server:** `ansible`, `puppet`, `chef`, `salt_minion`, `mcollective`. Refused unless
   the owner decides otherwise (open question 6). They do not call the controller, but the VM then depends on another server.
10. **Known keys.** Every other top-level key must be in a vendored list of cloud-config keys, taken from cloud-init's JSON schema. The
    list carries `FETCHED` and `SOURCES`, as `apixo.py:26-29` does. An unknown key is a warning, "cloud-init would ignore it (did you
    mean snap?)", since a newer cloud-init may know it. This is CT-12's controller half.

The string `@@SF:` and the prefix `@@ref ` are refused anywhere in a template, fields and extra alike. The first is the renderer's
marker. The second is what `wlexport._refs` turns into a bare reference. They are refused again in every parameter value (see
*Values*), because a value is filled in after the template was saved.

### Versions

- Every save writes a new version: 1, 2, 3. A version is never edited.
- A version is never pruned by itself. This differs on purpose from `design_versions._make_room`: a version a saved plan pins must not
  vanish from under it.
- At 100 versions the save is refused: "web-base has 100 versions: delete one that no saved plan uses, or save under a new name".
- Deleting one version is allowed only when no `change_plans.body_json` names it. The bodies are parsed as JSON in Python, not matched
  with `LIKE`. The delete is audited.
- **Remove** sets `removed_at`. The template leaves the list and cannot be chosen for a new step. Its versions stay, and every saved
  plan and schedule that pins one keeps rendering and running (rule 1). The confirmation says "3 saved plans use web-base and keep
  working; it can no longer be chosen for new steps".
- Two versions are compared in plain sentences, in the style of `design_versions.compare`: "Packages: chrony added. Time zone is UTC in
  v2 and Europe/Berlin in v3. 1 file only in v3: /etc/motd".
- **Login only** has no row. It cannot be edited, removed or used as a name. Its one button is *Copy to edit*, which starts a new
  template from the vm-create flavour.

### The step fields

Each VM step that takes a template gets these fields, all `added=True`, so every plan saved before 0.6.10 keeps its `plan_hash` and
its "ran" mark.

| Field | Kind | What it holds |
| :-- | :-- | :-- |
| `cloudinit` | new `cloudinit`: `NAME(@[1-9]\d{0,5}(:[0-9a-f]{64})?)?` | The template. Empty means Login only. After the pin: `web-base@3:` and the pin hash |
| `cloudinit_values` | new `tvalues`: `k=v` pairs joined by `&`, values percent-encoded, at most 20 pairs and 4000 characters | The per-VM parameter values |

`pve-vm` also gets `snippet_storage` (kind `name`) and `cloudinit_strict` (bool, "refuse rather than leave fields out"), both added.

The steps that get them: `vm-create`, `pve-vm` (only with source `image`), `incus`, `os-install`, and the new steps of CT-09.

**Not spec fields.** `steps_vm.SPEC_FIELDS` is every vm-create field except `name` and `spec` (`steps_vm.py:97`), so adding
`cloudinit` and `cloudinit_values` to `FIELDS` would make them VM spec fields by themselves, and `_clean` would store them. A spec
that stored a pinned `name@N:SHA` would break every new plan made from it once a vault key rotates. So both fields are left out of
`SPEC_FIELDS` explicitly: a VM spec never carries a template. A test makes a vm-create step from a spec and checks that the spec holds
no `cloudinit`, and that a template set on the step is pinned at save. Whatever registers the pin hook, it is appended to
`changes.PREPARE` after `expand()` (`steps_vm.py:447`), and a test asserts that order.

**The pin.** A `PREPARE` hook, like `expand()`, turns `web-base` into `web-base@3:SHA` when a plan is checked or saved. `SHA` is the
sha256 of the version's canonical JSON (sorted keys, as `design_versions.canonical` at `design_versions.py:61-66`) followed by every
vault key the template names, with its public key as it is in `ssh_keys` at that moment. The field is hashed into `plan_hash`. So:

- Editing a template cannot change an approved plan. The plan names v3.
- Rotating a vault key a template names cannot change it either. At script time the renderer computes the hash again, and a mismatch
  is refused: "a vault key named by web-base v3 changed since the plan was saved: save the plan again to use it".
- A name given as `web-base@3` with no hash is pinned to that version's hash at save.
- The hook recomputes `SHA` for every `name@N` and `name@N:SHA` it sees, on every save and on the check route, and writes the fresh
  hash. A stored `web-base@3:OLDSHA` is replaced, so a deliberate save after a key rotation takes in the new key and changes
  `plan_hash`, which is correct: the plan now deploys something else and needs approving again. The version number is never changed
  by the hook. Only `script()` refuses a mismatch. Test: rotate a vault key, the script is refused, the plan is saved again, the
  script passes.

**An unpinned name never reaches a host.** `script()` and `check()` do not prepare, so a body that was never saved can reach them with
a bare name. The renderer refuses a bare name at script time ("save the plan to pin web-base") rather than take the newest version.
The check route prepares, so the wizard's review sees the pinned form.

**Values.** `cloudinit_values` passes its regex in `normalize`. The prepare hook and each step's check then load the pinned version and
check every value against its parameter's kind. A required parameter that is empty, or a value the template does not declare, is a
crit. The Changes form shows the field as one line. The wizard shows one input per parameter and writes the line.

A parameter's kind is not enough. Kind `text` (`[^NUL newline]{0,200}`) and kind `path` (`/[^NUL newline]*`) both accept
`@@SF:b64:tskey@@`, `/root/.ssh/authorized_keys` and spaces or tabs, and the save-time checks ran before any value existed. So after
the values are filled, the same checks run again on the filled document, in three places: the prepare hook, each step's check, and the
renderer itself (which refuses rather than renders):

- each filled field's own check: `HOSTNAME` for the host name, `CHECKS['spec']`, `path`, `MOUNT_FS` and `options` for a mount, `@`
  refused then `HOST_RE` for an NTP server, the `cidr` and `ip` rules for the network;
- the refused `write_files` paths (`/root/.ssh`, `authorized_keys`, `/etc/shadow`, `/var/lib/cloud` and the rest of the list above);
- the refusal of `@@SF:` and `@@ref ` in every value.

Without this, a person with `plans.edit` could put a slot marker into user-data, which the host's slot filler would fill from a secret
file another step left in `/run/storageforge/secrets` (and cutting at the first marker could write it into a 0644 file); fill a
`{path}` parameter with a path the save refused; or put spaces into a mount device and break the guest's `/etc/fstab`. Tests: a `text`
parameter set to `@@SF:b64:x@@` is a crit, and a `path` parameter set to `/root/.ssh/authorized_keys` is a crit.

**Open option for the owner.** The pin could copy the whole template body into the plan instead of a reference, as specs copy their
values. A plan would then survive a database restore or a copy to another controller. The cost is plan size, and every value of the
body would sit in `change_plans`. The spec proposes the reference with its hash (open question 1).

## The renderer and Login only

### The module

`cloudinit.py` holds pure functions. It touches no database and no host, apart from reading the template store and `ssh_keys` through
the connection it is given.

```
render(template: dict | None, vm: dict, target: str) -> Rendered
```

- `template`: a version body, or `None` for Login only.
- `vm`: the step's validated params (name, login fields, image, guest agent), the filled parameter values, and the pinned public keys.
- `target`: `vm-create`, `os-install`, `pve-native`, `pve-snippet`, `incus`, `xo`, `truenas`, `tf-libvirt`.

`Rendered` holds:

- `files`: `user-data` (bytes), `meta-data` (bytes), `network-config` (bytes or `None`), `vendor-data` (always `None`).
- `qm`: for `pve-native` only, the `qm set` words, and the fields Proxmox cannot carry.
- `slots`: the values filled on the host at deploy (below).
- `secrets`: `(name, how)` for each vault secret the files need.
- `notes`: check items for the step's check.
- `sha256` of each file as rendered, which the report prints and the preview shows.

vendor-data stays `None` for a reason. In cloud-init, user-data replaces vendor-data key by key, and lists are not merged without
`merge_how`. If StorageForge put the guest agent package in vendor-data, a template with its own `packages` would drop it silently.
The renderer merges StorageForge's own additions into user-data instead: `sudo` for Alpine, `qemu-guest-agent` and its `runcmd`, with
duplicates removed.

### Emitting

- **Login only** (a template of `None`) is emitted by a small hand emitter per flavour. It writes the same pieces as today's `printf`
  lines, in the same order, including the `IFS=,` packages list with no space.
- **A template** is emitted as `#cloud-config` and `json.dumps(doc, indent=2, ensure_ascii=False)`. JSON is today's format and YAML
  1.2 reads it. Every string stays quoted, so YAML 1.1's traps (`on`, `yes`, `0644`) cannot happen, and there are no anchors or
  aliases to emit. `ensure_ascii=False` keeps non-ASCII text as UTF-8: PyYAML does not join `😀` surrogate pairs.
- The order of a template's document: StorageForge's login part for that target, then the template's fields in the order of the field
  table, then the extra block.
- The login part already writes keys the template has fields for. vm-create's writes `hostname`, `packages` and `runcmd`
  (`steps_vm.py:201-213`). os-install's writes `hostname`, `growpart: {mode: off}` and a `mounts` list from the `os-mounts` slot
  (`steps_osinstall.py:327`, `:336`). The login part of a target is not known when a template is saved, so a collision cannot be
  refused at save, and the renderer builds one dict, so one side would silently overwrite the other. The renderer merges each such
  key by a fixed rule instead, and a test covers each collision per target:
  - `users`: StorageForge's login user first, then the template's. The same name in both is a crit in the step check.
  - `packages` and `runcmd`: StorageForge's entries first, then the template's, duplicates removed, first one kept.
  - `mounts`: one list, the template's entries and then the carried slot. The renderer writes the slot so the joining comma is there
    only when both sides have entries and the slot is not empty. The same mount point on both sides is a crit on the host (the carried
    side is known only there) and a crit in the step check when the template's point is one the step's reading already lists.
  - `hostname`: from the template's pattern. meta-data's `local-hostname` stays the step's `name`.
  - `growpart`: always `{mode: off}` for os-install, whatever the template says, because the new root shares a disk on purpose and
    must keep its `size_gb`. A template that asks for growpart gets a check note: "growpart of web-base is left off: this system
    shares its disk". On every other target the template's value is used.

### Slots

Some values exist only on the host at run time. The renderer writes a marker in their place, `@@SF:KIND:ARG@@`.

| Slot | Made where | Today |
| :-- | :-- | :-- |
| `stamp` | The host: `$STAMP`, or `$(date +%s)` for os-install | `steps_vm.py:214`, `steps_osinstall.py:326` |
| `randhash:USER` | The host: `$6$`, 16 then 86 characters from `/dev/urandom` | `steps_vm.py:210-213` |
| `pwhash:NAME` | See *Secrets* | none |
| `b64:NAME` | The host: `base64 -w0` of `/run/storageforge/secrets/NAME` | none |
| `os-hostkeys`, `os-mounts`, `os-network` | The host, by the existing `sf_os_json`, `sf_os_mounts` and `sf_os_network` | `steps_osinstall.py:330-345` |

How Bash fills a slot:

- It cuts at the marker with `${ud%%MARK*}` and `${ud#*MARK}`, and joins the pieces with `printf '%s%s%s'`.
- It never uses `${ud//MARK/$value}`. On bash 5.2, `patsub_replacement` is on by default, so an `&` in the value is replaced by the
  matched text. A mount path from fstab can hold an `&`.
- Each value is checked against a fixed character set before it goes in. A crypt hash must match
  `^\$[0-9a-z]+\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{20,}$`. Base64 must match `^[A-Za-z0-9+/]*=*$`.
- A marker left after filling is a conflict, and nothing is written.

`randhash` is a string in the shape of a SHA-512 crypt hash, made of random characters. No password matches it in practice, and it is
not a secret. It stays host-made where a host runs the step, which keeps the bytes. Where no host runs Bash, the controller makes it:

- The XO step makes it with `secrets` at apply, once per VM.
- The Terraform export must not. The export is generated on every download (`routes_workloads.py:76`), and in the dmacvicar/libvirt
  provider `libvirt_cloudinit_disk.user_data` is ForceNew, and so is the domain's `cloudinit`. A fresh random value would make every
  re-export differ, and `terraform apply` with a re-exported `main.tf` would replace the seed and the VM. So the export's `randhash` is
  deterministic and still a hash of nothing: HMAC-SHA512 under a key the controller holds (a new setting, made once at first use),
  over plan id, step id and user name, mapped to the crypt alphabet `./A-Za-z0-9` in the 16 + 86 shape. No password
  matches it, and the same plan exports the same bytes. Test: two exports of one saved plan are byte-identical apart from the
  generated date line.

### Template users on Alpine

A template user with no `password_secret` is rendered with `lock_passwd: false` and its own `randhash` slot, as vm-create's login is
today. A locked account on Alpine, whose OpenSSH has no PAM, refuses the user's key. This holds on every target, so a template behaves
the same on every image.

### How the four writers become callers (CT-01)

Every rendered file reaches the step's Bash function as one base64 word, added by `args_of` and shlex-quoted by `script()`. The word's
characters are `[A-Za-z0-9+/=]`: no quote, no `$`, no space, no line break. The function decodes it with `base64 -d` into a 0600 file.
This is the one rule that keeps template text out of Bash text.

- **vm-create.** It is registered with `args_of`, which returns base64 of user-data and of network-config (or an empty word).
  `t_vm_create` takes them after its 20 words. `run` pads absent words with empty ones (`changes.py:1871`), so a step without them is the same as today.
  The `printf` block (`steps_vm.py:199-214`) becomes the decode, the slot filling and the same `meta-data`. The ISO line also takes
  `network-config` when it is there. `_ansible(t)` (`steps_vm.py:428-433`) builds its words from `words_of(ARGS)` alone, so it becomes
  `_ansible(t, conn)` and appends the `args_of` words itself.
- **os-install.** The same words. The user-data base is decoded, the `randhash` slots are filled, and the host facts go into their
  slots. The datasource pin (`steps_osinstall.py:311`) stays StorageForge's own and is never in a template. The 0700 folder and the
  0600 file stay.
- **pve-vm.** The `pve-native` flavour returns today's `qm set` words exactly. With no template, the script text is unchanged, checked
  by string equality. That holds only if nothing is appended to the run line: `cloudinit`, `cloudinit_values`, `snippet_storage` and
  `cloudinit_strict` stay out of pve-vm's `ARGS`, and its `args_of` returns `[]` for Login only, never an empty word (an empty word
  would append `''`). With a template, see *Proxmox VE* below.
- **incus.** `_incus_extra` already supplies the `ports` word after the 13 `INCUS_ARGS`, as word 14. The instance YAML word goes after
  it, as word 15, and only when there is a template, so a step without one keeps its script text.
- **Terraform.** `libvirt_cloudinit_disk.user_data` becomes `render(..., 'tf-libvirt')['user-data']`. After the CT-10a fix it carries
  what vm-create's document carries, with the deterministic `randhash` of *Slots*.

### Login only, byte for byte

Today's "login-only config" is four documents, not one. *Login only* is one built-in template with four flavours. Its preview says so
per system, and its row in the list reads "built in: what each system wrote before templates".

1. **vm-create**, from `steps_vm.py:199-214`:
   `#cloud-config\n{"hostname": "N", "manage_etc_hosts": true, "ssh_pwauth": false, "disable_root": true, "users": [{"name": "U",
   "lock_passwd": false, "hashed_passwd": "@@SF:randhash:U@@", "ssh_authorized_keys": ["K"]` then `, "sudo": "ALL=(ALL) NOPASSWD:ALL"`
   for `nopasswd`, then `}]`, then `, "packages": [...]` joined with `,` alone (`"sudo"` for Alpine with `nopasswd`, then
   `"qemu-guest-agent"` with the agent), then the agent `runcmd`, then `}\n`. meta-data:
   `instance-id: sf-N-@@SF:stamp@@\nlocal-hostname: N\n`.
2. **os-install**, from `steps_osinstall.py:326-337`: hostname, `preserve_hostname`, `growpart`, one locked user with `/bin/bash` and
   the optional sudo, then the `os-hostkeys` and `os-mounts` slots. meta-data: `instance-id: N-@@SF:stamp@@`.
3. **pve-vm**: no file, the `qm set` words of `steps_proxmox.py:212-216`.
4. **Terraform**: today's `json.dumps` until the CT-10a fix, then vm-create's document as above.

The proof is golden files, made by running HEAD's own Bash with fixed inputs. `STAMP` is pinned and `/dev/urandom` is replaced by a
fixed file, in the fake-tool harness the tests already use. The matrix:

- vm-create: `sudo` (nopasswd, none) by image (alpine, other) by guest agent (on, off). Alpine with nopasswd and the agent is the case
  that catches the `IFS=,` join.
- os-install: `host_keys` (same, new) by `carry` (mount, none) by `network` (same, fixed, dhcp), with stubbed host facts.
- pve-vm: the script text for a step with no template.
- Terraform: a golden before CT-10a and a new one after it, changed in that commit only.

After CT-01, the renderer's output with the slots filled as the script fills them must equal each golden byte for byte.

## Delivery per system

### What each system can carry

| Field | libvirt | Proxmox, snippets | Proxmox, native | Incus | OS install | Xen Orchestra | TrueNAS | Terraform libvirt |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| StorageForge login | yes | yes | yes | no login field | yes | yes | yes | yes |
| Users and keys | yes | yes | first user only | yes | yes | yes | yes | yes |
| Password secret | yes | refused until the lab (CT-13) | refused (argv) | refused | yes | refused | yes, unless the dataset is shared | left out |
| Packages, update, upgrade | yes | yes | upgrade only | yes | yes | yes | yes | yes |
| Time zone, locale, NTP | yes | yes | no | yes | yes | yes | yes | yes |
| Files (text) | yes | yes | no | yes | yes | yes | yes | yes |
| Files (secret) | yes | refused until the lab | no | refused | yes | refused | as passwords | left out |
| runcmd, bootcmd | yes | yes | no | yes | yes | yes | yes | yes |
| Mounts, swap, growpart | yes | yes | no | yes | mounts merged with the carried ones (a shared mount point is a crit), swap yes, growpart always off (a note) | yes | yes | yes |
| Host name pattern | yes | yes | yes (the VM name) | yes | yes | yes | yes | yes |
| Network | yes | yes | addresses, gateway, DNS, search | yes | refused with `network=same` or `fixed` | yes | yes | yes |
| power_state | yes | yes | no | yes | yes | yes | yes | yes |
| extra | yes | yes | no | yes | yes | yes | yes | yes |

### libvirt (`vm-create`, CT-05)

- The seed ISO holds user-data, meta-data and, when the template sets a network, network-config. The existing xorriso, genisoimage or
  mkisofs line builds it (`steps_vm.py:216-221`). It is a file of the VM and stays when the controller is gone.
- The ISO is built under umask 077, so it is root 0600. libvirt's `dynamic_ownership`, on by default, relabels it for qemu when the VM
  starts. The report reads `dynamic_ownership` in `/etc/libvirt/qemu.conf` and says "the VM may not read its seed" when it is 0.
- The report line names what it delivers: `seed: user-data (web-base v3, 2.1 KiB, sha256 ...), meta-data, network-config (fixed
  10.0.4.21/24 on enp*)`.
- With a password secret: "the seed ISO /var/lib/libvirt/images/web-01-seed.iso holds the hash of vault secret web-admin-pw: readable
  by root on the libvirt host only".
- A seed already there is a conflict, as today (`steps_vm.py:174-176`).
- network-config v2 on images without netplan (Rocky, Alma, Leap, Alpine) goes through cloud-init's translators, and some keys are
  dropped. The check warns per image family, from a table CT-13 proves.

### Proxmox VE (`pve-vm`, CT-06)

- The check reads the node's storages and their content types from the node reading that exists (`pvenode.py:39-62`).
- **With a storage whose content includes `snippets`:**
  - The script finds the folder with `pvesm path STORE:snippets/sf-VMID-NAME-user.yaml`. It writes the user-data, and the
    network-config when there is one, under umask 077. Then it runs `qm set VMID --cicustom user=STORE:snippets/...,network=...`.
  - The check names the storage it chose: "ok: user-data and network-config go to local:snippets/sf-web-01-user.yaml and
    sf-web-01-net.yaml, set as cicustom". When there are several, `snippet_storage` chooses.
  - `cicustom user=` replaces the user-data Proxmox generates, so the rendered document must hold the login. The `pve-snippet` login
    part copies what Proxmox's own generated user-data gives the `ciuser`. CT-06 reads it with `qm cloudinit dump VMID user` for a
    Login-only VM on `sf-pve`, and the renderer copies that, not a guess.
  - `pve_vm_undo` (`steps_proxmox.py:178-185`) also removes the snippets this run wrote. A snippet already there is a conflict.
  - A snippet stays on the node when the VM is removed outside StorageForge. A VM that moves between nodes needs shared snippets
    storage. The docs say both. No code.
- **With no snippets storage:**
  - The fields Proxmox's own options carry go through them: `--ciuser`, `--sshkeys FILE`, `--ipconfigN`, `--nameserver`,
    `--searchdomain`, `--ciupgrade`.
  - The check warns and lists what is left out: "warn: no storage on pve1 holds snippets, so Proxmox's own cloud-init options carry
    what they can: the login account and its key, the addresses and gateway of each card, DNS servers and search domain, and upgrading
    packages. These fields of web-base v3 cannot be carried and are left out: 2 more users (deploy, backup), packages (nginx, chrony),
    3 files, 2 first-boot commands, time zone, swap, when done, extra. To carry them, add snippets to a storage's content (Datacenter >
    Storage > local > Content) and measure pve1 again."
  - `cloudinit_strict` turns that warn into a crit for a person who wants all or nothing. Warn or crit by default is open question 3.
  - A password secret is refused on this path. `--cipassword` takes the value on the command line, which breaks the secret rule.
    There is no `--cipassword-file`.
- **Login only** uses the native words whatever storage is there, as today.
- When a template is used, `user` is checked again against `username`. Its kind is `name` (`steps_proxmox.py:477`), which allows
  `:` and `+`.

### Incus (`incus` step, CT-07)

- The instance gets `cloud-init.user-data` and, when there is one, `cloud-init.network-config`.
- They do not go into the `incus init` argv. That argv is printed whole by `info "incus init $image $name ${args[*]}"`
  (`steps_workloads.py:265`) into the report and deploy_runs. It is visible in `/proc/PID/cmdline`, and one argument is limited to 128
  KiB (`MAX_ARG_STRLEN`). Instead, the controller renders an instance YAML holding the two keys. `_incus_extra` adds it as a base64
  word, the script decodes it to a 0600 temporary file, and runs `incus init IMAGE NAME ... <FILE`. `incus init` reads instance config
  from a stdin that is not a terminal. CT-13 proves it on the Incus version of `sf-ubuntu`.
- `RESERVED_INCUS` stays, so the `user.*` keys stay refused as labels.
- The image must carry cloud-init. An `images:` alias needs its `/cloud` variant, and the `ubuntu:` remotes have it. With a reading of
  the image: "crit: images:debian/13 has no cloud-init (its variant is default): choose images:debian/13/cloud, or no template". A
  container image without cloud-init ignores the keys silently, so this is a crit. Without a reading, a note, and the script checks
  the variant before it creates anything.
- An instance key replaces a profile's `cloud-init.user-data` whole. The report reads `incus profile get P cloud-init.user-data` for
  each profile and says so.
- The step has no login fields, so it has no StorageForge login part. The template's users are all the users. The editor says so.
- Secrets are refused. Instance config is readable by anyone who may run `incus config show`.
- An existing instance is left as it is (`steps_workloads.py:240-247`). A template applies at creation only.

### OS install and host migration (CT-08)

- **OS install.** The template's fields go into the same NoCloud folder of the new root, beside what the step writes today: the host
  keys, the carried mounts and the copied network. The datasource pin stays.
  - A template with its own network and `network=same|fixed` is refused: "the network of web-base v3 would replace the one copied from
    this host: leave the template's network to the image, or choose network dhcp".
  - A template user that already exists on the source: "warn: user deploy is in web-base and already in this host's /etc/passwd (uid
    1001): cloud-init leaves an existing account as it is".
- **Host migration.** `vm clone` makes a vm-create step (`cli.py:831-845`), so it comes with CT-05. The CLI already takes
  `--set cloudinit=web-base`. CT-08 adds `--template NAME` as a short form, and the migration docs say so.
- What is in user-data stays in the guest's `/var/lib/cloud/instances/<id>/user-data.txt` (root only). Deleting the seed after first
  boot is not offered: with `datasource_list: [NoCloud, None]`, a missing seed makes the None datasource look like a new instance, and
  the per-instance modules run again.

### Xen Orchestra (CT-09, a major checkpoint)

This would be the first write ever made through an API connection, and the first plan step that runs in the controller rather than in
a report-first script on a host. The spec designs it. The owner decides at the checkpoint whether it is built in 0.6.10 or written down
as a decision in the ledger (open question 4).

- **A new action `create-vm`** in `apixo.GUIDE['actions']`, beside `snapshot` and `power`. It asks for its own privileges, narrowed by a
  selector (a pool, or the `storageforge` tag). It is granted with `set_actions` and enforced where actions are checked
  (`apiconn.py:587`, `:812`).
- **The endpoint.** The connection is REST (`/rest/v0`). The roadmap's `vm.create` is the JSON-RPC name. The builder confirms the REST
  endpoint that creates a VM from a template with a cloud config and a network config, against the OpenAPI examples `apixo.py:14-16`
  cites. If REST has none, the checkpoint decides between JSON-RPC and the written decision.
- **Report** is reads only: the template and the SR exist, the name is free, the action is on.
- **Apply** is one POST, audited under `deploy.apply`. XO accepts duplicate VM names, so the step tags the VM
  `storageforge-step-<sha>` and looks the tag up before creating. A retry finds the VM and does not make a second one.
- **On the page**, "+ New VM" on an XO pool node is visible on a read-only connection, but disabled: "This connection only reads. To
  make VMs here, allow "create VMs" on Connections > xo-lab, and give the StorageForge role vm:create narrowed to a pool (the guide
  shows the commands)".
- **Secrets are refused.** XO keeps the cloud config on a config-drive VDI that anyone who can read or export the VM can read.
- Rule 5 keeps the change engine apart. The owner says whether a controller-side plan step counts as part of it.

### TrueNAS (CT-09)

StorageForge makes no VM on TrueNAS. CT-09 adds a step `truenas-seed`: for a VM made in TrueNAS that has not booted yet, write a NoCloud
seed ISO into a dataset over SSH and attach it as the VM's CD-ROM.

- The ISO needs a writer. The script looks for xorriso, genisoimage or mkisofs on the appliance, as vm-create does, and gives a
  conflict when there is none. The appliance has no package manager to add one, and the controller has no ISO code or dependency.
  The other ways are pycdlib (a new dependency), a hand-written minimal ISO 9660 or VFAT `cidata` image, or the written decision
  (open question 5).
- Attaching runs `midclt call vm.device.create` on the appliance as root over SSH. That is a root write beside the READONLY_ADMIN key
  model of `apitruenas.py:55-68`, and the docs and the check say so.
- A dataset shared over SMB or NFS is refused, checked against `parse_shares` (`apitruenas.py:219`).
- The VM backend changed across TrueNAS releases. If the lab shows the attach cannot be done safely, CT-09 writes the decision in the
  ledger. The list then shows TrueNAS as "seed by hand", and the CLI `render --out DIR` writes the files for the person to make the ISO.

### Exports (CT-10)

- **Bash and Ansible** carry the same base64 words, through `args_of` into `script()` and the step's Ansible task, so an exported plan
  makes the same VM. A secret must already be in `/run/storageforge/secrets`. `vault send-secret` puts it there
  (`secretstore.py:34`, `:289-290`). `pve-ct` says only that an apply from StorageForge brings it (`steps_proxmox.py:93-96`), and the
  template steps say the same and name `vault send-secret` for an exported plan. `send-secret` writes the cleartext `NAME`, never
  `NAME.crypt`, so for a password the step falls back on the host: when the hash file is missing and `NAME` is there, it runs
  `openssl passwd -6 -stdin <NAME` (a file and a pipe, never argv), and it is a conflict when openssl is missing too. CT-04 states this
  fallback whichever hashing the owner chooses for StorageForge's own apply.
- **Terraform and OpenTofu:**
  - `libvirt_cloudinit_disk` takes `user_data` and, when there is one, `network_config` from the renderer (`wlexport.py:217-218`). HCL
  strings already escape `${` and `%{` (`_hstr`, `wlexport.py:109-110`), so a command word such as `${HOME}` stays text.
  - `incus_instance` gets `cloud-init.user-data` (and `cloud-init.network-config`) in its `config` (`wlexport.py:180-202`). They are
    added in the Terraform `incus_instance` block only, never to `model()`'s `config` dict (`wlexport.py:81-85`), which `puppet()`
    also renders.
  - The Proxmox provider's `cicustom` is new export work: `KINDS` has no `pve-vm` (`wlexport.py:23`). CT-10 adds `pve-vm` to the
    export with a comment that the snippet file must exist on the node. It is not "from the renderer" alone.
  - A template with a secret: the export leaves the secret part out and says so in a comment, such as "# the password of deploy is
    vault secret web-admin-pw: StorageForge's own run sets it, this export leaves the account with a password nobody knows". No export
    holds a secret (`wlexport.py:8-10`). Terraform state would otherwise hold it in clear.
- **Puppet** keeps naming only the disk for VMs (`wlexport.py:309-310`). For Incus, Puppet renders `config` as `-c k=v` inside an
  unquoted exec `command` string (`incus launch IMAGE NAME ... -c k=v`, `wlexport.py:290-292`). A rendered document there would run
  template words such as `$(...)`, `;` or backticks in the shell on the Puppet node as root, and break on spaces. So the Puppet export
  never puts cloud-init text in a command: an Incus resource with a template gets a comment, "# web-base v3 is the cloud-init of this
  instance: the Bash or Terraform export carries it", and nothing else. The CT-03 property test covers the Puppet output too: no
  template byte appears in it.

## Secrets (CT-04, a major checkpoint)

**The rule.** A template holds a vault name and never a value. Wherever a secret could go (a user's password, a file's contents), the
editor offers a list of vault secrets by name, with "+ New secret in the vault…", and has no text box. The preview, the plan, the
script, the exports, deploy_runs output and the audit hold names only. The preview shows `<vault secret web-admin-pw, hashed at
deploy>`.

**Discovery.** `plan_secrets` reads only fields of kind `secret` (`secretstore.py:202-226`). A template's secrets are in neither, so an
apply would carry nothing and the step would fail with "not on this host". CT-04 adds a hook, `changes.SECRETS_OF[type](conn, task) ->
[(name, how)]`, with `how` one of `pwhash` (a user's password, delivered hashed) or `file` (a file's contents, delivered as itself),
that reads the pinned version, and `plan_secrets` takes the union. Names alone would not do: `plan_secrets` yields (name, step kind)
pairs, so `stream()` could not tell a password from a file secret, and one name can be both. `how` is carried through `plan_secrets`
and `stream()`: the value is hashed only for `pwhash`, sent as itself only for `file`, and the cleartext of a secret used only as
`pwhash` is never sent. Release then goes through the existing `stream()`: one release per secret, for this host and this step kind,
checked against the secret's policy and written up by the enclave. Report mode
carries none, and says what an apply would release: "at deploy: vault secret web-admin-pw for deploy's password, released for pve1
and step vm-create".

**Where a password is hashed.** CT-04 says "hashed at deploy, never sent as text". There are two ways:

1. **In the controller (proposed).** After release inside `stream()`, the controller hashes the value with sha512-crypt and a fresh
   salt, and sends only the hash on stdin, under the name `NAME.crypt`. The cleartext never reaches the hypervisor. Python has no
   `crypt` module from 3.13 and no dependency offers sha512-crypt, so this needs a small hand-written sha512-crypt (about 80 lines),
   tested against fixed vectors from glibc's specification. `sf_secrets_in` accepts only names that match
   `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$` and skips the rest as "not in the expected form", so `NAME.crypt` for a name of 59 characters
   or more would be skipped. A secret a template names as a password is therefore limited to 58 characters, checked at template save,
   so `NAME.crypt` always fits.
2. **On the host.** The value lands in `/run/storageforge/secrets/NAME` as other secrets do, and the step runs
   `openssl passwd -6 -stdin <FILE`. The value goes through a file and a pipe, never argv. Without openssl, a conflict. The cleartext
   stays in the hypervisor's `/run` until reboot, as `pve-ct`'s root password does today (`steps_proxmox.py:93-96`).

The first fits the roadmap's words and keeps the cleartext off the host. The owner chooses (open question 2). Either way, an exported
plan uses the host fallback of *Exports*, since `vault send-secret` sends the cleartext name only.

**File secrets.** A file secret is a one-line vault value: the web only generates values (`POST /api/keys/secrets`: password, token,
hex, pin, wireguard), and `vault secret-add` refuses a newline or more than 4096 characters (`cli.py:1373`). `payload()` appends a
newline to every value it sends (`secretstore.py:240`), so the file on the host is the value plus `\n`. `b64:NAME` strips that one
trailing newline and then takes `base64 -w0`, so the guest file is byte for byte the stored value, and it is written as a
`write_files` entry with `encoding: b64` and mode 0600. A PEM private key, a certificate or a multi-line config cannot be stored as a
step secret today. Storing one (for example the base64 of the file kept as a token-like value, decoded by `encoding: b64`) would be a
new kind of stored secret, a stored-format change that needs the owner, and is not part of this spec.

**On the host.** The assembled user-data is written under umask 077. The temporary folder is removed on every way out, as
`t_vm_create` removes `$cd` today, with `rm -rf` before each `vm_undo` and after the ISO is written (`steps_vm.py:211`, `:218-222`).
`vm_undo` itself removes only the disks in the run's `made` array (`steps_vm.py:137-140`) and stays that way. No info line prints a
file. The hash goes in only through the slot rule above.

**Per system.** Refused, with the reason, where the system exposes user-data to people who may read the VM:

| System | Secrets | Why |
| :-- | :-- | :-- |
| libvirt | Allowed | The seed ISO is root 0600 on the hypervisor and stays for the VM's life. The check says so |
| OS install | Allowed | The seed is 0700/0600 in the new root, beside the host private keys it already holds |
| Proxmox, snippets | Refused until CT-13 | Snippets are plain files, and on shared storage every node and every mount of the share reads them. Whether `GET /nodes/N/qemu/ID/cloudinit/dump` with VM.Audit returns their contents is not proven. Then allowed only on storage that is not shared. This goes further than the roadmap, which names Incus and XO (open question 7) |
| Proxmox, native | Refused | `--cipassword` is a command-line value |
| Incus | Refused | Instance config is readable through the API |
| Xen Orchestra | Refused | The config-drive VDI, and XO's own records |
| TrueNAS | Refused on a shared dataset | Otherwise as libvirt |
| Exports | Left out | Named in a comment |

**What stays in the guest.** A hash or a file secret stays in `/var/lib/cloud/instances/*/user-data.txt` (root only). The editor says
so beside every secret field.

**Policy breadth.** A release is checked against the step kind. A secret released to `vm-create` on a host is released to every
`vm-create` step on that host. The editor suggests a policy that names the host.

**Clear text that is allowed.** Pasted public keys, file text and commands. The editor says file text is stored in clear and shown in
the preview, the script and the exports. It warns once when file text looks like a key or a token (`BEGIN ... PRIVATE KEY`, or a long
base64 string). For a one-line token: "this file looks like a token: put it in the vault and choose the secret here". For a
multi-line key or certificate, which a vault step secret cannot hold: "this file looks like a private key: it would be stored in clear
in the template and every VM made from it; a multi-line key cannot be a vault secret yet, so copy it to the VM another way".

## Checks

### At save (CT-03)

Every field, size and count above. The extra block's steps 1 to 10. `@@SF:` and `@@ref ` anywhere. Then:

- "Users: deploy is listed twice".
- "Users: admin is the login account of the VM steps: give this user another name". A warn at save. A crit in a step whose login has
  that name.
- "Commands, first boot, line 2: a command is a list of words, one per box". The editor offers the split as a fix to accept.
- "Files: /etc/sudoers.d/90-x: mode 0644 lets everyone read a sudo rule; 0440 is what sudo wants". A warn.
- "Host name: {name}.{domain} needs domain: give it a default or make it required".
- "Parameters: address is used in Network > enp* but not declared".
- A vault key name that is not in `ssh_keys`: a warn at save, a crit in the step check.

### In each step's check (CT-12, the controller half)

Added to each step's `check_of`, before any step runs:

- "ok: first boot from web-base v3: 3 users, 2 packages, 3 files, fixed address 10.0.4.21/24".
- "note: web-base has a v4 (saved 2026-11-28 by gabe): this step keeps v3". In the wizard this is a link that switches the version
  and checks again.
- A removed template: a crit for a new step. For a saved plan: "note: web-base was removed after this plan was saved; this plan keeps
  v3".
- The pinned version exists, and its hash matches.
- "crit: parameter address is required and empty", and "crit: address 10.0.4.300/24 is not an address".
- "ok: rendered user-data parses, 2.1 KiB; network-config version 2 parses", or "crit: rendered user-data is 70 KiB, over 64 KiB".
  network-config is parsed back with `safe_load` and must be `version: 2`.
- Every top-level key is in the vendored list, or a warn.
- Each secret's system allows it, and the secret exists in the vault (`secretstore.meta`).
- Image fit: a catalog image, or a custom one (warn: its cloud-init version is unknown). The Incus image variant. Alpine with `locale`
  or `ntp` set (warn, from the image-family table).
- Proxmox snippets storage, or the list of fields that cannot be carried.
- "note: the login account comes from this step (admin, key laptop-ed25519); web-base adds 2 more".
- `runcmd`, `bootcmd`, `write_files` and extra: "note: these run as root on the new VM at first boot". `bootcmd`: "runs early, before
  the network, on every boot". Template users with `nopasswd` get the note vm-create gives its login (`steps_vm.py:421-422`).

### In report mode on the host (CT-12, the host half)

- When the host has `cloud-init`, the script writes the decoded files to a temporary folder under umask 077 and runs
  `cloud-init schema -c FILE` (older releases: `cloud-init devel schema`). It removes the folder on every way out. Report mode holds no
  secret, so the folder holds markers in place of hashes.
- That is the hypervisor's cloud-init, not the guest image's, and its version can be newer or older. The result is an info line and
  never blocks.
- Without cloud-init: "info: this host has no cloud-init to check the files with; the controller checked them".
- The report prints the sha256 of each decoded file. The preview shows the same sums, so a person can match them.

### Permissions

`runcmd`, `bootcmd`, `write_files` and extra run as root in every VM made from the template. So does a user that has `ssh_keys`
together with `sudo` `nopasswd` or `password`: its key's owner has a root login on every VM later made from the template, by anyone.

- Saving any template needs the new `cloudinit.edit`.
- Saving a template that has any of those four parts, or a user with keys and sudo, also needs `hosts.command`, checked in the handler
  with `need('hosts.command')` as a command schedule does (`routes_scheduler.py:34`). A template of plain fields with no such user only
  needs `cloudinit.edit`. Whether to require it is open question 8. If the owner agrees, a test saves a template with a keyed sudo user
  without `hosts.command` and it is refused.
- The editor says it beside the sudo radios of a user with keys: "a key with sudo is root on every VM made from this template".
- Deploying still needs `deploy.apply`.

## API, CLI and the Workloads page

### API

A new module, `routes_cloudinit.py`, registered from `server.py` as `routes_workloads` is (`server.py:1724`). It lives under
`/api/cloudinit`, not `/api/workloads`, because every READ under `/api/workloads` maps to `workloads.view` (`permissions.py:133`).
Handlers follow `/api/vm/specs` (`server.py:1902-1924`): `LookupError` is 404, `ValueError` is 400, and saves call `core.audit`.

| Route | What it does | Permission |
| :-- | :-- | :-- |
| `GET /api/cloudinit/templates` | The list, with Login only first, used-by counts, and the field schema for the editor. `?removed=1` adds removed ones | `plans.view` |
| `GET /api/cloudinit/templates/<name>` | The current body and its version list. `?version=N` for one version | `plans.view` |
| `GET /api/cloudinit/templates/<name>/compare?a=&b=` | Two versions in sentences | `plans.view` |
| `PUT /api/cloudinit/templates/<name>` | Body `{template, note}`: saves a new version. Audited `cloudinit.template.save` with `{name, version, sha}`, never the body | `cloudinit.edit`, plus `hosts.command` for commands, files, extra, or a user with keys and sudo |
| `DELETE /api/cloudinit/templates/<name>` | Removes the template. `?version=N` deletes one unpinned version. Audited `cloudinit.template.remove` | `cloudinit.edit` |
| `POST /api/cloudinit/render` | Body `{name, version} or {template}`, `target`, `values`, optional `host`. Returns the files, the `qm` words, the slots and the check items. Secrets show as their vault names. Never opens the vault, saves nothing | `plans.view` |
| `POST /api/cloudinit/from-step` | Body `{type, host, params}`. Returns a template body for *Make a template from this VM*. Saves nothing | `plans.view` |

Permissions (`permissions.py`):

- A new catalog entry in Planning: `cloudinit.edit`, "Create and change cloud-init templates, whose commands and files run as root on
  every new VM made from them", high risk. The `operator` built-in role gets it (`permissions.py:80`), so built-in roles behave as
  before. Custom roles made before do not hold it, and the changelog says so.
- Rules: `(READ, r'/api/cloudinit(/.*)?', 'plans.view')`, `(('POST',), r'/api/cloudinit/(render|from-step)', 'plans.view')` (reads, as
  `/api/planner/versions/compare` is at `permissions.py:109`), and `(('PUT', 'DELETE'), r'/api/cloudinit/templates/[^/]+',
  'cloudinit.edit')`. `/api/cloudinit` matches none of the generic `/api/(moves|changes|...|vm|clone)` rules (`permissions.py:194-197`).

The route tables:

- `tests/test_route_rules.py`: PUT and DELETE go in `NO_FRESH_PASSWORD` beside the VM specs (`:247-248`), with "a template only shapes a
  VM step when a plan is saved: nothing runs". `render` and `from-step` go in `NO_FRESH_PASSWORD` and `NOT_AUDITED` with "reads only,
  saves nothing". `test_no_get_runs_on_a_host` (`:457`) covers the GETs.
- `tests/test_roles.py`: `NEW_ROUTES` (`:32`) gets `/api/cloudinit`.
- The route index in `server.py`'s docstring, beside `GET /api/vm/specs` (`server.py:138`), gets the new routes.

### CLI

```
storageforge-index cloudinit list
storageforge-index cloudinit show NAME [--version N] [--json]
storageforge-index cloudinit save NAME FILE [--note TEXT]        (JSON or YAML of the body)
storageforge-index cloudinit remove NAME [--version N]
storageforge-index cloudinit compare NAME A B
storageforge-index cloudinit render NAME[@N] --for vm-create|os-install|pve-snippet|pve-native|incus|xo|truenas|tf-libvirt
                                    [--vm VMNAME] [--set k=v ...] [--out DIR]
storageforge-index vm clone ... --template NAME
```

The CLI goes through the same functions as the web. It audits saves and removes, in today's CLI actor format. That does not settle the
roadmap's open decision on CLI and web auditing, and the changelog says so (open question 9). `render --out` writes the files a step
would deliver, with the slots shown as markers.

### The Workloads page (CT-11)

**Where it lives.** A **Cloud-init templates** button in the page's toolbar (`static/workloads.html:32-44`), shown with `plans.view`. It
opens a dialog built as the wizard's is (`wwDialog`, `static/workloadwiz.js:180`).

**The list.** One row per template:

- name and note;
- the newest version: "v3 · 2026-11-28 · gabe";
- what it does in one line: "3 users · nginx, chrony · 3 files · fixed address · power off when done";
- the systems it fits, as chips: "libvirt ✓ · Proxmox (snippets) ✓ · Incus ✗ secret · XO ✗ secret". Hovering a chip gives the reason;
- the saved plans that use it.

Login only is pinned first, with *Copy to edit* and no Edit button. Buttons: **+ New template** (with `cloudinit.edit`) and **Import
JSON**.

**The editor.** Two columns, or one with the preview below at phone width.

- Left, the plain fields in folded sections. Each summary line shows what is set, so a folded editor still reads as the template:
  - Name and note.
  - Host name: one box, default `{name}`.
  - Users: a card each, with name, groups as chips, sudo as three radios, keys as "Vault key ▾" or "Paste a public key", and password
    as "None ▾ / a vault secret ▾". Above the cards a fixed line: "The login account StorageForge uses comes from each VM step and is
    always added first".
  - Packages, with the update and upgrade ticks.
  - Time and language.
  - Files, with the "stored in clear" note.
  - Commands: "At first boot, once" and "On every boot, early". Each command is a row of word boxes with + and −.
  - Disks: mounts, swap, grow the root partition.
  - Network: Leave it to the image, DHCP, Fixed.
  - When done.
  - Parameters: a table of name, label, kind, default, required.
  - Extra (raw cloud-config): folded, a monospace text area, with the server's refusals listed by line under it. Its heading says
    which keys are refused and why. The server's check is the one that counts.
- Right, **Preview**:
  - A "For" selector: libvirt, Proxmox VE (snippets), Proxmox VE (no snippets), Incus, OS install, Xen Orchestra, TrueNAS, Terraform.
  - Parameter boxes with the defaults, to try values.
  - Tabs: user-data, meta-data, network-config, vendor-data (greyed: not used), and "qm options" for Proxmox without snippets.
  - The check items for that system under the tabs, so the Proxmox list of fields it cannot carry shows before any VM step.
  - Slots shown as `<a password nobody knows, made on the host>` and `<vault secret web-admin-pw, hashed at deploy>`.
  - Filled with `textContent` in a `<pre>`, never `innerHTML`. Template text is untrusted HTML.
  - It calls `POST /api/cloudinit/render` once after a short pause in typing. There is no polling.
- Footer: the version picker, **Compare…**, a note box "What changed (optional)", **Save as v4**, and **Remove**.

**In the wizard** (`static/workloadwiz.js`):

- A page **First boot** after Access. `WW_GROUPS` (`workloadwiz.js:11-15`) gets `['First boot', ['cloudinit', 'cloudinit_values',
  'snippet_storage', 'cloudinit_strict']]`, so the fields do not fall into Settings. It shows for `vm-create`, `pve-vm` with source
  `image` (the same toggle as `wwVmSource`, `:71-76`), and `incus`. The wizard never offers `os-install`: `WW_KINDS`
  (`static/workloadwiz.js:8`) has no such kind, and the step is registered in group Systems, not Workloads (`steps_osinstall.py:480`).
  os-install gets the cloud-init fields through the Changes form only, which renders the same field specs. Putting it in the wizard
  would be new CT-11 work and is not proposed.
- On the page: **Template**, a select with Login only first, each option with its one line. **Version**: "v3 (newest)". The template's
  parameters as fields, required ones open and the rest under More (the `wwSection` rule, `:77-81`). **Preview**, folded, set to this
  host's system and this step's values. **Make a template from this VM…**
- The review shows the check items above.
- The Changes form shows the same fields, from the same field specs. `static/changes.js:115` fills VM specs from `/api/vm/specs`; the
  template list is filled the same way from `/api/cloudinit/templates`.

**Make a template from this VM.** It opens the editor with a new template named "NAME-base" and fills in what the step says beyond its
login, through `POST /api/cloudinit/from-step`:

- `vm-create`: the guest agent becomes the `qemu-guest-agent` package and its start command.
- `pve-vm`: the network becomes DHCP on the first card.
- `os-install` (from the Changes form): `dhcp` becomes network DHCP. `same` and `fixed` become "leave it to the image", since those
  networks are copied on the host (`sf_os_network`, `steps_osinstall.py:339-346`) and a template network is refused with them.
- No step has an address or gateway field to copy (vm-create's `FIELDS`, pve-vm's `_vm_fields` and os-install's choice of `same`,
  `fixed` or `dhcp`), and pve-vm always sets `ipconfig0 ip=dhcp`. So `address` and `gateway` parameters are made only when a person
  declares a static network in the editor, never taken from a step.
- The login account and its key are not copied. The editor says "The login account stays in each VM step".
- Saving sets this step's template to the new one, at v1.

## Migration

New tables only. No existing table or stored format changes. The number is the next free one when CT-02 is committed (077 is the
newest today), in both `migrations/sqlite` and `migrations/postgres`, each ending with its `schema_version` insert as
`077_docker_settings.sql` does.

```
cloudinit_templates
    id              primary key
    name            TEXT NOT NULL            unique index on lower(name)
    note            TEXT NOT NULL DEFAULT ''
    current_version INTEGER NOT NULL
    created_by      TEXT NOT NULL
    created_at      INTEGER NOT NULL
    updated_at      INTEGER NOT NULL
    removed_at      INTEGER                  NULL until removed

cloudinit_template_versions
    id              primary key
    template_id     INTEGER NOT NULL         references cloudinit_templates
    version         INTEGER NOT NULL         UNIQUE (template_id, version)
    body_json       TEXT NOT NULL            the canonical body
    sha256          TEXT NOT NULL            of body_json
    size_bytes      INTEGER NOT NULL
    author          TEXT NOT NULL
    note            TEXT NOT NULL DEFAULT ''
    created_at      INTEGER NOT NULL
```

Plans saved before 0.6.10 have none of the new step fields. They load, check, keep their `plan_hash` and their "ran" mark, and deliver
the same seed bytes, which the goldens prove. Their script text is not the same for vm-create and os-install: after CT-01b a Login-only
step reaches Bash as base64 words through `args_of`, and the function body changes. The script text stays identical, apart from the
generated date in its head, only for pve-vm (its new fields stay out of `ARGS` and its `args_of` returns `[]` for Login only), for
incus (the YAML word comes only with a template, after the `ports` word at position 14) and for every step this spec does not touch.
Commit 1's old-plan test asserts exactly that: same `plan_hash` for all, same script text for pve-vm, incus and the untouched steps.

## Tests and the lab

Nothing runs on the owner's workstation while this is designed. When it is built: each item passes its own tests and the light block
(rule 6), at most `-j 6`, one run at a time.

### Unit tests

- **CT-10a:** a Terraform export of a vm-create step with `sudo=none` has no sudo key, an Alpine step has `lock_passwd: false` and a
  hash, and a step with the guest agent has its package. Written first, they fail on HEAD (`wlexport.py:217`). Two exports of one
  saved plan are byte-identical apart from the generated date line.
- **CT-01:**
  - The goldens of *Login only, byte for byte*, from HEAD's Bash. The renderer with the slots filled equals each one.
  - The generated vm-create and os-install functions still run their seed part in the fake-tool harness, with xorriso stubbed.
  - vm-create's Ansible task carries the same words as its script.
  - The pve-vm and incus script text is unchanged for a step with no template, and pve-vm's `args_of` returns `[]`.
  - An old plan keeps its `plan_hash`; its script text is unchanged for pve-vm, incus and the untouched steps (not for vm-create and
    os-install, whose seed bytes the goldens prove instead).
- **CT-03:**
  - Each field's checks and limits, and each extra refusal with its own message.
  - YAML attacks, each refused with the reason: billion-laughs, `!!python/object`, `!!binary`, `<<`, a duplicate key, a `yes:` key,
    depth 17, 33 KiB, `#include`, `#!`, MIME.
  - `{name.__class__}` in the host name is refused and never evaluated.
  - Two users sharing one key list render without anchors.
  - Rendering is deterministic, the login user comes first, and parameters never reach commands or extra.
  - An Alpine template user with a key only renders `lock_passwd: false` and a slot.
  - The merge of each login key per target: `packages` and `runcmd` with duplicates, `mounts` with an empty and a full carried slot
    and a shared mount point, `hostname`, and `growpart` left off for os-install with its note.
  - A host name `root@web-01` or `[::1]` is refused; a user or group `1000` is refused.
  - After filling: a `text` parameter set to `@@SF:b64:x@@` is a crit, a `path` parameter set to `/root/.ssh/authorized_keys` is a
    crit, and a mount device with a space is a crit, each in the prepare hook, the step check and the renderer.
  - The largest template the limits allow gives a vm-create Ansible `cmd`, and an Incus one, under 120 KiB.
- **Property tests** (hypothesis, already a test extra): every field and the extra block fuzzed with quotes, `$( )`, backticks, line
  breaks, `&`, `@@SF:`, `@@ref `, `${`, `%{` and NUL. The script passes `bash -n`, no template byte appears outside a base64 word,
  shellcheck stays clean, the HCL keeps `${` escaped, and no template byte appears in the Puppet output.
- **CT-02:**
  - The store on SQLite, and on PostgreSQL where `STORAGEFORGE_TEST_PG` is set: versions are immutable, a hash mismatch is refused, a
    pinned version cannot be deleted, remove keeps the versions, the limits hold.
  - Routes: the table entries, the audit rows without a body, `cloudinit.edit`, and `hosts.command` for commands, files, extra and
    (if the owner agrees) a user with keys and sudo.
  - A CLI round trip.
- **CT-05 to CT-08:**
  - The prepare hook pins `name` to `name@N:SHA`. A rotated vault key is refused at script time; saving the plan again recomputes
    the hash and the script passes.
  - A vm-create step made from a VM spec: the spec holds no `cloudinit`, the step's template is pinned, and the pin hook runs after
    `expand()`.
  - A script made from an unsaved body with a bare name is refused.
  - `plan_hash` of a plan saved before the fields existed is unchanged.
  - The check items above.
  - Each script part in Bash with the tools stubbed: the seed's file list and its mode, the snippet path and the `--cicustom` words,
    `incus init ... <FILE` with nothing of the template in the argv or the info line, the NoCloud folder at 0700 and 0600.
  - Slot filling with an `&` and a `/` in the value.
- **CT-04:** `plan_secrets` lists a template's secrets with their `how`. A `pwhash`-only secret is never sent in clear by
  StorageForge's apply. A password secret name of 59 characters is refused at template save. A file secret reaches the guest without
  the delivery newline. An exported plan with a password and only the cleartext from `vault send-secret` hashes it with openssl, and
  without openssl is a conflict. A report carries none. The value of a test secret never appears in the plan,
  script, export, preview, deploy_runs output or audit (the search the secret store tests do). Incus, XO, Proxmox native and Proxmox
  snippets refuse, each with its reason. The sha512-crypt function, if chosen, matches the fixed vectors.
- **CT-09:** the XO step's report makes no write, apply makes one POST with the tag, a second apply finds the tag and makes nothing,
  and a read-only connection refuses. Run against recorded answers, as the other API readers are tested.
- **CT-11:** in-process Flask tests for the JSON the page uses. Browser checks only on the owner's word, through the repo's own
  headless harness, one run at a time: the First boot page shows on the three wizard kinds (`vm-create`, `pve-vm` with source
  `image`, `incus`) and not on `vm-iso` or `pve-vm` with source `iso`, the Changes form shows the fields for `os-install`, the preview
  shows slots and never a value, *Make a template from this VM* copies the guest agent and the DHCP network and makes no `address`
  parameter, the disabled XO button shows its reason.

### The lab (CT-13)

Run with 0.7.0's lab run (rule 7), as a systemd user unit, with `SFLAB_DIR=sflab-run`, and no lab script edited mid-run. 0.6.10 ships as
*built and unit-tested*.

One template, `ct-lab`: two users (one with a vault password), packages (htop, curl), a file, a secret file, a first-boot command, a
swap file, a static address given as a parameter, `{name}.{domain}`, and power off.

- `sf-ubuntu`, libvirt: Debian 13 and Alpine 3.24, the two that differ in sudo, OpenRC and PAM. The Alpine key-only user logs in.
- `sf-ubuntu`, Incus: a VM and a container from `images:debian/13/cloud`, with a copy of the template without secrets, plus the
  refusal of the one with secrets. It proves `incus init` reads config from stdin.
- `sf-pve`, twice: with snippets on a local dir storage, and with no snippets storage (the warn lists the fields left out, and the VM
  comes up with its login). It reads `qm cloudinit dump` for the login part, and answers who can read a snippet and
  `/cloudinit/dump` with a VM.Audit-only token. That answer decides whether secrets open on Proxmox.
- `sf-xcp`, through XO: only if CT-09's checkpoint says yes.
- `sf-truenas`: as CT-09 decides.
- One `os-install` run and one `vm clone --template` run.
- Debian 12, Rocky 9 and Alpine 3.24 boot the same template, and the check's per-image warnings match what happened.
- After first boot, each VM is scanned. The scan shows the users, groups, packages, files with their modes, the time zone, the address
  and the host name the template said. The StorageForge login still works and the scan binds.
- A Login-only plan saved before 0.6.10 deploys with the same seed bytes, with the hash and stamp masked.

PostgreSQL light and medium run on the local container before the tag.

## Commit order

Each line is one commit that passes its own tests and the light block, with its own changelog line, so the tree is releasable after
each. Plans without a template render today's bytes from the first commit on.

1. **CT-01a, tests only.** The goldens of the four writers' Login-only output, from HEAD's Bash, and the old-plan test: same
   `plan_hash` for every step, same script text for pve-vm, incus and the untouched steps only (see *Migration*).
2. **CT-10a, Fix** (rule 3, its own commit, its test written first; CT-10's first part, moved early).
   The export's `randhash` is the deterministic one of *Slots*, so re-exports are byte-identical. The Terraform export writes vm-create's document: sudo only when
   the step asks, an unlocked login with a hash nobody knows so Alpine accepts the key, and the guest agent and Alpine sudo packages.
   Changelog: "The Terraform and OpenTofu export of a VM gives its login account sudo only when the step does, as the script always
   did, and an Alpine VM accepts its key". A security-relevant drift: tell the owner.
3. **CT-01b, Duplicate.** `cloudinit.py` with the four Login-only flavours and the slots. vm-create, os-install, pve-vm and the export
   call it, and the goldens are unchanged. It changes the generated scripts of vm-create and os-install without changing behaviour,
   so it is on rule 7's lab list.
4. **CT-03, Feature.** The template body, its field checks, parameters and the extra block with its refusals, the vendored known-keys
   file with its `FETCHED` and `SOURCES` header (step 10 of the extra block), and `render` with a template. Pure functions, no
   storage, nothing calls them yet. Save and render refuse `password_secret` and `content_secret` with "secrets in templates come with
   CT-04", so no tree between this commit and commit 8 can save or deploy a template whose secret would end as an unfilled marker.
5. **CT-02, Feature.** The migration, the store with immutable versions and remove, the API, the CLI, `cloudinit.edit` and the
   `hosts.command` gate, the route tables, the route index and audit. Templates can be made and previewed.
6. **CT-05 and CT-12's controller half, Feature.** vm-create's fields, the pin, the unpinned refusal, delivery by `args_of`, the umask
   077 ISO, the `dynamic_ownership` note, the step check's use of the vendored known keys. `vm clone --set cloudinit=` works from here. Bash and Ansible follow
   by construction.
7. **CT-11, Feature.** The Workloads page dialog, editor, preview and compare, the First boot page, and *Make a template from this VM*,
   for vm-create. An early "libvirt only" 0.6.10 tag after this commit is open question 10.
8. **CT-04, Feature. Major checkpoint, before merge.** `SECRETS_OF` with `(name, how)` into `plan_secrets` and `stream()`, the
   chosen hashing, the export's openssl fallback, the `pwhash` and `b64` slots, and the per-system refusals. It lifts commit 4's
   refusal of `password_secret` and `content_secret`.
9. **CT-07, Feature.** Incus: the instance YAML on stdin, the image variant crit, the profile key reads, secrets refused.
10. **CT-06, Feature.** Proxmox VE: snippets with the login inside, the undo, the native fallback with its list, `snippet_storage` and
    `cloudinit_strict`, secrets refused.
11. **CT-08, Feature.** The OS install from a template, with its network refusal, and `vm clone --template`.
12. **CT-10b, Duplicate.** Terraform and OpenTofu (`libvirt_cloudinit_disk` with network-config, `incus_instance`, and `pve-vm` as a new
    export with `cicustom`), with secrets left out, and Puppet's comment for an Incus instance with a template.
13. **CT-12's host half, Feature.** `cloud-init schema` in report mode, as an info line.
14. **CT-09, Feature. Major checkpoint, before merge.** Xen Orchestra's `create-vm` action and its controller-side step, and TrueNAS's
    `truenas-seed`, or the written decisions in the ledger. Last, because it opens a new execution path.
15. **CT-13** with 0.7.0's lab run. Its results are a major checkpoint.
16. **CT-14.** `docs/cloud-init-templates.md`, the VM, Proxmox, Incus, OS install and migration pages updated, and the changelog with
    every *not lab-tested* label.

Then the version, the changelog heading and the tag (rule 8). Tell the owner it is ready to sign.

## Risks

1. **Drift after approval.** A template resolved by name at deploy would let someone with `cloudinit.edit` change what an approved
   plan does while its `plan_hash` and "ran" mark stay the same. The pin with its hash, including the vault keys, closes it.
2. **The first API write (CT-09).** Nothing writes through an API connection today. It runs neither through the signed runner nor a
   report-first script, and XO accepts duplicate names. It needs the owner's yes and the tag.
3. **Root in every guest.** `runcmd`, `write_files` and extra are root commands in each new VM. `plans.edit` is all the `/api/vm`
   write routes need today (`permissions.py:197`). Hence `hosts.command` for those parts.
4. **Secret exposure per system.** Proxmox's exposure is unproven, so secrets are refused there until CT-13.
5. **Where the password is hashed.** On the host, the cleartext stays in the hypervisor's `/run` until reboot. In the controller, the
   project carries its own sha512-crypt.
6. **Byte-for-byte rests on the hand emitter.** The `IFS=,` join is the trap. The goldens come from HEAD's Bash, never by hand.
7. **bash 5.2 `patsub_replacement`.** Slots are filled by cutting at the marker, never with `${x//pat/$val}`.
8. **The seed ISO is probably world-readable today.** That is harmless while it holds a public key and a hash of nothing, but not once
   it holds a template's hash. umask 077 fixes it and depends on `dynamic_ownership`.
9. **Old cloud-init on images.** Module support and network translation differ (ntp, `write_files` `defer`, network v2 on sysconfig,
   eni and NetworkManager, locale on Alpine). The hypervisor's `cloud-init schema` does not speak for the guest. A per-image-family
   table, proven in CT-13, and a warning for custom images.
10. **Interface names differ** (enp1s0 on libvirt, ens18 on Proxmox, eth0 on Incus), and the MAC is not known before create. Static
    network matches by name glob by default.
11. **Incus profiles** lose their `cloud-init.*` keys to the instance's, and a container image without cloud-init ignores them. Both
    are reported.
12. **Proxmox without snippets** could drop fields. It is a listed warn, with the opt-in crit.
13. **Snippets and seeds outlive their VM** when it is removed outside StorageForge. Documented.
14. **Version growth.** No pruning, bounded by 100 versions and 200 templates.
15. **The new permission.** Custom roles do not get `cloudinit.edit`. A changelog line.
16. **People expect an edit to reach every plan.** The "v4 exists" note answers it and must be easy to see.

## Open questions for the owner

1. Should a plan pin a reference with its hash (proposed), or copy the template body into itself?
2. CT-04: hash the password in the controller after release (proposed, matches "never sent as text"), or on the host with openssl, as
   `pve-ct` does with its root password?
3. Proxmox without snippets: a warn that lists the fields left out and makes the VM (proposed, as the roadmap reads), or a crit?
4. CT-09, Xen Orchestra: is a controller-side plan step that writes through the API acceptable under rule 5? The REST endpoint or
   JSON-RPC `vm.create`? Or the written decision?
5. TrueNAS: an ISO writer on the appliance, pycdlib (a new dependency), a hand-written ISO or VFAT image, or the written decision?
   Is a root `midclt` attach over SSH acceptable?
6. Extra block: refuse configuration-management pulls (ansible, puppet, chef, salt) outright (proposed), or allow them with a warning?
7. Secrets on Proxmox snippets: refused until the lab proves who reads them (proposed), or allowed on local storage from the start?
8. Is `hosts.command` required, beside `cloudinit.edit`, for templates with commands, files, extra, or a user with keys and sudo
   (proposed)? A keyed sudo user is root on every VM made from the template just as a command is.
9. The CLI audits template saves (proposed), while the CLI-against-web audit decision stays open?
10. May 0.6.10 be tagged early as "libvirt only" after commit 7, or only after CT-14?
11. Should a removed template's versions ever be purged once no plan names them?

## Post-1.0 list

New features this spec leaves out. The freeze is at 0.8.0, so none of these lands before 1.0.

- *Make a template from a scanned host* (its users and packages), not only from a filled VM step.
- Importing an existing cloud-config YAML into the plain fields. The extra block covers the need until then.
- Importing templates from other tools (snippets already on a node, Terraform files).
- vendor-data with content.
- Templates for VMs made from an ISO, once unattended installs exist.

## Left to the builder

- The editor's styling within `tokens.css` and `components.css`, and the chips.
- The per-image-family capability table's first contents, before CT-13 corrects it.
- The vendored known-keys file's format, and the script that refreshes it.
- Splitting `cloudinit.py` if the extra block's loader grows past the size of the other modules.
