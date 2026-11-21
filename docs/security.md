# Security

StorageForge holds SSH keys that reach every host, and it can run root scripts on hosts set up for deploys. This page describes how those are protected. Findings and fixes from the reviews are in [security-audit-2026-10-28.md](../security-audit-2026-10-28.md).

StorageForge is meant for a LAN behind its TLS proxy. Do not publish it on the internet. The one port that may face it is the optional [tunnel for remote nodes](remote-nodes.md).

## Key vault

```text
STORAGEFORGE_VAULT_SECRET ──Argon2id(salt, t=3, m=64 MiB, p=4)──► KEK (32 bytes, never stored)
KEK ──AES-256-GCM──► wraps one random DEK per key, the audit MAC key and a verifier
DEK ──AES-256-GCM──► encrypts the OpenSSH private key
```

- **Associated data** binds every ciphertext to its row and purpose, so a ciphertext copied into another row fails to decrypt. A GCM-encrypted verifier detects a wrong secret.
- **Weak keys:** RSA below 3072 bits is refused. Passphrase-protected keys are accepted with `--passphrase-env` and stored decrypted inside the vault.
- **Rotation:** `STORAGEFORGE_VAULT_NEW_SECRET=… storageforge-index vault rotate-secret` rewraps every DEK and the audit key under a new KEK in one transaction. Key ciphertexts never change.
- **At run time** a key is decrypted with `update_into` into an `mlock`ed buffer, written to `ssh-add -` from it, and zeroed. Each task gets its own `ssh-agent -D -a` in a fresh 0700 directory on the tmpfs runtime dir, with a key lifetime limit; the agent is killed and the directory removed when the task ends. `ssh` runs with `-F /dev/null`, `IdentityAgent=<socket>`, `BatchMode`, password auth off and a persistent `known_hosts`.
- **Child processes** (`ssh` and others) never see `STORAGEFORGE_*` variables.

Python cannot promise no other copy of a secret exists in memory: the environment variable and import paths are ordinary objects. The design minimises how long plaintext lives and never writes it to disk; it does not claim zero copies.

Backups never contain the vault secret, on purpose: a backup together with its secret would be the keys. Keep the vault secret safe somewhere else (`docker compose exec storageforge cat /run/sf-secrets/vault_secret`).

### Key enclave

*New in 0.5.5. Built, not lab-tested: its lab tier (19) is written and has not run. It is off unless `STORAGEFORGE_ENCLAVE` is set.*

A second layer on the vault's keys: a micro VM whose only program holds the KEK, and whose only device is a vsock socket. It has no network card, no disk and no shell. The web app hands it the vault's own ciphertexts with each request, so nothing stored changes format and the vault opens as before without it.

```text
web app ──vsock, encrypted──► enclave: unlock · lock · status · sign with key K · make or take in a key · MAC for the audit chain
                            seal and release a secret · rotate the vault secret · step-up · the audit chain's head
```

**Running it.** With `STORAGEFORGE_ENCLAVE=vm` the server starts the micro VM itself from the image in `STORAGEFORGE_ENCLAVE_IMAGE_DIR`, and refuses to start if it cannot: the image's files must match its `SHA256SUMS` and, where `STORAGEFORGE_ENCLAVE_IMAGE` pins a digest, that digest; what answers must say it is the VM's only program with its memory locked. The VM gets one device, the vsock socket: no network card, no disk, no shared folder. Two programs can run it from the same image. Firecracker is the one in the shipped image and is used where it is installed; it needs `/dev/kvm` and nothing else, runs under its own seccomp filter, and cannot be reconfigured once started. QEMU's `microvm` is for a developer's machine and the lab; it needs `/dev/vhost-vsock` too and runs under QEMU's seccomp sandbox. Either gets none of the server's environment. Firecracker's jailer is not used: it needs root, and the server's container has neither root nor any capability, so the container itself (read-only root, no capabilities, no new privileges) is what surrounds Firecracker.

In Docker, add `docker-compose.enclave.yml` to the compose command and set `STORAGEFORGE_KVM_GID` to the group of `/dev/kvm` on the Docker host (`stat -c %g /dev/kvm`). The container gets that one device and that one group. The image holds the enclave's kernel and initramfs, built by the same script as `enclave/image/build.sh`, so `SHA256SUMS` in `/usr/share/storageforge/enclave` can be compared with a build of your own. A command run beside the server that needs a key (`docker compose run admin …`) starts an enclave of its own for as long as it runs; one that needs no key starts none. If the VM stops, the server says so in its log, the audit log (`enclave.down`) and the notification center (critical, and it cannot be muted; a locked enclave is a warning, one that locked itself down is critical), starts it again at the same address, and until it is unlocked again every operation that needs a key fails. `STORAGEFORGE_ENCLAVE=vsock:CID:PORT` uses an enclave something else runs.

With it set:

- **SSH keys are not decrypted in the web app.** Each task's agent socket is served by the web app, lists the one public key, and asks the enclave for each signature. Deploy requests and evidence bundles are signed the same way. A new ed25519 key is made inside and its private half is never outside.
- **The audit chain's MAC key stays inside.** Each entry's MAC is computed there; the chain is the same chain, and either side verifies what the other wrote.
- **The secret is needed once, and not by the web app.** Whoever unlocks the enclave hands it over; after that the web app works without it (see *Unlocking it* below).
- **It fails closed.** An enclave that does not answer, is locked, or has locked itself down after five malformed requests is a locked vault. The web app does not fall back to opening the vault itself.
- **Its limits are its own:** six unlock attempts a minute, 600 signatures a minute per key, 60 releases a minute per secret and 600 an hour altogether, five step-ups a minute a person, one request at a time, a 1 MiB frame. The web app cannot raise them.
- **Each kind of task has an allowance of its own** on top of the one per key: every signature says what it is for (scan 1200 a minute, deploy 600, device 300, git 300, signing requests 300, console 120, rotation 120, access set-up 60, anything else 120), and secrets leave at most 120 times a minute for one kind of step or platform. The kind is the web app's word, so it cannot get more out of a key than the key's own limit gives; what it does is keep one kind of work from using up what the others need, and show in the counts which kind asked for what. **Keys → Key enclave** shows the counts by kind.
- **Its counts open notifications.** The enclave counts what it refused, inside, where the web app cannot change the numbers, and the notification center reads them: requests refused at a limit, ciphertexts or secrets that did not authenticate (three in an hour is a warning, twenty critical), step-ups that failed, requests that came without the step-up they needed, secrets asked for what their policy does not name, many releases in an hour, audit entries that were signed and not written, a released secret missing from the log, a log that was cut, and malformed requests on the way to a lock-down. Each says how many in the last hour and leaves an hour after the count last moved. They are security findings: none can be muted or snoozed.

- **A secret that has to leave is released, not read, and for something named.** A device password or a step's secret is sealed inside and given back one request at a time, for a named step, host or platform. The enclave counts each release and gives any one secret at most 60 times a minute. What was sealed as a private key cannot be asked for this way.
- **A secret can carry a policy:** the steps, hosts and platforms it may be released for, and whether it is sensitive (`vault secret-add NAME --step tailscale --for-host nas1 --sensitive`, `vault secret-policy NAME` to show or change it, `--none` to take it off). The policy is in the secret's associated data, so the copy stored beside it cannot be changed or left out: the secret then does not open. A release for anything the policy does not name is refused inside, and a sensitive one takes a step-up token.
- **Every release is written into the audit log by the enclave.** It makes the entry itself (`enclave.release`: which secret, for what, the how-manieth release, who stepped up), signs it into the chain after the log's last entry, and only then hands the secret over. The web app stores the entry. One it keeps to itself leaves a log that no longer ends where the enclave says, and the enclave counts it. A release the enclave refused is written up by the web app as `denied`.
- **The enclave keeps the head of the audit chain.** It remembers the entry it signed last. A log that was cut short in the database still verifies entry by entry, since what is left is a chain; it no longer ends where the enclave signed it. `audit verify` and **Audit → Verify chain** say so, a notification opens, and no secret is released until a person has looked and taken the log as it is (**Keys → Key enclave**, written to the log with their name). Entries others wrote after the head, by a command with an enclave of its own or without the key while it was locked, are shown to the enclave one by one and it checks each follows the one before. Cutting exactly the last entry looks like a write that failed: it is counted, and shown as a warning. The head is in the enclave's memory, so a restart forgets it and the enclave takes the log as it finds it at the next entry; restarts are in the audit log and the notification center.
- **An imported key is sealed inside** after the enclave has checked it can sign with it (RSA below 3072 bits is refused there too). It passed through the web app to get there, which is the reason for the `generate-only` key policy.
- **The vault secret is rotated inside.** The enclave derives the new KEK and rewraps each DEK without letting one out, and switches only when every row is written; a rotation that fails part way changes nothing.

The web app never opens the KEK when the enclave is configured. What still passes through it: a key being imported, an RSA key (made in the web app and imported, since the enclave makes ed25519 and ECDSA), a secret on its way in or out, and the vault secret itself at the first unlock and at a rotation.

**Where it is not there.** On a machine with no KVM (a VPS without nested virtualization, say) the enclave cannot run, and without `STORAGEFORGE_ENCLAVE` it is off: the vault then opens its keys in the web app, as before 0.5.5. **Keys → Key enclave** and the **Security** overview (*This server's keys*) say so in words, with the reason this machine cannot run it where that is the case: *Key enclave: off. The extra layer is not there.* Where it runs as a plain program on a socket file, which is for development and tests, the same line says it is not a micro VM.

**Unlocking it.** A restarted enclave holds nothing until it is given the vault secret again. Three ways hand it over, and none leaves it in the web app:

- **The starter, apart.** `storageforge-index vault starter` is a process of its own: it reads `STORAGEFORGE_VAULT_SECRET_FILE` once, hands the secret to the enclave the server runs (the server writes where that is to `enclave.addr` in its runtime folder), overwrites its copy and ends. With `--watch` it stays, holding nothing, and reads the file again only when the enclave has come back locked after a restart. `docker-compose.enclave.yml` runs it as the `starter` service and moves the vault secret to a volume of its own (`sf-vault-secret`) that the server's container does not mount, so the server has neither the secret nor the file. The server then starts with `STORAGEFORGE_VAULT_SECRET_APART=1` and refuses to start if it is given a secret all the same.
- **The starter, in place.** A server that does find the secret in its own environment hands it over once as it starts, overwrites the variable where `/proc/PID/environ` shows it and takes both variables out of its environment. A secret file the server's account can read is still a file it can read, and Python cannot promise no copy of the bytes is left in its memory: the starter apart is the one that closes that.
- **A person.** **Keys → Key enclave** shows a locked enclave with a field for the vault secret (`POST /api/enclave/unlock`, which takes `keys.manage` and a fresh password). The secret crosses the web app once, on its way in, and is checked only inside the enclave. Every attempt is in the audit log, without the secret.

An enclave that locked itself down is never unlocked by a starter: a person looks at what sent the malformed requests first, and then unlocks it on the Keys page. **Lock the enclave** there (`POST /api/enclave/lock`) makes it forget every key at once.

**Step-up, checked inside.** The web app's own rule, the password typed within the last five minutes, is the web app's word, and a web app that has been taken over can give it for anyone. For what matters most the enclave checks the person itself:

- **What takes it:** making or importing a key, rotating the vault secret, enrolling another person, and lifting a lock-down. Signing with a key that is already there takes none, so scans and deploys still run unattended.
- **What it checks:** a password against a hash it holds (Argon2id), or a FIDO2 assertion against a public key it holds and a challenge it made itself, which counts once. The record of each person is sealed under the KEK and kept in the database (`enclave_stepup`) like every other ciphertext; only the enclave reads it.
- **What comes back** is a token good for five minutes, kept in the server for that session and never in the cookie. Tokens rotate by themselves: none lives longer, and none survives a lock or a restart. Five tries a minute a person, counted inside.
- **Enrolling:** **Keys → Key enclave → Enroll your password with the enclave** takes your account password and the security keys the account already has. The first person needs nothing more: until then there is no step-up to pass. After that a new record takes a step-up of your own or the vault secret. `storageforge-index vault stepup-enroll USER` does it from the server's shell, the password on stdin, and `vault stepup-forget USER` removes a record. Changing your account password gives the enclave the new one. A security key added later is not in the record until you enroll again.
- **Whoever holds the vault secret needs no person:** a command run with the secret gets its own token from it.

What it does not do. A password is typed into the web app on its way to the enclave, so a web app that is taken over and waits sees the next one typed; a security key's answer cannot be kept and used again. The enclave knows step-up is on because it is shown a record when it is unlocked, so whoever can write the database can remove every record before a restart: set `STORAGEFORGE_ENCLAVE_STEPUP=required` where the enclave is unlocked from (the starter's environment) to insist on it whatever is shown. A record of an earlier password, kept by someone who could read the database then, still opens: the enclave has no disk to remember that it was replaced. Step-up with a physical FIDO2 token is not lab-tested; the tests make the assertions in software.

To read the vault secret for safekeeping with this compose file: `docker compose -f docker-compose.yml -f docker-compose.enclave.yml run --rm --entrypoint cat admin /run/sf-vault/vault_secret`. To go back to a stack without the enclave, put that secret in `./secrets/vault_secret` before deploying without the file.

What does not work with the secret apart: the nightly copy of a backup to another host, which the server encrypts with a key derived from the vault secret, has no secret to derive it from and is not made. The backup itself still is. Until that key is derived inside the enclave, copy backups off with a command that holds the secret (`docker compose … run --rm admin backup …`), or use the starter in place.

#### Layers

*The owner's direction of 2026-11-18: a flaw in one layer must not give up the keys. Built, not lab-tested.*

**A second lock on the KEK.** Without it the KEK comes from the vault secret alone, so the secret beside a stolen database, or a backup with its secret, is the keys. `storageforge-index vault second-lock on` (run by whoever holds the vault secret) makes a second share, 32 random bytes in a file only its owner can read, and mixes it into the KEK:

```text
KEK = HMAC-SHA256(key = host share, "storageforge:second-lock:v1" ‖ 0 ‖ Argon2id(vault secret))
```

- The secret alone then derives a key that opens nothing, on this machine or any other. This holds with the enclave, which mixes the share inside, and without it.
- Nothing stored changes format. Turning the lock on or off is a rotation: each DEK is rewrapped and no key's ciphertext is touched. `vault_meta.second_lock` says which way the KEK is derived. `vault second-lock off` is the way back, and `vault second-lock status` says which it is.
- The share is in `STORAGEFORGE_HOST_SHARE_FILE` (`/etc/storageforge/host_share` if not set), outside the database, its backups and the secret volume. A file others can read is refused. Whoever unlocks the vault reads it: the starter, or a command that holds the secret. `docker-compose.enclave.yml` mounts a folder of the Docker host for it (`STORAGEFORGE_HOST_SHARE_DIR`), read-only for the starter. Restart the server after turning the lock on or off, so that its enclave is unlocked again with what the vault now needs.
- **The recovery share** is printed once when the lock is turned on. With it and the database, `vault second-lock recover` (the share on stdin) writes the host share again on a machine that lost it, or on a new one. The database holds the host share sealed under a key made from the recovery share, and nothing else of it. Kept beside the vault secret, the recovery share undoes what the lock is for: keep them apart. Without the host share and without the recovery share the vault cannot be opened by anyone.
- **TPM:** sealing the share to the host's TPM is not built. It needs `tpm2-tools` and a TPM to test against, and neither was there. The share is a file.
- Backups of the database are encrypted from the vault secret alone, as before, so a backup can be read without the share; the keys inside it cannot be opened without it.

**The app speaks to the enclave over a channel of its own.** vsock is local to the host, but something else on the host should neither read it nor stand in for the enclave. Every connection begins with a Noise handshake (`Noise_NX_25519_AESGCM_SHA256`) and everything after it is encrypted, both ways, under keys of that one connection.

- The enclave makes a static key as it starts and proves in the handshake that it holds it. **The key is pinned at first start:** the server, which has just started the VM over a socket it made for it, pins the key the VM shows first (`enclave.pins` beside the enclave's socket, readable by the server's account only), and pins the new one when it restarts the VM. Every later client, in the server or beside it, refuses to speak to anything that shows another key at that address. So the vault secret is never sent to something that only sits where the enclave should be.
- For an enclave that something else runs, the key is pinned the first time it is spoken to. It makes a new key each time it starts: `storageforge-index vault enclave-pin` shows the pinned key, `--renew` pins the one it shows now, and `STORAGEFORGE_ENCLAVE_KEY` names the key to insist on instead.
- A frame changed on the way does not decrypt: the connection ends and the enclave counts it as a malformed request. What does not begin with the handshake gets no answer.
- What it is not: the handshake proves the enclave to the client, not the client to the enclave. Whoever can open the socket can still ask, under the same limits and with the same step-up. A client's first contact with an enclave nobody pinned for it trusts what answers.

**Keys that rotate by themselves.** What can rotate cheaply does, on a schedule, so that a key someone took is of use for a short time only:

- **The session-signing key** changes every `STORAGEFORGE_SESSION_ROTATE_HOURS` (24; `0` turns it off, and the session secret signs as before). It is made from two things kept in two places: the session secret in the server's secret file, and a random value made at each rotation and kept in the database. Either alone signs nothing. The keys of the last periods still check cookies for as long as a session can last (8 hours) and sign nothing, so nobody is signed out by a rotation, and a signing key read out of the server's memory is dead a day later.
- **The vault key** is derived again under a new salt every `STORAGEFORGE_KEK_ROTATE_DAYS` (30; `0` turns it off), and every DEK is rewrapped under it. No key's ciphertext is touched, and the vault opens with the same secret afterwards. With the enclave this happens inside, from the secret the enclave has held since it was unlocked: nobody hands it over again, and since it gives nobody anything it takes no step-up. Rotating to a *new* vault secret still does. Without the enclave the server derives it from the secret in its environment, as it does at start.
- **The enclave's tokens** last five minutes, and none survives a lock or a restart.
- **SSH keys** are rotated by the [`rotate`](#if-a-key-may-have-leaked) plan when the operator runs it: that changes what hosts trust, and is not done unasked. Job keys per run are made per send, as before. The agent's tunnel uses the agent's own key, which changes when the agent is enrolled again, and fresh keys for every session, which lasts at most fifteen minutes.
- A rotation that fails is in the audit log (`vault.rekey`, `session.key.rotate`) and in the notification center, tried again every few minutes, and the notification leaves when one succeeds. The key in use stays in use meanwhile.

**Sensitive routes that move.** A request that changes keys, bindings, the key enclave, deploys, consoles, host access or security keys carries a code that changes every 30 seconds. It rides in the path, as a 2FA code does: `POST /api/keys` is sent as `POST /api/~1a2b3c4d/keys`.

```text
code = first 8 hex digits of HMAC-SHA256(route key, "METHOD /api/route|" + floor(time / 30))
```

- The route key is a secret of the one session. A browser is given it once, in the answer to its sign-in, and keeps it. The server takes the code out of the path before anything routes, so permissions, the fresh-password rule and the audit log see the route as before, and checks the code for this half minute and the one on either side. The server's clock is the one that counts: sign-in and every refusal say what time it is.
- A session that asked for the key at sign-in, which the sign-in page does, must send the code from then on. The mark is in the signed session cookie and cannot be taken off. A browser that lost its key gets it again from `POST /api/routecode`, which takes the password.
- **What it is worth:** a recorded or guessed URL is dead half a minute later, a code for one route is no code for another, and a session cookie alone, copied to another machine, changes nothing on a sensitive route: it has no route key, and getting one takes the password. That is on top of the cookie, the same-origin check and the fresh-password rule.
- **What it is not:** a defence against someone who already runs code in the page or in the web app, who can read the key or skip the check. A moving path is not a secret. A client that signs in without asking for the key (a script using the API) is not asked for codes.
- The code is checked by the server. Checking it inside the enclave as well, for the operations that take a step-up, is not built: the enclave has no clock to share with a browser, and those operations already need a token the enclave gave for a proof it checked itself.

For the vault key to be derived again on a schedule the enclave holds the vault secret, and the host's share where the second lock is on, from unlock to lock, in its locked memory. Before this it held the secret only for the moment of unlock.

**The image** is built by `storageforge-indexer/enclave/image/build.sh`: a kernel without modules, an IP stack or block devices and with lockdown forced on, and an initramfs of one static file. The compiler image is pinned by digest and the kernel by checksum.

- **Reproducible, and recorded.** Two builds give the same bytes, file for file. `enclave/image/SHA256SUMS` in the repository records them for the sources as they are committed, so anyone can build the image and compare, and a change to the program or the kernel list shows as a change to that file. CI builds the image twice, compares the two, and compares both with the recorded lines.
- **Scanned.** CI scans the program's dependencies (`Cargo.lock`) and fails on a high or critical finding. The program is the only file in the image, and it is Rust with no C library beside it.
- **Signed.** `enclave/image/sign.sh OUT KEY` signs `SHA256SUMS` with an SSH key, as release tags are signed, in a namespace of its own (`storageforge-enclave`). CI signs with the release key where the run is given it (the secret `STORAGEFORGE_RELEASE_KEY`); a fork or a pull request is given none, and there the image is built and compared and not signed. With `STORAGEFORGE_ENCLAVE_SIGNERS` naming an allowed-signers file (`storageforge namespaces="storageforge-enclave" ssh-ed25519 AAAA…`), the server starts only an image whose `SHA256SUMS.sig` checks out against it, at start and at every restart. `sign.sh --verify OUT SIGNERS` checks the same by hand. The release key itself is the owner's: until its public half is in the repository and its private half in CI's secrets, images are compared by hash and not signed.
- **arm64.** `ARCH=arm64 enclave/image/build.sh` cross-compiles the same image for arm64 (`Image`, `initramfs.cpio.gz`), recorded in `enclave/image/SHA256SUMS.arm64` and built in CI. Here it was booted under QEMU's emulation, where it unlocked, made a key, signed, released a secret and verified an audit chain. It has not run under KVM or Firecracker on an arm64 machine, and the server's own supervisor starts only the x86-64 image so far.

### Secrets for plan steps

Some steps need a secret on the host they run on: the `tailscale` step needs an auth key. Such a secret is stored in the vault like a device credential (`vault secret-add NAME`, one line on stdin, so it is in no shell history), and never goes into a plan, a script, the Ansible playbook or a log.

*Since 0.5.9 (built, not lab-tested; lab tier 25 is written and has not run):* the **secret store** makes such secrets as well (a password, token, hex key, PIN or WireGuard key, `vault secret-generate` or **Keys → Secrets for plan steps**), shows a value once, when it is made or rotated, and never again. An apply from StorageForge brings the secrets a plan's steps name on the signed runner's stdin, released for that host and step when the run starts, and the script writes them to `/run/storageforge/secrets` before its first step; `vault send-secret` is still how a script run by hand gets one. A rotation sends the new value to every host the secret went to, beside the old one, and switches only when every host has it. The `secret-file` step writes a secret into a file a service reads. [Secrets for plan steps](secrets.md) has all of it, and [what the web app can and cannot get](secrets.md#what-the-web-app-can-and-cannot-get) from the store: in short, it sees a value when it makes one and when a plan or rotation has one released for a named host and step (each release written into the audit log by the key enclave, where there is one), and no route gives a value back; without the key enclave the web app holds the vault key and could open any secret, as it could any SSH key.

Tests search every value for the store's rules: the database outside its ciphertext, the plan, the generated script, the Ansible playbook, the run's output, a command line seen by stand-in programs, and the audit log.

`vault send-secret NAME --host HOST [--step STEP]` decrypts it (with the key enclave: has it released for that host and step, which a policy on the secret may name) and writes it to `/run/storageforge/secrets/NAME` on the host over SSH, on ssh's stdin. `/run` is in memory, the folder is mode 700 and the file mode 600, and both are gone at reboot. The login needs `sudo` without a password, as deploys do. The step reads the file there. The `tailscale` step hands it to Tailscale as `--auth-key=file:…`, so the key is on no command line, and removes it once the node has joined. Both commands write to the audit log, and neither prints the secret.

Two more steps take a secret the same way. Neither is lab-tested against the real service: Cloudflare needs an account, and the lab has no Pangolin server yet. The unit tests run them against stand-ins. One thing was checked against the real program: `cloudflared` 2026.10.4 lists `--token-file` and reads the file the unit names. No tunnel was started with it, and Newt has not been run at all.

| Step | The secret | How the program gets it |
| :--- | :--- | :--- |
| `cloudflare-tunnel` | a Cloudflare Tunnel token | moved to `/etc/cloudflared/storageforge-token` (root, mode 600) and read by `cloudflared tunnel run --token-file`, as the unit `storageforge-cloudflared` |
| `pangolin-site` | a Pangolin site secret | written with the site id and the server's address to `/etc/newt/storageforge.json` (root, mode 600), which Newt reads because the unit `storageforge-newt` sets `CONFIG_FILE` |

A tunnel's token is needed at every start, so unlike a Tailscale auth key it stays on the host, in that one file. The copy under `/run` is removed once the program runs. Both programs' own instructions put the secret on a command line (`cloudflared service install <token>`, `newt --secret <secret>`), where every account on the host can read it; these steps never do. A `cloudflared` too old to have `--token-file` (before April 2025) is refused. A unit the program's own installer made is left alone, and the step says so when that unit has the secret on its command line. Neither step installs the program. `state: absent` stops the unit and removes the file.

A tunnel makes what it publishes public with no port open: see [Tunnels](infrastructure-map.md#tunnels-public-with-no-port-open).

The steps that join a private network were each built only after reading how the program takes its secret (its own documentation and source, on 2026-11-20). None is lab-tested: the unit tests run `netbird`, `zerotier-cli` and `ziti-edge-tunnel` as stand-ins, and Nebula as the real program.

| Step | The secret | How the program gets it | What stays on the host |
| :--- | :--- | :--- | :--- |
| `netbird` | a NetBird setup key | `netbird up --setup-key-file /run/storageforge/secrets/NAME`: the client reads the file and hands the key to its daemon over a local socket | Nothing of the key: the file is removed once the peer has joined, and the peer keeps a key of its own |
| `tailscale` with Headscale | a pre-auth key `vault headscale-key` made on the Headscale server | It comes back inside the SSH connection, goes straight into the vault and is never printed. From there it travels like any auth key, and `tailscale up` reads it as `--auth-key=file:` | Nothing: the file is removed once the node has joined |
| `openziti` | a one-time enrollment token (a JWT) | `ziti-edge-tunnel enroll --jwt /run/storageforge/secrets/NAME` | The identity file the enrollment writes, which holds a private key made on the host: mode 640 for root and the group `ziti` where the packaged service is there, 600 otherwise. The token file is removed, and a token works once |
| `zerotier` | none | A network is joined by its id, which is in the plan. Whether the node is let in is decided at the controller | |
| `nebula` | none that travels | The host makes its own key pair (`nebula-cert keygen`, in `/etc/nebula`, mode 600, root). Only the public half is read. The CA key is a vault key and signs in the vault, in the key enclave where there is one. The certificate, the CA certificate and the configuration are public, and the last two are written into the plan's script | The host's private key, where Nebula needs it at every start. `state: absent` removes it |

If a program repeats its secret when it fails, the step takes it out of what it reports. A NetBird too old to have `--setup-key-file` is refused, because it could only take the key as an argument.

**Netmaker has no step.** `netclient join -t TOKEN` is the only way netclient takes its enrollment token, and its own container script builds the same command line. The token registers a machine on the network, and a command line is readable by every account on the host, so StorageForge does not run it.

**The Nebula CA.** The CA's certificate and the list of what it issued are kept as a setting, with no key in it. A certificate from here always has one address inside the CA's networks, an end no later than the CA's own, and the CA's fingerprint as its issuer. An address is given to a second name only after the first one's certificate is revoked. Revoking does not reach a host by itself: a host refuses a revoked certificate once the `nebula` step has run on it again, and a tunnel that is already up stays up until its next handshake. Making a CA, issuing and revoking are in the audit log (`vault.nebula_ca`, `vault.nebula_issue`, `vault.nebula_revoke`). They are commands of `storageforge-index vault`, run by someone who can unlock the vault: there is no page or API route for them yet.

### Platform API tokens

*Since 0.5.10 (built, not lab-tested; lab tier 27 is written and has not run):* StorageForge can read Proxmox VE, Backup Server and Datacenter Manager, TrueNAS, Xen Orchestra, Dockhand, Portainer, Komodo and Pangolin through their own APIs ([Platform connections](api-connections.md)). What holds for the tokens it keeps for them:

- **The least, always shown first.** Before a token is asked for, the guide shows the narrowest role and scope that does the job (`PVEAuditor`, `DatastoreAudit`, PDM's `Auditor` on named remotes, TrueNAS's `READONLY_ADMIN`, a Xen Orchestra role with read on six resources, Portainer's Read-only user, a Komodo group with Read, five list permissions on a Pangolin key) and the steps that make it. `root@pam`, TrueNAS's root, `truenas_admin` and `admin`, Xen Orchestra's `admin@admin.net` and Portainer's `admin` are refused outright. An action that needs more says what, on which object, when it is turned on.
- **Where a platform cannot narrow a token, the finding says so.** Dockhand without an enterprise key gives every user full access, and Portainer Community Edition has no read-only role: StorageForge still reads them, and the read-back raises the finding that cannot be muted. Dockhand also gives a token no way to read its own permissions, and the read-back says that plainly instead of guessing.
- **An expiry, and a warning before it lapses.** The guide sets an expiry wherever the platform allows one; the read-back reads it where the platform says, and otherwise the date given with the token is used. A notification comes 30 days before and turns critical in the last week. Portainer and Pangolin keys cannot expire: the guide says to replace them on a schedule.
- **A new token replaces the old one without a gap.** It is sealed beside the old one, read back against the platform, and taken only when the platform takes it, it reads what the old one read and it can do no more than StorageForge needs; otherwise it is dropped and the old one stays. The old token keeps working on the platform until it is deleted there, and the connection says so until a person confirms it.
- **Read back on every read.** The platform is asked what the token can really do. A privilege that changes something and that no turned-on action needs is a security finding that cannot be muted or snoozed (critical when it reaches users, permissions or the system), and it leaves when the token is narrowed.
- **Sealed for one platform.** The token is a vault row (inside the key enclave when it is configured) whose sealed policy releases it only for that platform instance. It goes into the one header the platform reads it from (or, for TrueNAS, into the login call inside the TLS connection) and nowhere else: never a URL, a command line, a log line, an audit row or an error message. Tests search each of those for it, for every platform. A redirect is followed only to another API path on the same server.
- **Secrets a platform hands back are dropped.** Xen Orchestra's list of a user's tokens holds the tokens themselves: only the expiry of the one in use is taken from it, in memory. A Dockhand license key, Portainer stack variables, TrueNAS replication credentials and the remotes' tokens in PDM's list are never kept.
- **The certificate is accepted by a person, then pinned.** Nothing is sent with the token before you accept the platform's certificate by its SHA-256 fingerprint, and a changed certificate gets nothing and raises a critical finding that cannot be muted.
- **Read-only by default**, with plain HTTP refused, a timeout on every request, a rate limit per platform and a cap on each read.

What a taken-over web app can do with a stored token, and what stops it, is in [Platform connections](api-connections.md#what-a-taken-over-web-app-can-do-with-a-stored-token): in short, it can use a token for its own platform within the enclave's limits, each release written up, and do there only what the token's role allows, which the guide keeps to reading.

### Console keys

A key bound with `--actions console` opens a terminal from the web UI ([Console](console.md)), as the binding's login. It is kept apart from scan bindings, so the read-only scan login never becomes a shell. Sessions take only host keys a scan confirmed, forward nothing, and are audited when they open and close. With recording on, they are kept in full, input included.

### SSH certificates

Built, not lab-tested: the unit tests run both steps against a real `sshd` on the build machine, and lab tier 21 is written and has not run.

StorageForge can be a certificate authority for SSH. The CA is one more key in the vault, named `storageforge-ssh-ca`, made there (**Keys → SSH certificates → Make the SSH CA**) and never imported. With the key enclave it is made inside the enclave and signs there. It can be bound to no host: it signs certificates and logs in nowhere.

**What a host is given.** The `ssh-ca-trust` plan step (Changes, group Hardening, or **Stage trust** on the Keys page) writes four things and nothing else:

| File | What it holds |
| :--- | :--- |
| `/etc/ssh/storageforge_user_ca.pub` | the CA's public key |
| `/etc/ssh/storageforge_principals/<user>` | who may log in as `<user>` with a certificate: `<user>@<host name>`, and any principals you added |
| `/etc/ssh/storageforge_revoked_keys` | the list of revoked certificates, with its version beside it |
| `/etc/ssh/sshd_config.d/50-storageforge-ca.conf` | `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`, `RevokedKeys`, and `HostCertificate` if you asked for it |

It does not set `AuthorizedKeysFile` or `PubkeyAuthentication`, so every key that logged in before still does. A user with no principals file cannot log in with a certificate and can with a key. Before `sshd` is reloaded the step runs `sshd -t`, then asks `sshd -T` whether the three settings took effect and whether keys are still read from the same place. If any of that fails, or `sshd` does not reload, the files are put back from a copy taken first. With a rollback timer set (10 minutes from the Keys page), the host puts them back by itself unless StorageForge reaches it again. A host that already has a `TrustedUserCAKeys`, an `AuthorizedPrincipalsFile` or a `RevokedKeys` of its own is left alone: `sshd` takes one of each, and StorageForge does not replace yours. `state: absent` removes the four files and leaves `authorized_keys` as it is.

**Logins.** Certificates are opt-in per host, for the web console, for scans, or both (**Console** and **Scans** on the Keys page). For a host that is opted in, each console session and each scan gets a certificate for the key its binding already names:

- one principal, `<user>@<host>`, so it logs in as that user on that host and nowhere else;
- 5 minutes for a console (only the login has to fall inside it; an open session is not cut), 60 minutes for a scan;
- a terminal for the console and nothing for a scan. No port, agent or X11 forwarding in either;
- a serial number, and a key id that says what it is for and who asked, which `sshd` writes to its log.

The private key stays where it was, in the agent or the enclave. The certificate is not secret; it is written to a file for `ssh` and removed after. `ssh` offers the certificate first and the plain key after it, so opting a host in before it trusts the CA breaks nothing. Once certificates work on a host you can remove the key from `authorized_keys` there yourself; StorageForge does not do that for you. Each certificate is a row under Keys and an `ssh.certificate` row in the vault's audit log. If one cannot be made, that is logged and the login goes on with the key.

**Revoking.** **Revoke** marks the certificate and raises the version of the revocation list. The host learns of it when the `ssh-ca-krl` step has run there (**Stage the list for the hosts**): until then the certificate still works, for the minutes it has left. `sshd` reads the list at every login, so no reload is needed. Because `sshd` refuses every key when it cannot read the file `RevokedKeys` names, the step checks a new list with `ssh-keygen` on the host and moves it into place in one rename, and an older list never replaces a newer one. A list holds at most 8000 certificates that have not ended.

**Host certificates** are optional. **Issue host certificate** signs the host key a scan pinned, for the host's name and the address it is scanned at, for 90 days; the trust step installs it when *Install this host's certificate too* is set. A client with the `@cert-authority` line for the CA then accepts the host without having seen its key. A certificate that ends within 14 days raises a notification.

What this does not do: it does not issue certificates to people. Only StorageForge's own console and scan logins get them.

## Bindings

`key_bindings` maps a key to an exact host or IP, a glob (`*.tailnet.ts.net`) or a CIDR, with a user, port and allowed actions (`scan`, `checksum`, `deploy`). The most specific match wins: exact host, then glob, then longest prefix, then the lowest priority number. `vault resolve --host H` shows which key and user a host would get.

### The scan key's line on a host

A scan key is a login: whoever can make StorageForge run a command over it has the account it logs in to. So the line StorageForge writes into `authorized_keys`, when a key is installed from Keys and when one is rotated, is `restrict,pty ssh-ed25519 AAAA… name`: no port, agent or X11 forwarding and no `~/.ssh/rc`, with a terminal kept for the console. Set `STORAGEFORGE_SSH_FROM` to the addresses or networks the controller logs in from, as the hosts see them (`10.42.0.3`, or the Docker network on the controller's own host), and the line also carries `from="…"`: a stolen key is then of no use from anywhere else. `restrict` does not stop a command: scans are commands.

Each scan reads which options every key line carries (the option names only: a forced command's text never leaves the host). Two findings follow, both warnings:

- **A StorageForge key with no restrictions** (`key-unrestricted`): a line written by hand or by a version before 0.5.10. Install the key again from Keys, or put `restrict,pty` in front of it on that line.
- **A StorageForge key in an account that is root in effect** (`key-account-root`): the account is in `docker`, `lxd`, `incus-admin`, `wheel`, `sudo`, `admin` or `libvirt`. A scan needs none of these. Bind the scan key to an account outside them: everything a compromise of the web app could then do on that host is what that account can do.

Found by a machine audit on 2026-11-20, which saw a bare scan key in accounts in `docker` and `wheel` on two hosts.

## Host identity

A host's name is what it reports, so it proves nothing.

- Each indexed host is pinned to the SSH host keys verified at its address. A scan of another machine that claims an indexed name (or the same short name) is refused and audited, and the real host's data, address and deploys are untouched. After reinstalling or moving a host: `storageforge-index hosts rekey <name>`, then scan it.
- Scans trust a new host key on first use. The worst a wrong first answer gets is a scan of the wrong machine, which pinning then contains.
- Before a **password** is sent (key install, read-only scan access, deploy access), the host key must be confirmed by a person: the UI shows the fingerprint to compare with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the host, and the password then goes over a connection that accepts only that key. *(This confirmation step was being added while these pages were written; see the [audit](audit-2026-10-29.md).)*
- Signed deploy requests carry the host's `/etc/machine-id` from its last scan, so a request runs on no other machine, even one with the same short name.

### Signed scan payloads

Everything a scan reads from a host (the inventory, each folder walk, the checksum pass, the journal, the network and container surveys, the git survey) is signed on the host and checked here before any of it is used.

- For every command the scan sends a new random nonce. The host hashes exactly the bytes it sends back (SHA-256) and signs `storageforge-scan-v1`, the nonce and that hash with `ssh-keygen -Y sign` in the namespace `storageforge-scan`. StorageForge hashes what arrived, compares, and verifies the signature with a key pinned for that host.
- The key is the scan signing key that read-only scan access makes (`/usr/local/lib/storageforge/scan-sign`, readable only by the `storageforge-scan` group), or the host's own SSH host key when the scan logs in as root. When StorageForge runs the scan access setup itself, the setup's connection accepts only the host key a person confirmed, so the signing key it prints is pinned from there. A key first seen on a scan is pinned on first use, as host keys are. The namespace means these signatures count for nothing to SSH, git or anything else that verifies SSH signatures.
- A payload whose signature does not verify, that was signed by another key than the pinned one, or whose bytes differ from what the host signed, is refused. A refused folder walk leaves that mount's index as it was; a refused inventory stops the scan before anything in it (job runs, ClamAV results, security events) is taken in.
- A host that has signed before (a key is pinned for it, which now includes the SSH host key of a host scanned as root) and answers unsigned, or with a different key, is refused as a downgrade even when signed scans are not required. A person decides: forgetting its scan signing key (`storageforge-index access signing --forget <host>`, or `DELETE /api/scans/signing/<address>`) makes its scans count as unsigned until it signs again, and the next key it signs with is pinned. `PUT /api/scans/signing` takes `true` or `false` (text that plainly says on or off is read as such); anything else is a 400.
- A host that has never signed and cannot (no key the scan account can read, or OpenSSH older than 8.0) says why. Its payloads are used and shown as unsigned, unless signed scans are required: `storageforge-index access signing --require on`, or `PUT /api/scans/signing`, which takes `keys.manage` (admins, not operators: it is about which keys a host is trusted with). Then they are refused too.
- After rebuilding a host, forget its scan signing key (`storageforge-index access signing --forget <address>`) and run the scan access setup again.

What it does not stop: an attacker who controls the host's scan account, or root, can sign whatever they like, because that account is what reads the host. It proves a payload came unchanged from the machine the key belongs to, for this request and no other, and it cannot be replayed. Reports that hosts send on their own (deployed jobs, schedules and the sentinel, with a bearer token) are not scan payloads and are not signed this way.

## Accounts and sessions

- Local accounts only. Werkzeug hashes passwords (scrypt) and Flask-Login manages sessions. Passwords need at least 12 characters. A sign-in with an unknown name costs the same time as a wrong password.
- Requests that change something must come from this origin (`Sec-Fetch-Site`, or `Origin` where a browser sends no such header). `SameSite` alone would let a page on another port of this host post here.
- The session cookie is signed with `STORAGEFORGE_SESSION_SECRET`, `HttpOnly` and `SameSite=Strict`. With `STORAGEFORGE_COOKIE_SECURE=1` (compose sets it) it is also `Secure` and named `__Host-sf_session`.
- Sessions are also kept server-side; only a hash of their id is stored. Signing out ends that session even for a copied cookie. `user signout <name>` ends all of them (`user clear-keys <name>` removes a lost security key, from the server's shell only, and is audited), as do `user passwd` and `user disable`.
- A session ends 30 minutes after sign-in. Each user can raise their own to up to 8 hours from the header's **Session** menu. An open page clears itself and goes to `/login` when its session ends.
- **Re-authentication:** anything that runs commands on hosts, and changing the session length, needs the password typed within the last 5 minutes (`POST /api/reauth`).
- **Roles:** an account can do only what its role allows. The built-in roles are `search`, `viewer`, `operator` and `admin`, and custom roles draw on the permission catalogue in `permissions.py`. `operator` can deploy to every enrolled host, including destructive deploys. Only `admin` can write raw commands (`hosts.command`). See [Roles](features/administration.md#roles).

### Sign-in limits

Failed sign-ins are throttled by Flask-Limiter (successful ones don't count):

| Key | Limit |
| :--- | :--- |
| client IP | 10 per minute, 50 per hour |
| username from one network (/24 or /64) | 5 per minute, 20 per hour |
| username from anywhere | 100 per day |

The per-network limit means a stranger elsewhere cannot lock the owner out; the per-day limit is the backstop. Hitting a limit is audited and `/api/login` answers `429` with `Retry-After`. Counters live in memory and reset when the server restarts. Key install, access grant and deploy access are limited to 10 attempts per minute per user, and re-authentication shares the per-user sign-in limit.

## HTTP

- Pages and their scripts are served only with a valid session; `/login`, `login.js`, `style.css` and `favicon.svg` are the exceptions. Without a session the app redirects to `/login?next=…`, and `next` must be a path on this site.
- State-changing routes accept only `application/json`, so a cross-site form cannot reach them; no CORS is granted.
- Strict CSP (`'self'` only; the one relaxation is `style-src-attr 'unsafe-inline'` for sized bars), `nosniff`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
- Request bodies are capped at 4 KiB. A route that takes more says how much in `server.BODY_LIMITS` (2 MiB for a design, 512 KiB for rule sets, map views and reports), and a test walks that table in both directions. List sizes and limits are clamped.
- `/healthz` returns only `{"status"}` unless asked from inside the container or by a signed-in user.
- Behind a reverse proxy, set `STORAGEFORGE_PROXY_HOPS=1` so limits and the audit log see the real client IP, and `STORAGEFORGE_PROXY_HOST` to the proxy so nothing else can claim a client address (compose sets both).
- The UI builds the DOM with `textContent`. Designs and plans reject control characters and `< > " \`` in text (see [Concepts](concepts.md#the-rules)).
- `POST /api/jobs/report` is the one API route without a session. It needs a job's bearer token, and each token may only report for its own job.

## Audit log

Every connection, scan result, denial, sign-in, plan save, script download, deploy and vault change is appended to `audit_log`. Each entry carries an HMAC-SHA256 over the previous entry's hash, keyed with a random MAC key wrapped by the KEK. Triggers reject `UPDATE` and `DELETE` (and `TRUNCATE` on PostgreSQL). `storageforge-index audit verify` (or **Audit → Verify chain**) finds an edited, deleted or reordered row even if the triggers were bypassed. When the vault is locked, entries fall back to plain SHA-256 chaining.

## Container

| Control | Setting |
| :--- | :--- |
| User | non-root uid 10001; the entrypoint refuses root |
| Filesystem | read-only root; tmpfs for `/run/storageforge` (agent sockets, 0700) and `/tmp`, both `noexec,nosuid,nodev` |
| Privileges | `cap_drop: ALL`, `no-new-privileges` |
| Limits | app: 2 CPUs, 2 GiB memory, 256 PIDs; proxy: 0.5 CPU, 64 MiB, 32 PIDs; memlock raised for `mlock` |
| Secrets | compose secret files, 0640 with your group; checked for length (≥ 32 characters) at start |
| Network | the app port is not published; only the nginx proxy is, on 8443 over TLS 1.2/1.3 with HSTS, replacing (not appending) `X-Forwarded-For` |
| Image | base image pinned by digest, Python packages pinned by hash and installed with `--require-hashes`; pip, `scp`, `sftp` and `ssh-keyscan` removed |
| Egress | optional `docker/egress-firewall.sh` lets the containers open only SSH and alert ports (`STORAGEFORGE_EGRESS_PORTS`, default `22 443`) out of the `sf0` bridge, to other machines and to the Docker host itself |

## Remote nodes

The tunnel in `docker-compose.remote.yml` is the one port meant to be open beyond the LAN. See [Remote nodes](remote-nodes.md) for what a stolen key can and can't do.

## The agent

The optional [agent](agent.md) is an extra layer beside SSH and shares nothing with it. Built, not lab-tested. It gets **no trust for what it says** and **as little as works for what it can do**. What holds for it:

- **Off unless switched on,** per host, by someone with `keys.manage` and a fresh password.
- **Its own accounts.** The agent runs as `sfagent`, never root. The controller manages it as `storageforge-agentctl`, whose key can start one program and whose sudoers file has one line. Neither is ever in `docker`, `lxd` or `incus-admin`: the setup and every request are refused while one is.
- **Its own keys.** The agent makes its key on the host; the public half is read back over the pinned SSH connection at enrollment and pinned. The controller's two agent keys are vault keys of their own, not the scan, deploy or job keys. The receiver has a key of its own too, which opens tunnel sessions and signs nothing.
- **Code comes from the release key.** Plugins and the agent's image run only when a release key signed them (or a key the operator put on that host by hand). The controller carries those signatures and holds no key that makes one, so a controller that was taken over chooses among signed plugins and cannot write one, widen one, or swap the image. What arrives through the tunnel is checked the same way before a byte is written.
- **A manifest cannot be played back.** It names one agent's key and one machine, and its counter only goes up. One that arrives through the tunnel takes effect only when `storageforge-agentctl` made the container for it, over SSH.
- **A container with what was declared and nothing more:** read-only, every capability dropped, no runtime's socket, SSH's and StorageForge's secrets masked inside every mount, and no network at all unless it has a tunnel, in which case the host's firewall lets it reach the receiver's one address and port and nothing else, the host's own `sshd` included.
- **Its own tunnel, both keys pinned.** Noise IK over TCP to the receiver: the agent refuses a receiver without the key pinned on its host, and a receiver key that changes is taken only when an admin accepts it.
- **Its own receiver.** A process and (on PostgreSQL) a database role of its own, with no vault secret and nothing that can open an SSH connection. The host comes from the key the session was opened with, never from a message. Batches are signed and counted, replays refused, gaps and silence shown, and every reading is stored and shown as the agent's claim. Rates, sizes and a row quota per agent keep one agent from crowding out the others or the web app.
- **Privileges take an admin.** A plugin that declares any privilege on the host needs `agent.privilege` and a fresh password.
- **Wipe and stop.** The controller checks every running agent from outside, over SSH, on a timer and after each scan: the image by digest, what changed in the container, its mounts, capabilities and devices, and its plugin and state folders, against the signed manifest. Any finding revokes the agent's key on the controller first, then stops its container for good and deletes its key on the host, and opens a notification that cannot be ignored. The agent checks itself too, and on tampering deletes its key and never starts again. Only an admin enrolls an agent again after a wipe.
- **A report acts only on its sender.** The one action an agent's word can cause by itself is its own revocation. Anything that would reach another host or client needs an independent witness (a scan over SSH, a decoy, the share host's sentinel) or a person, and no such action is built yet.
- **Its plugins declare the least they need.** Heartbeat nothing; logs and sentinel the journal folders read-only and the journal's group; health `/proc` and `/sys` read-only and the process table; network the host's network; disks the whole disks read-only and `SYS_RAWIO`; scan the host's root, `/proc` and `/sys` read-only, with no capability. Pushed journal lines go through the same scrubbing, rate and log rules as a scan's, are marked as signed, and the numbers missing from the journal's own count are shown.
- **A capability is kept by giving root up, not by running as root.** Docker and Podman give a process that is not root no capability it can use, so a container whose plugins declare one starts as root with every capability dropped but the declared ones and the three it takes to give root up. The agent's first act, before it reads anything, is to become `sfagent`, keep the declared capabilities for its children, drop the other three from its bounding set and lock the securebits; each plugin gets only its own declared ones. The check from outside reads the process from the host's `/proc`: any uid that is root, or any capability beyond the declared ones in any set, is a finding that wipes the agent.
- **The files plugin is root on the host in effect,** and is said to be wherever it is switched on: it holds `SYS_ADMIN` (fanotify on whole filesystems), `SYS_PTRACE` and `DAC_READ_SEARCH`, so it can read any file and undo the masks over SSH's keys, and an agent taken over while it runs has what root has. It is never switched on by default; the Keys page lists it as root in effect and asks again before it is ticked, and the route takes `agent.privilege`, a fresh password and the audit log. What it reports (changes, who made them, reads) is the host's claim like any other: it updates the file index, and each SSH scan checks it.
- **Scans on an agent host are scripts carried in the scan plugin.** The script is compiled into the plugin's program, which the release key signs; every word of it reads, none runs a program, and no request names a script. A controller that was taken over can choose the scan plugin or not, never what it runs.
- **Monitoring-only hosts** have `storageforge-agentctl` as the controller's only way in. An admin runs the setup by hand and pastes the line it prints; the host key in it is pinned as a key a person compared. Deploys, change plans, Moves, sends, clone, holds and quarantine are refused there with the reason before anything reaches the host.
- **The console on a monitoring-only host turns SSH on for one session** through `storageforge-agentctl`, and off again after: a key made for that session alone, its public half in the account's `authorized_keys`, written as that account, as a line sshd stops taking after five minutes and that forwards nothing; it is taken out when the session closes, and any later request takes out a grant whose time is past. Only accounts the host's own admin listed by hand in `/etc/storageforge-agent/console_users` can be logged in as, never the agent's two, and no request writes that file. The agent has no part in it and still carries no shell.

[The agent page](agent.md#what-a-taken-over-agent-can-and-cannot-do) says what an agent that was taken over can still do, and [what is not checked yet](agent.md#what-it-does-not-do-or-check-yet).

## The StorageForge network

StorageForge's own WireGuard network ([how to set it up](infrastructure-map.md#storageforges-own-network)) is a security boundary, and these are its rules. Built, not lab-tested.

- **A private key never leaves the machine that made it.** Each host makes its key pair in `/etc/wireguard/sf0.key`, readable by root only. No step prints it, and no plan, script, reading, log or database row holds it. The reading runs `wg show` for public keys only, and never `wg showconf` or `wg show dump`, which print private keys. The index stores ranges, addresses and public keys.
- **A key is taken from a reading twice at most, and each time because a person asked:** once when a host joins, and once per rotation that was asked for. A key that fits neither is never trusted. A different key on an active member is a critical notification, its peers keep the key on record, and so the machine that shows it is not let in.
- **A rotation never leaves a host with a key its peers do not know.** The host switches only to the key the peers were given, checked on the host by its public half, and only after the readings show every peer holds it. The old private key is deleted at the switch, with any copy `wg-quick save` had written into the configuration file.
- **A peer is trusted for its own address and nothing more** (`/32`), so a host that is taken over cannot answer for another member's address. In the hub topology a hub is trusted for the whole range, since traffic between two spokes passes through it.
- **A revoked member** comes off every other member at the next plan. Its address and its key are never given out or accepted again.
- **An interface StorageForge did not make is never changed,** whatever it is called.
- **The controller's key is not in the controller.** Where the controller is a member, a separate program (the link, the `sfnet` container) makes the interface and holds the private key in a volume the server does not mount. The server has no capability and cannot read it. What the server asks of the link is checked line by line there: only an address, a port and WireGuard public keys are acted on, only on `sf0`, and no line is ever run or repeated in a message, so a server that is taken over cannot use the link to run a command, read the key or touch another interface. The link's one capability, `NET_ADMIN`, reaches the server container's own network and nothing on the Docker host.

- **The network is a path, not an identity.** A connection StorageForge makes over it still checks the SSH host key pinned for that host, strictly, and logs in with the same vault key. The network address is used only when the controller's own interface holds the host's key on record for that address, so what answers there holds that host's private key.

What it does not do: it is not a firewall. A member can open any port of another member over the network that the other's firewall allows. Add `fw-fence` steps where a service should be reached only by some.

## What is signed

Everything sent to a host to run as root is signed, with these named exceptions. A signature covers the host, machine id, issue time, nonce, args and script, and not what a run reads on stdin, which is only ever data.

| What | Signed | Why |
| :--- | :--- | :--- |
| Deploys, security actions, measurements, updates, playbooks | **Yes, on each run** | Through `storageforge-run` |
| Timers on a host: jobs, tasks, schedules, the sentinel, ClamAV | **At install** | A signed deploy puts them there, root-owned. They are not checked again on each run |
| `storageforge-job --serve` on a job source, and on the receiving host of a send | **At install** | A job key's forced command with a fixed list of actions, from a config a signed deploy wrote |
| Each side of a ZFS or btrfs send to another host | **Yes, on each deploy** | A signed run on the receiver says what it may receive and writes the key's forced command. A signed run on the sender writes the key. See [Sends between hosts](#sends-between-hosts) |
| The [agent](agent.md): requests to `storageforge-agentctl`, and each host's manifest | **Yes, each one** | By the controller's agent signing key, each in its own namespace, for one machine, once. `storageforge-agentctl` itself reaches a host on the stdin of the signed setup, which installs it only when its size and sha256 are the ones in the signed script |
| The agent's plugins and image | **Yes, by the release key** | Not by the controller, which only carries the signatures. Or by a key the operator put on that host by hand. The scan plugin's scripts are inside its program, so the same signature covers them |
| What the agent sends: each batch | **Yes, by the agent's own key** | Checked by the receiver against the key pinned at enrollment before the batch is read, and counted so a batch cannot be played again. A valid signature makes it the agent's claim, nothing more. Journal lines pushed this way are marked as signed in host logs; lines a scan collects over SSH are not signed |
| Scans: inventory, file walk, checksums, network, containers, Git | No | Read-only, as the scan user |
| First-time scan and deploy access | No | No signer is on the host yet. It takes a fresh password and a host key a person confirmed |
| **`rsync` to or from another host in a task block** | **No** | The signed script on the first host logs in with that host's own root key. Nothing is signed there and no run is recorded, so the check says so and the `deploy.start` audit row names the host (`second_hops`). Use a Moves step instead: a [deployed job](deployments.md#deployed-jobs) has a forced-command key of its own |
| Scripts you download and run yourself | No | Yours to read |

The Falco install fetches its vendor's key at run time, which a signature cannot vouch for, so the script compares it with a fingerprint it carries.

### Sends between hosts

A send to another host needs no root key between the hosts. Each side is a signed run on an enrolled host, and the stream goes over one key that can do nothing else. [Deployments](deployments.md#sends-between-hosts) has the steps.

**What the receiver holds.** A signed run writes `/etc/storageforge/receive/<id>.conf`, which says the tool, the folder or dataset, and how many copies retention keeps. It also adds a line for this send's key in `storageforge-deploy`'s `authorized_keys`: `restrict,command="sudo -n storageforge-job --serve <id> \"$SSH_ORIGINAL_COMMAND\""`. No change to sudoers is needed, because `storageforge-job --serve *` is already there.

**What a key can ask.** A fixed list of verbs. The whole line must match a strict pattern before it is split, and anything else exits 97 and is recorded.

| Verb | Does |
| :--- | :--- |
| `recv-probe` | Is the tool here, and does it run? |
| `recv-root`, `recv-list`, `recv-state <name>` | Is the folder or dataset there, what is in it, and is this copy finished? |
| `recv-mkdir` | Makes the folder from the conf |
| `recv-receive <nonce> <name>` | The stream on stdin into the folder or dataset from the conf. `btrfs receive -C`, chrooted into that folder, or `zfs receive -u -x mountpoint -x sharenfs -x sharesmb -o setuid=off -o devices=off -o canmount=noauto`, never `-F` |
| `recv-discard <name>` | Removes one unfinished btrfs copy. A finished one is refused |
| `recv-prune [dry]` | Keeps the newest copies the conf says, of the prefix the conf says |

The sender names a verb, a nonce and a snapshot. It never names a path, an option or a command, so nothing it says can change where data lands or how much retention keeps. The conf is read line by line and never run.

**What a failure looks like.** The sender checks both ends of the pipe, the exit code that comes back through ssh, the receiver's acknowledgement, and then the copy's id against its own: btrfs Received UUID, ZFS guid. A failed receive removes what it made, says why on stderr, which reaches the sender's output, and leaves a line in the record. Nothing is pruned after a failure.

**The record.** `/var/lib/storageforge/receive/<id>/runs.jsonl` on the receiver, with the verb, nonce, name, exit code and the tool's last words. A line also goes to `/var/lib/storageforge/tasks/runs.jsonl`, so the next scan of that host files it under `receive-<id>`. The signed runs are in that host's runner log, in `deploy_runs` under its name and in the audit log, and the `deploy.start` row names it under `receivers`.

**How long a key lasts.** A change plan's key ends with the plan: a signed `--remove` follows the run, and the conf carries an expiry 12 hours out in case that run never happens. So does **Run now** of a task that is not installed. An installed task or a schedule fires with nobody there, so its key stays until it is uninstalled, like a job's key. Keys are new on every apply. A timer's run has no fresh signature: it was signed at install, as a job is.

**A scan binding reaches none of this.** Being bound for scans is not being enrolled, so the check says `crit` and a deploy is refused with 409. On the host, sudo lets only `storageforge-deploy` start the verbs, and the key is root's, mode 0600.

**What a stolen job key can still do.** Someone who takes a sender can use its key. These can't be taken away while the sender is trusted to send:

- **Send junk under newer names.** Retention then removes older good copies, because the newest count win. With **Keep there** at 0 the key can remove no finished copy. A ZFS hold on the receiver also stops `zfs destroy`. A btrfs copy has no such stop, so a backup you must keep should have its retention set to 0 and its pruning done by a task on the receiver.
- **Fill the receiver's disk.** There is no quota on a send. Give the dataset a quota, or the folder a btrfs quota group, if that matters.
- **Put files with the sender's owner and mode into a btrfs copy.** `btrfs receive` keeps the owner, group, mode and setuid bits a stream carries, so a stolen key can leave a root-owned setuid file in the received folder. Nothing on the receiver can strip it, so **a folder the receive makes for the copies is root's alone, mode 0700**: no other account on the receiver reaches a file in a copy. A folder that was there already keeps the mode you gave it, since you may share or browse the copies from it: mount that one `nosuid,nodev`, or set it to 0700 yourself, if other accounts can log in on the receiver. Either way, do not run files from a copy. Lab tier 16 sends a root setuid file and checks all of this (`send-btrfs-setuid`). A ZFS receive sets `setuid=off`, `devices=off` and `canmount=noauto` itself and takes no `mountpoint`, `sharenfs` or `sharesmb` from the stream, so a received dataset does not export itself, mount at boot, or honour setuid. Mount it by hand to look. Lab tier 16 reads each of these back on a real pool (`send-zfs-properties`).
- **Feed a hostile stream to the tool.** A stream is the sender's data, and `btrfs receive` and `zfs receive` read it as root. The chroot and `-x mountpoint` confine what a stream can name, but a bug in the kernel or the tool is out of reach.
- **Pick a new nonce.** The nonce stops a repeat by accident or from a log. It does not stop someone holding the key.

It can't read the receiver: no verb sends anything back but names, ids and what happened. It can't remove anything outside the conf's folder or dataset, or run anything at all. A stream that makes more than it was asked for fails, and says which names it made. Those stay for you to look at.

**What this does not cover.** Scripts you download and Ansible playbooks hold no key, so a send to another host stops and says so. `rsync` blocks are the row above.

## Netconsole and pstore

[netconsole](deployments.md#kernel-messages-over-netconsole) is plain UDP from a host's kernel, and **it proves nothing about who sent it**. It has no signature, no sequence a sender has to keep and no answer back. The receiver takes a packet only when its source address and port are exactly those of one host listed under **Logs, Netconsole**, and trusts it no further than that: anyone who can send packets from that address and port, on the path or by forging the source on a network that lets them, can write lines in that host's name, and packets can be lost, repeated or come out of order with nothing to say so. So a line that came this way is marked **came over netconsole: UDP, not signed**, never as signed; it is matched by the log rules, so a forged panic can raise a critical notification, and it never changes how the host's journal pickup went or its baselines. Each source is held to a rate and a packet size, and packets from unknown addresses are counted and dropped without being read further. Use it to see why a host died, not as evidence; the agent's signed lines are the record. Saying which address a host sends from takes the password typed in the last minutes and is audited, since it decides whose name unsigned packets are stored in.

The receiver listens only when `STORAGEFORGE_NETCONSOLE_LISTEN` says where. Keep the port reachable from the hosts that send and from nowhere else: a firewall rule that admits UDP to it only from those hosts' network is the one thing that makes forging their addresses harder.

**pstore** records are the host kernel's last words, written before a crash and read by the scan after the reboot. Root on the host can write or delete one, so a record says why a host died when nothing else does, and proves nothing. The scan reads them only where the scan user may; nothing is added to a host for it.

## On the hosts

| Feature | What it adds | Removal |
| :--- | :--- | :--- |
| Scanning | nothing; a user with your public key | remove the key |
| Read-only scan access | `find` and `sha256sum` copies with `CAP_DAC_READ_SEARCH`, executable only by `storageforge-scan`; the scan user in `systemd-journal`, so it can read every journal line for scans to collect | `access script --remove` |
| Deploy access | `storageforge-deploy` user, a sudoers file allowing two commands, `storageforge-run`, `allowed_signers` | the setup script's `--remove` |
| Deployed jobs | `storageforge-job`, per-job configs, keys and timers; forced-command keys on sources | deploy the plan empty (**Remove from hosts**) |
| netconsole (the plan step) | `/etc/modprobe.d/storageforge-netconsole.conf`, `/etc/modules-load.d/storageforge-netconsole.conf`, and netconsole loaded, or a target of its own in configfs | the same step with **stop** |
| Sends between hosts | On the receiver: `storageforge-job`, `/etc/storageforge/receive/<id>.conf` and a forced-command key. On the sender: `/etc/storageforge/sends/<id>.key` and `.hostkey` | goes when a plan ends; **Uninstall** for a task or schedule. Records stay in `/var/lib/storageforge/receive/` |

## If a key may have leaked

`storageforge-index rotate` changes every key StorageForge holds. Run it without `--apply` first: it lists each SSH key in the vault with the hosts and accounts that use it now, and what it cannot change.

```bash
docker compose exec storageforge storageforge-index rotate            # what it would do; changes nothing
docker compose exec storageforge storageforge-index rotate --apply    # do it
```

With `--apply`, for each SSH key that a scan, checksum or deploy uses on a host:

1. A new key is made in the vault.
2. Its public half is added to that account's `authorized_keys` over the old key, and a login with the new key is tried on every host.
3. Only when every host takes it: the bindings move to the new key, the old key's line is taken out of each `authorized_keys` over the new key (with any options in front of it, and nothing else touched), and the old key is deleted. The new key takes the old one's name.

If one host does not take the new key, nothing moves for that key: the new line is taken back off the hosts that had it, and the old key stays bound and working. The run says which host and why, and exits 1. A key no scanned host uses is left alone; delete it with `vault remove` if it is not needed. `--key K` limits the run to named keys.

It also ends every web session (everyone signs in again) and revokes every invite not yet used. With `STORAGEFORGE_VAULT_NEW_SECRET` set (32 characters or more) it wraps every key under that new vault secret; put it in `secrets/vault_secret` and restart straight after. Each step is in the audit log.

What it cannot change from here, and lists with what to do:

| What | How |
| :--- | :--- |
| Session secret | delete `secrets/session_secret`, run `docker/init-secrets.sh`, restart |
| TLS certificate | delete `secrets/tls_cert` and `secrets/tls_key`, run `docker/init-secrets.sh`, restart, and trust the new one |
| Vault secret | the run above with `STORAGEFORGE_VAULT_NEW_SECRET`, or `vault rotate-secret` |
| Report tokens of deployed jobs, schedules and remote nodes | deploy them again: each deploy issues a new token and the old one stops working |
| A host's scan signing key | delete `/usr/local/lib/storageforge/scan-sign*` on the host, run the scan access script again, then `access signing --forget <address>` |
| Router and switch passwords | change each on the device, then store the new one |
| Alert addresses (ntfy topics, Gotify tokens, webhook URLs) | make new ones where they are hosted and set them under Settings, Alerts |

Nothing secret is in the git repository: the folders that hold secrets (`secrets/`, `keys/`, `data/`) and `.env` are ignored, and a scan of every commit for private keys, tokens and passwords found only placeholders and test values (2026-11-07).

