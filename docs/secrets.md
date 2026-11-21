# Secrets for plan steps

*New in 0.5.9. Built, not lab-tested: its lab checks (tier 25) are written and have not run.*

Some plan steps need a secret on the host they run on: a password a service reads, an API token, a WireGuard key, an auth key that joins a private network. StorageForge keeps these in its vault, makes new ones for you, brings them to the host when a plan is applied, and changes them everywhere they went when you rotate them. A value is shown to you once, when it is made or rotated, and never again.

The rules, which the tests check for every value:

- A secret is never on a command line, in a plan, a generated script, an Ansible playbook, a deploy's output, a log line or an audit row.
- The database holds it only as ciphertext, sealed as the vault's SSH keys are, inside the [key enclave](security.md#key-enclave) when one is configured.
- A secret with a policy is released only for the steps, hosts or platforms the policy names.

## Making a secret

**Keys → Secrets for plan steps → Make a secret**, or on the command line:

```sh
storageforge-index vault secret-generate grafana-admin --kind password --length 24 --step secret-file --for-host nas-01
```

| Kind | Made of | Length |
| :--- | :--- | :--- |
| `password` | letters, digits and `- _ . , : + = @ %`, at least one of each | 24 (12 to 128) |
| `token` | letters and digits | 40 (16 to 256) |
| `hex` | `0` to `9` and `a` to `f` | 64 (16 to 256) |
| `pin` | digits | 8 (6 to 32) |
| `wireguard` | a WireGuard private key: 32 random bytes in base64, as `wg genkey` prints | 44 |

Values come from the operating system's random source. A password leaves out every character a shell, a URL, an INI or a YAML file would read as syntax: no quotes, `$`, `#`, `\` or spaces.

The value is in the answer to that request, and only there. The page shows it with a Copy button until you hide it or the list is loaded again. The command prints it to standard output and everything else to standard error, so `> file` keeps only the value. Nothing lists it again: not the page, not `vault secret-list`, not the API.

A secret you already have (a Tailscale auth key, a Cloudflare token) is stored with `vault secret-add NAME`, one line on standard input, as before. It is listed as *given by a person*.

The policy options are the ones `vault secret-policy` takes: `--step`, `--for-host`, `--platform` and `--sensitive` (with the key enclave, each release takes a [step-up](security.md#key-enclave)). Without any, the secret is released for any named step or host.

## How a step gets it

A step names the secret in its form (the `secret` field of `tailscale`, `netbird`, `openziti`, `cloudflare-tunnel`, `pangolin-site` and `secret-file`). When the plan is **applied** from StorageForge:

1. When the run on that host starts, and not before, StorageForge releases each secret the plan's steps on that host name, for that host and that step. With the key enclave, the enclave checks the policy, takes a step-up for a sensitive secret, limits how often one secret leaves (60 times a minute), and writes the release into the audit log itself.
2. The values go to the host on the signed runner's standard input, after the signed request, as base64 lines. They are not part of what is signed, so they are not in the request either.
3. The plan's script, started with `--secrets-stdin`, writes each to `/run/storageforge/secrets/NAME` before its first step: `/run` is memory, the folder is mode 700, the file mode 600, and both are gone at reboot. `printf` is a shell builtin and `base64` reads a pipe, so the value is on no command line.
4. The step reads the file there, as it reads what `vault send-secret` writes.

A secret the vault would not release (its policy names other hosts, it is marked sensitive and nobody stepped up, the vault is locked, it does not exist) is said in the run's output as a conflict on that host, with the reason, and the step that needed it stops there.

A report brings no secrets: it has nothing to compare them with, and needs none to say what it would do. A script you download and run yourself never reads its standard input either (run as `curl … | bash`, that would be the script itself): send the secret first with `vault send-secret NAME --host HOST`, which still works as before.

Where each secret went is recorded (`secret_deliveries`): the host, the step, how (a plan, `send-secret` or a rotation) and when. The list shows it.

### The secret-file step

`secret-file` writes a secret to a file a service reads: `/etc/grafana/admin-password` for Grafana, a password file for a database container. It names the secret, the file, its owner and group, and its mode (0600 unless said). It copies the file under `/run` through a temporary file in the same folder and a rename, and only when what is there differs or the owner or mode are not what the step says. `state: absent` removes the file.

The file holds the secret in the clear for whoever can read it: its owner and mode are what protect it. The check warns when the mode lets every account read it, and refuses a path under `/run/storageforge` or a few system files.

## Rotating

**Rotate** on the page, or `vault secret-rotate NAME` (a dry run) and `vault secret-rotate NAME --apply`. It works like `rotate` for SSH keys:

1. A new value of the same kind and length is made.
2. Each host the secret was delivered to gets it in a signed run, into `/run/storageforge/secrets/NAME.next`, beside the old one. A host where the step already removed the file (`tailscale` and `netbird` do once they have joined) has nothing to replace and says so.
3. Only when every host has it is the vault's value replaced, and then each host moves `NAME.next` over `NAME`.
4. If one host does not take it, the hosts that did have `NAME.next` removed, the vault keeps the old value, and nothing changed anywhere.

The new value is shown once, as when the secret was made. A host that cannot be reached by a signed run (not set up for deploys) blocks the rotation before anything is sent, and the dry run says which. A rotation takes `deploy.apply` as well as `keys.manage`, since it runs as root on each host.

What a rotation does not do: tell the service that uses the secret. A service that read the old value at start keeps it until it reads the file again, and a file a `secret-file` step wrote gets the new value the next time that plan is applied. A secret a person gave is rotated with the new value on standard input: `vault secret-rotate NAME --apply --given`.

## Removing

**Remove** on the page (type the name to confirm), or `vault secret-remove NAME`. The secret and the record of where it went are deleted. Copies on hosts are under `/run` and go at their next reboot; a file a `secret-file` step wrote stays until a step with `state: absent` removes it.

## What the web app can and cannot get

The web app is the part of StorageForge most exposed: it faces the browser. What it can do with the secret store:

- **It can make a secret** and sees the value for that one request, because it is the one that shows it to you.
- **It can have a secret released for a named host and step,** when a plan is applied or a secret rotated, and the value passes through its memory on its way to the runner's standard input. With the key enclave, every such release is an entry of the audit log that the enclave signed, the policy is checked inside the enclave, a sensitive secret takes a step-up the enclave checks itself, and each secret leaves at most 60 times a minute. A web app taken over could ask for releases within those limits, and each would be written up.
- **It cannot list or read a value back** through any route: no API answer after the one that made or rotated it holds one.
- **With the key enclave, it never holds the key that opens the vault.** It cannot open a secret without asking the enclave, cannot change a secret's policy without the secret failing to open (the policy is sealed with it), and cannot release a secret into an audit log that was cut short.
- **Without the key enclave,** the web app holds the vault's key while it runs, as it does for the SSH keys, and could open any secret. The enclave is the layer that takes that away.

Secrets that existed before 0.5.9 (`vault secret-add`) are the same rows and work as before. The database keeps how each one was made (its kind, length and origin) beside it, in the clear, as its name is.

## Commands and routes

| Command | What it does |
| :--- | :--- |
| `vault secret-generate NAME [--kind K] [--length N] [--step S] [--for-host H] [--platform P] [--sensitive]` | make a secret and print it once |
| `vault secret-list` | names, kinds and where each went: never a value |
| `vault secret-rotate NAME [--apply] [--given]` | a dry run, or the rotation |
| `vault secret-remove NAME` | remove it and the record of where it went |
| `vault secret-add NAME` | store a secret you have, one line on standard input |
| `vault secret-policy NAME [...]` | show or change what it may be released for |
| `vault send-secret NAME --host HOST [--step S]` | write it to the host over SSH, for a script you run yourself |

The routes are in the [API reference](api-reference.md): `GET /api/keys/secrets`, `POST /api/keys/secrets`, `GET` and `POST /api/keys/secrets/<name>/rotate`, `DELETE /api/keys/secrets/<name>`.
