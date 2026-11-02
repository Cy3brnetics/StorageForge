# Remote nodes

A remote node is a host StorageForge can't reach, such as one behind NAT or CGNAT or on another site. It dials out to StorageForge instead, the way Hawser's edge mode does. After that it works like any other host: scans, signed deploys and jobs that run on it go through the normal keys and checks.

```text
 node                                       StorageForge server
 storageforge-remote.service ──ssh -R─────► tunnel container :2222 (the only new open port)
 sshd on 127.0.0.1:22  ◄───────────────────  127.77.0.5:10022, on the server's loopback only
                                             ▲ scans and deploys connect here, over SSH as usual
```

The node needs systemd, `bash`, the OpenSSH client and server, and outbound TCP to the tunnel port. It needs no inbound port, and the agent is only a one-line script around `ssh`. Each node gets its own `127.77.x.y` address, because StorageForge tells hosts apart by address.

## Turn on the tunnel

The tunnel is off by default. Start the stack with the extra compose file:

```bash
docker compose -f docker-compose.yml -f docker-compose.remote.yml up -d
```

Use both files every time you run `up`. This publishes port 2222, or `STORAGEFORGE_TUNNEL_PORT`, on `STORAGEFORGE_TUNNEL_BIND`. Forward only this port from the internet. **Don't publish the web UI port.** A network that allows only web traffic may block 2222: set `STORAGEFORGE_TUNNEL_PORT=443` if that port is free.

## Add a node

1. In the **Deploy** tab, open **Remote nodes**. Enter a name and the address nodes dial, such as `forge.example.com:2222`, then press **Add node**. The CLI equivalent is `storageforge-index remote add cabin --endpoint forge.example.com:2222 > node.sh`.
2. Copy the downloaded script to the node and run it as root:

   ```bash
   sudo bash storageforge-remote-cabin.sh
   ```

   With no flags, it only reports. Run it again with `--apply` to set up the tunnel, a `sfscan` account with read-only scan access, and deploy access.
3. **Delete the script afterwards.** It holds the node's private tunnel key, and StorageForge keeps no copy. If you lose it, revoke the node and add it again.
4. Press **Adopt**, or run `storageforge-index remote adopt cabin`. This scans the node and proves a signed run works. In the web UI, press it again once the scan has finished.

An unused key stops working after 24 hours. Adopting removes that limit.

## Remove a node

**Revoke** in the UI, or `storageforge-index remote revoke cabin`, cuts the tunnel within about 10 seconds. Every other node is dropped too and reconnects within about 20 seconds. Then run the script on the node with `--remove` to take off the service and its accounts. If you've deleted the script, make a new one with the same name, since `--remove` works from any copy. Retire the host as usual to remove its index data. Retiring an adopted node's host revokes the node as well, so its tunnel is cut even if you skip **Revoke**. The machine keeps retrying until its script runs with `--remove`.

## What a tunnel key can do

The container runs `sshd` as its own unprivileged user, on a read-only filesystem, with no capabilities and only tunnel forwarding allowed. Each key is limited to listening on its own one address. The lab tests these limits on real machines.

| Someone holding a stolen key tries to | Result |
|---|---|
| Run a command or get a shell | Refused |
| Listen on another node's address, another port, or all interfaces | Refused |
| Forward into the server, such as to the web app | Refused |
| Log in with a password | Refused: passwords are off |
| Take over its own address while the node is away | Possible, but scans and deploys check the node's pinned host key and refuse to continue |

The node also pins the tunnel's host key from the script, so it won't connect to anything pretending to be your server.

## Limits

- **Node-to-node copies:** a tunnel reaches only the server. A job whose source is a remote node needs a route to it, such as a [mesh address](deployments.md#sync-engine), and the plan check says so. A job that runs on a remote node needs its source to be reachable from that node.
- **Reports:** a job on a node reports to your report URL if the node can reach it. The web UI is LAN-only, so usually it can't, and results then arrive with the next scan.
- **Hosts without systemd:** not supported, as with deployed jobs.
- **Backups and restores:** backups include the node list. A restored server rewrites what the tunnel reads, but a node's tunnel only returns if the tunnel's own host key volume, `sf-tunnel-host`, is still there. Otherwise nodes refuse the new key, and each needs a new script.
