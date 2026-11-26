# Infrastructure map

The **Map** view: networks, firewalls, listeners, containers, VMs and VPNs across your hosts, drawn from what those hosts report. The **Infra** panel holds the same facts as lists. A plan is [the roadmap](../archive/roadmaps/infrastructure-platform-roadmap.md); this page is what exists.

## How it knows

Nothing sends a packet to find out what exists. There is no scanner in here, by design.

| Fact | Read by | Needs root |
| :--- | :--- | :--- |
| Interfaces, addresses, routes, neighbours, bridges, DNS, listeners | The scan, as the scan user | No |
| Firewall rules, which process owns a listener, clients on storage ports | A signed read-only **measurement**, every 6 hours or when you ask | Yes |
| libvirt, Incus, LXC, Proxmox guests, other users' rootless Podman | The same measurement | Yes |
| WireGuard public keys and peers, Tailscale, proxy sites and upstreams | The same measurement. Never a private key, a preshared key or a password | Yes |
| Other private networks and access proxies: see [what each tool says](#private-networks-and-access-proxies-what-each-tool-says) | The same measurement, from each tool's own status or configuration, without its credentials | Yes |
| Docker and Podman containers | The scan | Depends on the host |

A host with no deploy access gets the unprivileged layers, and says what it could not read. A command that fails makes that part **not readable**, which never reads as empty. Alpine, TrueNAS and XCP-ng say which layers they are missing. Turn the measurement off for one host through `POST /api/infra/settings`.

Every node and line says how it is known:

| Shown | Means |
| :--- | :--- |
| Solid | **Certain:** read on this host. **Confirmed:** across hosts, because an address or public key matches |
| Dashed | **Inferred:** the same subnet, or an entry in a neighbour table. Unscanned devices are placeholders, never hosts |
| Long dashes | **Placed by hand,** and never confirmed by a scan |

Select anything to see the evidence: which host said so, and from which command.

## Who can reach a port

The exposure engine works from the bind address, then the firewall, then Docker's NAT, then which of the host's networks can reach it. It reads nftables, firewalld, ufw and iptables into one model.

| Level | Means |
| :--- | :--- |
| This machine only | Bound to loopback |
| Blocked | The firewall drops it from every network this host is on |
| VPN only, Private networks, Any address | Who can reach it, widest network first |
| Unknown | Could not be worked out, and it says why |

A wrong "not reachable" is worse than no answer, so unreadable rules and rules it could not understand give **Unknown**, and never **Blocked**. A published Docker port goes through the forward chains, which is why ufw does not stop it, and the map shows that with the rule that decides.

### Tunnels: public with no port open

A tunnel (Cloudflare Tunnel, frp, ngrok, Pangolin's Newt) dials out from the host and carries requests back in. What it publishes is public with no port open on the host or the router, and no firewall rule on the way stops it. Nothing in a firewall reading shows that, so it is read from the tunnel's own configuration, without the lines that hold its credentials, and from which tunnel programs run.

- A listener that a running tunnel on the same host sends requests to is **Any address**, whatever its bind address and the firewall say. The row names the tunnel and the public address, and keeps what the level was without the tunnel.
- The Exposure panel lists each thing a tunnel publishes, where it sends it, and through what. A tunnel that sends requests to another machine is listed here and does not change this host's listeners.
- A tunnel whose routes are kept at its server (a `cloudflared` run from a token alone, or Newt) is **Unknown**: StorageForge cannot read what it publishes from the host. So is a tunnel that is configured and was not running at the last reading: it is public whenever it runs.
- The Security overview says the same in a sentence for each host. It does not change the host's state: publishing a service is a choice, and the view cannot tell a tunnel you want from one you do not.
- A `cloudflared` or `newt` that was started with its token or secret as an argument is named: every account on the host can read a command line. Only the program's name leaves the host, never the line.

frp's `stcp`, `xtcp` and `sudp` proxies are not listed: only a visitor that holds the same key reaches them.

Read from configuration and tested with unit tests only. The lab has no check against a real Cloudflare, ngrok or Pangolin service: **not lab-tested**.

## Private networks and access proxies: what each tool says

The measurement asks each tool on a host for its own account of itself, and the map draws it. A tool that is not installed adds nothing. A tool that fails, or prints something that cannot be read, shows as **here, and its status could not be read**: it never fails the scan and never hides the others.

| Tool | Read from | What is read |
| :--- | :--- | :--- |
| Tailscale | `tailscale status --json` | Peers, online or not, direct or relayed, routes, exit nodes |
| Headscale | `headscale nodes list -o json`, on the server | Every node, with routes approved, waiting and served |
| NetBird | `netbird status --json` | Peers, direct or relayed, the networks behind them, the management server |
| ZeroTier | `zerotier-cli -j info`, `listnetworks`, `peers` | The networks joined, this host's address on each, and its peers by node id |
| Nebula | `/etc/nebula/config.yml` and `nebula-cert print -json` of the host certificate | Whether it is a lighthouse or a relay, the lighthouses and hosts it names, networks reached through another host (`unsafe_routes`), and from the certificate its name, address, groups, the networks it may route and when it ends |
| Netmaker | `netclient list -l` | Each network and this host's address on it, and its peers by WireGuard key. A peer allowed more than its own address is a gateway to those networks |
| strongSwan | `swanctl --list-sas` and `--list-conns` | Each tunnel that is up with the networks at both ends, and each connection that is configured and down. A remote end that was handed a virtual address is a client |
| OpenVPN | The server's status file, and its CA where it is kept beside it (easy-rsa's `index.txt`, the CRL, the CA and server certificates) | Clients connected with their addresses and the networks behind them. Certificates valid, revoked, ended and ending within 30 days, and until when the CRL is good |
| OpenZiti | `ziti-edge-tunnel tunnel_status` | The identities the tunneler has loaded, and the services each may dial or is the exit of |
| Teleport | `tctl status`, `tctl get nodes`, `/etc/teleport.yaml`, `tsh status` | The cluster and version, the nodes it knows with where each answers, which services this host runs, and until when a sign-in is valid |
| Boundary | `boundary targets list` where a token is at hand, and the controller or worker configuration | Targets with address and port, and what this host is to Boundary |
| Pomerium | `/etc/pomerium/config.yaml` | Each route, where it sends requests, and who it lets in |

**What does not leave the host.** These files and outputs hold keys, tokens and people's names, so they are cut on the host before anything is sent, and cut again by the same rule on the server:

- From a configuration file, every line that names a credential goes with everything that belongs to it: the block under it, the list under it, a quoted value that runs over several lines, and any PEM block. That covers keys, tokens, cookies, request headers, database addresses and a password written into a URL. A route or setting whose own line contains such a word (a site called `keycloak.example.com`, say) is dropped with it, and so is not shown.
- From strongSwan, every identity is replaced before it is sent: a certificate subject, an EAP or XAuth name. Where a client connects from is not kept.
- From Teleport, only the fields that are read are sent: a label, a command, a login or a user name stays on the host.
- From Boundary, a target's description and the credentials it is given are emptied.
- From Pomerium, an email address in a policy is replaced on the host. A policy is told by what it asks for and how many (`by policy: domain, email`, `2 domain(s)`), never by who.
- From an OpenVPN CA, the common name of each certificate is read and nothing else of its subject. No key file is opened.

**On the map.** Each network on a host is a **VPN** row that says what was read in a sentence. Its peers are lines:

- A peer whose address a scanned host has is that host, **confirmed**. So is a Netmaker peer whose WireGuard key a scanned host holds, and a ZeroTier peer whose node id a scanned host said is its own.
- A ZeroTier peer that was not scanned as a ZeroTier node, and is reached at an address a scanned host has, is drawn as that host and marked **inferred**: behind one address there can be more than one machine.
- Any other peer with an address is a placeholder, **inferred**. A peer known by a key alone that no scanned host holds is not drawn.
- A network behind a peer (a NetBird or Tailscale route, a Netmaker gateway, the far end of an IPsec tunnel, a Nebula `unsafe_route`) is a second line that names the networks.
- Nebula has no status command. Its lines say what the host is configured to reach, and never that a peer is up.

Each access proxy is an **ACC** row with its targets. A target at an address a scanned host has is drawn to that host, confirmed; one known by a name that a scanned host also has is inferred. A Pomerium route that lets anyone in without a sign-in (`allow_public_unauthenticated_access`, or a policy that accepts everyone) is marked **public** and listed on the row. It is not yet counted by the exposure engine: the Exposure panel and **Can A reach B?** do not know about it.

**In the console.** A host's address on a private network is offered by that network's name. The name comes from what the tool said its interface and address are, so a Nebula interface called anything, or a Netmaker one, is named correctly once the measurement has run; before that only the interface's name is used.

Built, not lab-tested. Nebula is read against the real `nebula-cert` 1.12.0 and the OpenVPN CA against one made by the real `openssl`. Every other tool is read against samples taken from its documentation or source, since none is installed where the tests run. Lab tier 22 has checks for ZeroTier, Nebula, strongSwan, an OpenVPN CA and a Pomerium configuration; they are written and have not run. Netmaker, OpenZiti, Teleport and Boundary have no lab check: the lab runs none of their servers.

**Can A reach B?** walks a packet's path: out of A, across anything between, into B, naming the first rule that decides it. It is worked out from the configuration and tested against nothing: anything between hosts that was not scanned is listed as a blind spot.

## Planning from it

Select something and stage a step. The **What this would do** panel draws it on the map, in outline, before anything is saved:

- Which listeners become reachable from further, or less far.
- Duplicate addresses and port clashes.
- Anything that would cut StorageForge's own SSH path. That counts as blocked unless a rollback timer is staged.

Then **Stage in Changes**, where it is an ordinary step with a Report and an Apply. The overlay is analysis of configuration, and the Report on the host has the last word.

| Step | Does |
| :--- | :--- |
| `fw-rule` | A rule in whichever firewall the host runs, so that firewall still lists it. `forward` is for published ports: it goes in `DOCKER-USER` |
| `fw-fence` | Only these clients may reach these ports, in a table ahead of any other firewall |
| `net-bridge`, `net-vlan`, `net-mtu` | With NetworkManager or systemd-networkd |
| `net-bond` | A bond over interfaces, in a mode you choose (`active-backup` if empty; `802.3ad` needs the switch set up for LACP), with an address or DHCP. See [networks](#networks-in-the-hosts-own-files) |
| `net-address` | Give an interface an address, or take one off. An address another file sets is not taken off: the step names the file |
| `net-route` | A route to a network through a gateway, with a metric, on the interface that reaches the gateway if none is named; or take one away. `0.0.0.0/0` is the default route |
| `net-dhcp` | DHCP on or off for IPv4, IPv6 or both on an interface. Off leaves it with the addresses set for it, and the check warns when there are none |
| `wg-peer` | Add or revoke a WireGuard peer, with where to call it and a keepalive where it cannot call back |
| `wg-interface` | Make a WireGuard interface and its key pair on the host, or remove them. The private key is made on the host and never leaves it. An interface StorageForge did not make is left alone |
| `wg-rotate` | One half of a key rotation on an interface StorageForge made. `prepare` makes a second key pair on the host, beside the one in use. `switch` starts using it, and only if it is the key the peers were given. `cancel` removes a second key that was never used |
| `tailscale` | Join a tailnet with an auth key from the vault, or leave it. With a control server named it joins through Headscale, with a pre-auth key `vault headscale-key` made there |
| `netbird` | Join a NetBird network with a setup key from the vault, read by `netbird up --setup-key-file`, or leave it: `netbird deregister` also removes the peer at the management server. See [joining a private network](#joining-a-private-network) |
| `zerotier` | Join or leave a ZeroTier network by its id. No secret is involved. The step does not authorise the node at the controller, and says which node id to authorise there |
| `nebula` | Write a host's Nebula configuration and its CA certificate, have `nebula -test` read them, and run Nebula as a unit of its own, as a lighthouse if asked. The host certificate comes first, from `vault nebula-issue` |
| `openziti` | Enroll the host as an OpenZiti identity from a one-time token in the vault, read by `ziti-edge-tunnel enroll --jwt FILE`, or remove the identity and its key |
| `container` | `docker run` or `podman run` with a fixed name. It will not replace an existing container |
| `vm` | `virt-install --import` from a disk you already have, with its console on loopback |
| `os-install`, `os-boot`, `os-remove`, `os-running` | A second operating system on the host itself, beside the running one, which of them starts, and a step that stops a plan in any system but the one it is for. See [host migration](host-migration.md#a-second-system-beside-the-first) |
| `dux-install`, `desktop-profile` | A desktop for a user: Dux with a chosen compositor, and a profile of keys, window rules and displays kept on the server. See [host migration](host-migration.md#a-desktop-on-it) |
| `vm-create` | A new VM from a cloud image: the image checked against its publisher's checksum, copied to a new root disk, data disks, and a cloud-init login for your SSH key. Fields can come from a [VM spec](host-migration.md#creating-vms). Never writes over a disk or a VM that is there |
| `packages` | The packages another host was given on purpose, installed with the same package manager. Reports first, never removes a package, never adds a source |
| `workload-action`, `workload-remove` | Start, stop, restart, snapshot. Removing keeps volumes and disks, and takes `--destructive` |

A step that could cut StorageForge off can carry a rollback timer. The script journals how to undo it and starts a systemd timer. Only a second signed run stops that timer, and that can only happen if the path still works.

### Networks in the host's own files

Built, not lab-tested (the [lab checks](kvm-lab.md) of tier 26 are written and have not run).

A scan reads what the host's network files say beside what the kernel has: netplan (`/etc/netplan`), systemd-networkd (`/etc/systemd/network` and what netplan writes into `/run/systemd/network`), NetworkManager (`nmcli`, one connection at a time) and ifupdown (`/etc/network/interfaces` and `interfaces.d`). It reads as the scan user, so a file only root can read (netplan wants its files closed so, and NetworkManager its keyfiles) is listed as unreadable, never taken as empty: what netplan rendered for networkd or NetworkManager still shows. The **Network** panel lists, per interface, where it is set up, DHCP for each family, its addresses and routes, and whether it is there now. On the map each interface says where it is set up and which configured addresses it does not have, and an interface that is set up and not there (a bond not made yet, a port unplugged, a name mistyped) is drawn in outline as *configured, not present*.

`net-bond`, `net-address`, `net-route` and `net-dhcp` work out on the host which system keeps the network, in this order: netplan where it has files (it writes for networkd or NetworkManager itself), NetworkManager when it runs, systemd-networkd when it is active, ifupdown. Each writes in that system's own way and applies the change now:

| System | Where a change goes | Applied with |
| :--- | :--- | :--- |
| netplan | a file of its own, `/etc/netplan/90-storageforge-*.yaml`, mode 600, checked by `netplan generate` before it is kept | `netplan apply` |
| NetworkManager | the connection on the interface (`+ipv4.addresses`, `ipv4.routes`, `ipv4.method`), or new `sf-` connections for a bond | `nmcli device reapply`, `nmcli connection up` |
| systemd-networkd | a drop-in beside the `.network` file that manages the interface, or `05-sf-` files for a bond so they come before any other file that matches its ports | `networkctl reload` and `reconfigure` |
| ifupdown | a file of its own in `interfaces.d`, which `/etc/network/interfaces` must read with `source`; routes in `/etc/storageforge/net/routes`, put back by an `if-up.d` hook each time the interface comes up | `ip` now, `ifup` for a bond or DHCP |

What another file says is not edited. An address or route set elsewhere, or how an ifupdown interface gets its address, is left to a person, and the step names the file. On a host with none of the four, the step says nothing would keep the change across a reboot and makes none.

A change that could cut StorageForge off needs a rollback timer, or the host refuses it: a bond over the interface StorageForge comes in on, DHCP on or off on that interface, taking off the address it reaches, and a route that covers the address the session comes from. The timer is the one firewall rules use: the change is journalled first, and only the plan's second signed run, which can only get through if the path still works, stops it. With systemd-networkd, `net-dhcp` sets `DHCP=` to the one family asked for, or to `no`.

### Joining a private network

Five steps join a host to a private network that something else runs, and take it out again: `tailscale`, `netbird`, `zerotier`, `nebula` and `openziti`. All are built and none is lab-tested: lab tier 22 is written and has not run. What they have in common:

- **The program is installed already**, except Tailscale, which the `tailscale` step installs with its own script. Each of the others has a package source of its own to add, and that is your choice to make.
- **A secret is never on a command line.** It is in the vault, reaches the host with `vault send-secret`, and the program is given the name of a file. How each program takes it is in [Secrets for plan steps](security.md#secrets-for-plan-steps).
- **A second run changes nothing**, and a host that is already on another network of the same kind is left there and said so.
- **Leaving is the same step with state `absent`.** What stays behind at the network's controller is said in the step's output, because the step does not always remove it there.

| Step | What it does not do |
| :--- | :--- |
| `netbird` | A NetBird older than `--setup-key-file` is refused. One too old for `netbird deregister` is disconnected, and its peer stays listed at the management server |
| `zerotier` | Authorise the node: a private network lets it in only once its controller has. Remove the node from the controller's member list when it leaves |
| `nebula` | Issue or revoke a certificate (`vault nebula-issue`, `vault nebula-revoke`), open the lighthouse's UDP port in a firewall, or touch a Nebula that was set up by hand: a `config.yml` it did not write and a running `nebula.service` are left alone |
| `openziti` | Make the identity or its token at the controller, or delete the identity there when the host leaves. Its service hands out names in 100.64.0.0/10 by default, the range Tailscale and NetBird use |

**There is no step for Netmaker.** `netclient join -t TOKEN` is the only way it takes its enrollment token: no file, no standard input, no environment variable. A token on a command line is readable by every account on the host, so the step is not built until netclient can read the token from a file.

**Nebula** has no control server. Its certificate authority is kept by StorageForge:

1. `storageforge-index vault nebula-ca NAME --networks 10.9.0.0/24` makes the CA. Its key is a vault key (in the key enclave where there is one, and it signs there), and its certificate is public.
2. `storageforge-index vault nebula-issue NAME --host HOST --address 10.9.0.5/24` has the host make its own key pair in `/etc/nebula` (the private key never leaves the host), signs a certificate for the public half, and writes the certificate back. An address belongs to one name until that name's certificate is revoked.
3. The `nebula` step writes the configuration: the lighthouses (`10.9.0.1=lh.example.org:4242`), what is allowed in (`icmp, tcp/22, tcp/443@web`), and whether this host is a lighthouse. A lighthouse listens on UDP 4242 unless told another port.
4. `storageforge-index vault nebula-revoke NAME HOSTNAME` revokes a certificate. Every other host refuses it once the `nebula` step has run on it again, which writes the list of revoked certificates into its configuration.

The certificates are Nebula's version 1 format (one IPv4 address per host), which every Nebula reads. Version 2 certificates, with IPv6, are not written.

**Headscale** is Tailscale's control server run by the site. `storageforge-index vault headscale-key NAME --host SERVER --hs-user 1` makes a pre-auth key on the server over SSH and stores it as the secret `NAME`: it is never printed. The `tailscale` step then joins with it when its control server field names the Headscale server. A scan of the server reads each node's routes: approved, advertised and still waiting for approval, and served.

## StorageForge's own network

StorageForge can build a WireGuard network of its own between the hosts you choose, on the interface `sf0` and UDP port 51903. It needs no outside service. Its page is **Infrastructure → StorageForge network**: make the network, add and remove members, see per member what the readings confirm, rotate a key, set up the controller's own end, read the findings, and save the plan, which then opens in Changes. Changing anything there asks for your password again; an account that may only look sees the members and no buttons. The same steps through the API:

1. `POST /api/sfnet` makes the network. It picks a range that no scanned host has an address or a route in, and never `100.64.0.0/10`, which Tailscale and NetBird use. Give `range` to choose one yourself, and `topology: "hub"` where hosts should meet only at a hub.
2. `POST /api/sfnet/members` with a `host` adds a scanned host. It gets one address for good. The other members call it at the address scans reach it at; give `endpoint` for another, or `reachable: false` for a host behind a NAT of its own, which then calls the others and keeps the path open.
3. `POST /api/sfnet/plan` saves a change plan. The first plan makes `sf0` and a key pair on each new member (`wg-interface`). Run it, and take a new infrastructure reading: the reading brings back each host's public key, and the host becomes active.
4. `POST /api/sfnet/plan` again writes the peers (`wg-peer`). Each host trusts a peer for that peer's one address and nothing more, so a host that is taken over cannot answer for another's address. After the next reading `GET /api/sfnet` shows, per host, which peers are confirmed by key.

What it holds to:

- **Private keys stay on their hosts.** The controller stores ranges, addresses and public keys. The step never prints the key, and its file is readable by root only.
- **A key is taken from a reading once.** If an active member later shows a different key, nobody is told to trust it. It is a critical notification, because either the interface was made again by hand or it is another machine.
- **A peer nobody asked for is a notification,** and the next plan revokes it.
- **A key changes only when you ask.** `POST /api/sfnet/members/rotate` marks a member, and the plans that follow do the rest in three runs, each after a new reading: the host makes a second key pair (`wg-rotate`, `prepare`) and the reading brings back its public half; every peer learns the new key, with no address on it yet; and when the readings show that every peer knows it, the host switches (`wg-rotate`, `switch`) and its peers move its address to the new key and drop the old one in the same plan. Until the switch nothing is interrupted. The old private key is deleted from the host at the switch. `{"cancel": true}` takes a rotation back before the switch. A second key that appears on a host without being asked for is not taken: it is a notification, and the next plan removes it.
- **A host that leaves** (`POST /api/sfnet/members/remove`) comes off every other member at the next plan and loses its interface and key. Its address is never given to another host.
- **Open the port.** Peers call UDP 51903; add a `fw-rule` step where a firewall is in the way.

A machine that already has an interface called `sf0` that is not WireGuard is left alone. Compose uses `br-sforge` for new installations. Existing sites can pin `STORAGEFORGE_BRIDGE=sf0` until their next maintenance window. To migrate, stop the stack with `docker compose down` (preserve its volumes), remove old sf0 egress hooks with `sudo STORAGEFORGE_BRIDGE=sf0 docker/egress-firewall.sh --remove`, and update host firewall rules and the site's bridge setting to `br-sforge`. Recreate the stack and reapply its egress firewall before joining WireGuard.

### The controller as a member

The controller can be a member too, so that its own connections to the hosts can go over the network. There are two ways.

**In Docker: the link.** Start the stack with `docker-compose.sfnet.yml` as well:

```sh
docker compose -f docker-compose.yml -f docker-compose.sfnet.yml up -d
```

That adds the `sfnet` service, a small container that shares the server's network, runs as root with the one capability `NET_ADMIN`, makes `sf0` there and keeps its private key in a volume only it mounts. The server stays unprivileged and never sees the key. It writes what it wants (an address, a port, peers by public key) to one folder and reads what the link reports from another; the link checks every line before it acts and never repeats one. The Docker host needs WireGuard in its kernel. Then:

1. `POST /api/sfnet/controller` makes the controller a member. It gets an address like any host.
2. `POST /api/sfnet/controller/apply` hands the link what the interface should be. This is the controller's half of every plan: do it whenever `GET /api/sfnet` shows `controller.pending`, as after a host joined, left or rotated its key. The link acts within five seconds, and its report brings back the controller's public key.
3. Save and run the plan for the hosts as before, so they learn the controller's key.

By default the controller calls the hosts and keeps each path open, so no port needs to be published. Where hosts must call it, uncomment the `ports` lines in `docker-compose.sfnet.yml` and give `{"endpoint": "<the Docker host's address>"}` when it joins. The controller's key is rotated like a host's (`/api/sfnet/members/rotate` with the host `StorageForge controller`, then apply), and `/api/sfnet/members/remove` followed by an apply removes its interface and key. If the server container is restarted on its own, the link notices that its network is gone, stops, and Docker starts it again in the new one.

**On a host, with no container: the host is the member.** Where StorageForge runs directly on a machine that it also scans, add that host like any other and say that the controller runs on it: `POST /api/sfnet/controller` with `{"on": "<host>"}`. Nothing else is needed, since the controller then uses that host's `sf0`. For a controller on a machine it does not scan, `storageforge-index sfnet link` prints the link program: run it as root as a service (`storageforge-sfnet-link run`) with `SF_WG_WANT` and `SF_WG_STATE` set to two folders, the first writable by the StorageForge user and the second by root only, and start the server with `STORAGEFORGE_SFNET_WANT` and `STORAGEFORGE_SFNET_STATE` naming the same two.

`storageforge-index sfnet` prints the members and what the readings confirm.

### What goes over it

Once the controller is a member, its own SSH connections to a host go over the network: scans, readings, deploys, key installs and rotations, plan runs and the console. This happens per connection, and only where the controller and the host are both active members and the readings confirm each as the other's peer by the key on record, with the right address. Then the host's SSH port is tried at its network address for two seconds; if nothing answers, the connection goes to the normal address as before, and the network is not tried again for that host for a minute. A host that is no member, is pending or revoked, or shows a key that is not the one on record is always reached at its normal address.

The SSH host key that is checked is still the one pinned for the host's normal address, whichever address carries the connection, and a host whose key was never pinned is not met for the first time over the network. In the console the route is listed first as **SSH over the StorageForge network**, and on the map the interface carries that name. An interface that happens to be called `sf0` is not offered as a route by its name alone.

Not carried: Sends, Moves and sync run between two hosts and keep a tunnel of their own per transfer (SSH with a job key), and NFS and SMB shares are not put on the network. In the hub topology a controller that is not a hub reaches only the hubs this way, because no step turns on forwarding at a hub.

Built, not lab-tested.

## Designs

A design is what should be there: hosts, bridges, VLANs, containers, VMs and rules. **Compare** lists what is missing, what differs, and what is there that it does not name, against what scans found. What has not been read is **not known**, and is not counted as missing. **Stage what is missing** turns the gap into a plan.

Exports go one way: nothing is read back from a script. Bash and Ansible come from that plan. Terraform (`kreuzwerker/docker`, `dmacvicar/libvirt`) and Puppet (`puppetlabs-docker`, `puppetlabs-firewall`) are for your own pipeline, and StorageForge never runs them.

## On the map

- **The look is Topology's:** a dot grid, each host a dashed frame with its name on a ruled heading, each interface, network, port, workload or mount a row with its kind in letters at the left end. The tag's colour only repeats the family (network, service, workload, storage): who can reach a port is still the row's own colour and the word at its right end. The legend is shut until you open it.
- **Modes:** Network, Flow, Workloads, Storage only, Security, Custom. They are presets of the layers (Storage, Network, Services, Firewall, Workloads, Access, Placed by hand), which can also be stacked by hand; doing so makes the mode Custom.
- **Grouping:** by host, subnet or runtime. Double-click a frame to shut it. Far out, frames stay and their rows go.
- **Saved views** keep layers, filter, grouping and where you dragged things.
- **Timeline:** go back to an earlier reading. Storage is not kept: it shows the other layers as they stood.
- **Security mode** shows who can reach what, holds and decoys on mounts, and workloads no hold or decoy reaches. It warns when an armed sentinel could cut off a gateway, DNS server or hypervisor that is not on the exempt list.
- **Exports:** JSON, Mermaid, DOT, SVG, draw.io, Obsidian canvas, PNG, and PDF through the browser's print. Redacting them hides addresses, host names and MACs, and each export is audited.
- **Links:** `/#/map/details?mode=security`, or `/#/map/details?layers=network,firewall`; the older `/#view=map&layers=network,firewall&mode=security` works too.

Firewall rules and exposure say how to get in, so they need `security.view`. The map itself needs `map.view`.

## Not built

The roadmap goes further than this.

- For private networks and access proxies: an alert when an OpenVPN certificate or CRL is about to end (the map says it, nothing notifies), OpenVPN client profiles, a public Pomerium route in the exposure engine, Teleport's applications, databases and session recordings, and making Teleport or Boundary targets from the host inventory.
- Deploying a stack, an LXC instance or a catalog tool from the map, or a VM from an ISO or cloud image. Those are in the [roadmap](../roadmap.md).
- From the map: moving, cloning or resizing a VM, restricting a service's bind address, putting a listener behind a proxy, rotating a peer's key.
- Reading a firewalld rich rule beyond family, source, destination, service, port, protocol, masquerade and the verdict. Rules with other clauses (`forward-port`, `icmp-type`, `mark`, `limit`) stay unmodelled, which gives **Unknown**.
- Changing what another file of the host's network says: the network steps write files of their own.
- Custom icons and colour rules.

### Built since, not lab-tested

These were built for 0.6.0 and have unit tests, but have not met a real device or fleet.

- **Layouts and exports:** the map has Grid, Force and Rack layouts, and its **Export** menu includes NetBox and Grafana files next to JSON, Mermaid, DOT, SVG, draw.io and the Obsidian canvas.
- **Readings:** `lldpctl` neighbours on Linux hosts, read-only SNMP v2c and v3 (`snmp.py`), and Linux interface byte counters between scans (`traffic.py`), with alerts for the network scanner and the counters.
- **Quarantine:** `bridge`-family fencing and `place-before` rule positioning, so a quarantine can reach bridged VMs. Whether it does has not been measured on a real bridge.
- **Dashboards:** map tiles on the custom dashboard.

## What has been tested, and how

| How | Covers |
| :--- | :--- |
| `tests/test_infra.py` | Real `ip` and `ss`, real `nft` and `iptables` in a throwaway network namespace, real Docker |
| `tests/test_platform_more.py` | The firewall writer against the real kernel, reach, what-if and designs |
| `tests/test_browser_smoke.py` | The panels and the map's modes in Chromium under the real CSP |
| `tests/test_tunnels.py`, `tests/test_tunnel_exposure.py` | What each tunnel's configuration publishes, with no credential in what comes back; a loopback or firewalled listener a tunnel publishes shown as public; the two tunnel steps against stand-ins for `cloudflared` and `newt`, since neither is installed where the tests run |
| `tests/test_overlay_readers.py`, `tests/test_accessproxies.py`, `tests/test_connections.py` | Each reader on a sample of the tool's own output, saying where the sample comes from; Nebula against the real `nebula-cert`, the OpenVPN CA against one the real `openssl` made; the collector's own lines run in bash against stand-in tools, with no credential and no person's name in what they print; the rule that cuts a configuration file gives the same text in awk on the host and in Python on the server; no reader raises on anything; the map built from the readings |
| `tests/test_network_steps.py`, `tests/test_netconfig.py` | The bond, address, route and DHCP steps in bash against stand-ins for `ip`, `netplan`, `nmcli`, `networkctl` and `ifup` that keep their state in files: what each system is given, a second run finding its own work, the way back the rollback timer runs, and the real `storageforge-fwrules` journal undoing a bond. The readers of netplan, networkd, NetworkManager and ifupdown on samples of each format, damaged at random, and the map built from them |
| `tests/test_overlay_steps.py` | The `netbird`, `zerotier` and `openziti` steps against stand-ins on a PATH of their own, since none of the three is installed where the tests run. Nebula against the real thing: certificates made here are accepted by the real `nebula-cert` 1.12.0 and read back the same, `nebula -test` accepts the configurations, and two real Nebula nodes in network namespaces reach each other with them until one certificate is revoked. `vault headscale-key` against a stand-in for `headscale` |
| [KVM lab](kvm-lab.md) tier 10 | What scans read against each VM. A capture on the VM during a scan: the only connection is SSH |
| KVM lab tier 11 | Rules on ufw, nftables and firewalld judged by real connections between VMs, a published port's fix, a fence across a reboot, the timer undoing a firewall rule and a bridge that each cut SSH, VLANs on networkd and NetworkManager across a reboot, the reach table against real connections, the overlay against the next reading, a half-deployed design, WireGuard confirmed by key, and a placeholder promoted to a host |

**Not tested:** the 0.6.0 map extras above (SNMP, LLDP, counters, NetBox and Grafana files, bridge fencing). Terraform and Puppet have not applied the exports: those are checked for structure and for values held as data. Incus, LXC, Proxmox guests, Tailscale, proxy routes and identity providers have parsers and unit tests, and have not met a real host in the lab. libvirt has been read in the lab, with a guest defined and not booted. No generated VM has been booted. Whether a `bridge`-family quarantine reaches a bridged VM has not been measured, and the page says a bridged VM is outside host rules where no bridge fence is in place: the lab shows a quarantine without one does not stop a published container port.


### Saved storage designs after upgrade

Schema 74 copies each saved blueprint into its host’s storage section. The planner, CLI imports, shares and graph read that section. The original blueprint and its import time remain available through the read-only `blueprints` view. Essentials backups include the original and current data. Restoring a backup created before this migration upgrades its saved blueprints on startup.
