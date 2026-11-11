# Console

A terminal on a host or VM, in a browser tab of its own: **Open console…** on a host's menu, or in its details. It connects one of three ways:

- **SSH over the LAN**, to the address the host is scanned at.
- **SSH over Tailscale**, to its Tailscale address when a scan saw one (on `tailscale0`, or anything in 100.64.0.0/10). StorageForge must be on the same tailnet.
- **The serial console** of a VM, through `virsh console` on its scanned libvirt host, or on the machine StorageForge runs on. It works when the VM's network or SSH doesn't.

For a VM with a desktop, the page also gives the command that opens its graphical console in virt-viewer or Remote Viewer, over SSH to its libvirt host. That is native SPICE or VNC: faster than anything in a browser, with the clipboard and resizing. StorageForge doesn't stream screens itself.

## Setting it up

1. Bind a key for consoles, in **Keys**: tick **Allow the web console too** when you install a key, use **Bind a key that is already on a host** with **Web console** ticked, or turn **Console** on for a binding in the list. Your account needs `console.open` to allow it, and the password again. From the command line: `docker compose exec storageforge storageforge-index vault bind --key KEY --host HOST --user LOGIN --actions console` (as the app user: a root shell in the container cannot reach the database). The login is the account the terminal opens, so give consoles a login apart from the scan one where you can, and a scan login never becomes a shell. One binding per LAN address covers the Tailscale route too.
2. Scan the host through the vault once, so its host key is in StorageForge's `known_hosts`. Only a host key a scan confirmed is accepted. Over Tailscale the key of the LAN address is checked (`HostKeyAlias`).
3. For the serial console, the libvirt host's binding needs `console` too, and its login needs access to libvirt (the `libvirt` group).

## Who and what is kept

| | |
| :--- | :--- |
| Permission | `console.open`, marked high risk. Only the built-in admin role has it. Give it to a custom role on purpose |
| Password | Typed again for each session, unless it was typed in the last few minutes |
| Whose | A session is its opener's alone: no other account can read or type into it, admins included |
| Audit log | `console.open` and `console.close` for every session: who, host, kind, route, address, how long, bytes each way, why it ended. Failed opens too |
| Recording | Off unless turned on (**Recording and recordings** on the console page, `settings.manage`). Then every session is kept in full as an asciicast v2 file, input and output with their timing, mode 600 in the data folder, for as many days as set. It holds whatever is typed, passwords included. `console.recordings` lists and downloads them, and each download is in the audit log. Play one with `asciinema play FILE` |
| Limits | 4 consoles open at once. A session nobody reads or types into for 15 minutes is closed, and any session after 8 hours |

The SSH session carries nothing of the StorageForge machine along: no agent, no X11, no forwarded ports. The key is loaded into a private agent for the login, and that agent is gone a minute later.

## How it works

`ssh` (or `virsh console`) runs on a pseudo-terminal on the StorageForge machine. The page long-polls for output and posts what is typed, so there's no WebSocket: it works with the built-in server and through any proxy. The terminal is [xterm.js](https://xtermjs.org) 6.0, vendored into the app (MIT, `static/xterm-LICENSE.txt`). The console page is the one page whose policy allows `<style>` elements, which xterm.js sizes its character cells with. It still loads scripts from StorageForge only.
