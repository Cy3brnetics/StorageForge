"""The key enclave's micro VM, started and watched (roadmap section 14, "Stateless and restartable").

    Supervisor(image_dir).start()  → 'vsock:CID:7000'

What starting means here, in order, and each step that fails is the end of it:

    1. the image is the image: every file matches SHA256SUMS beside it, and SHA256SUMS matches the digest the caller pinned
    2. the VM boots with one device, the vsock socket: no network card, no disk, no shared folder, nothing typed into its console
    3. it answers, and says it is the VM's only program (pid1) with its memory locked. A test double of it says neither
    4. the key it shows for its channel is pinned (enclave.py): the VM was started a moment ago over a socket this made for it,
       so what answers first is the enclave. A restart pins the new key the same way

After that a thread watches the VM. If it stops, every operation that needs a key fails closed, because the address still names
the enclave and nothing answers there (vault.py never falls back); `on_event('down', …)` is called, and the VM is started again. It
comes back holding nothing: the next Vault.unlock() hands it the secret again where the secret is available, and otherwise it stays
locked until a person unlocks it.

Two programs can run the VM, from the same kernel and initramfs:

    firecracker   the one in the shipped image: a device model of a few thousand lines under its own seccomp filter. It needs
                  /dev/kvm and nothing else, and gives the guest's vsock to the host as a socket file (`fc:PATH:7000`)
    qemu          QEMU's `microvm` machine, for a developer's machine and the lab: it needs /dev/vhost-vsock too (`vsock:CID:7000`)

Firecracker is used where it is installed; STORAGEFORGE_ENCLAVE_VMM names one to insist on. Its jailer is not used: the jailer
needs root to make a chroot and cgroups, and the server's container has neither root nor a capability. What stands in for it
there is the container itself (read-only root, no capabilities, no new privileges) around Firecracker's own filter.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from . import enclave

PORT = 7000
FILES = ('bzImage', 'initramfs.cpio.gz', 'vmlinux')          # QEMU boots the first, Firecracker the last; one digest covers what either would run
MEMORY_MIB = 256                  # the kernel, the program, and Argon2id's 64 MiB at unlock
BOOT_SECONDS = 20
QEMU = 'qemu-system-x86_64'
FIRECRACKER = 'firecracker'
VMM_ENV = 'STORAGEFORGE_ENCLAVE_VMM'


class EnclaveVMError(RuntimeError):
    pass


def image_digest(folder) -> str:
    """One digest for the image: the SHA-256 of its SHA256SUMS lines for the two kernel files and the initramfs, after each file has been
    checked against its line. This is the value to pin (STORAGEFORGE_ENCLAVE_IMAGE) and to compare with a build of one's own."""
    folder = Path(folder)
    try:
        listed = dict(reversed(line.split(maxsplit=1)) for line in (folder / 'SHA256SUMS').read_text().splitlines() if line.strip())
    except (OSError, ValueError):
        raise EnclaveVMError(f'{folder} has no readable SHA256SUMS: build the image with enclave/image/build.sh') from None
    lines = []
    for name in FILES:
        try:
            with open(folder / name, 'rb') as f:
                actual = hashlib.file_digest(f, 'sha256').hexdigest()
        except OSError:
            raise EnclaveVMError(f'the enclave image has no {name}') from None
        if listed.get(name) != actual:
            raise EnclaveVMError(f'{name} is not the file SHA256SUMS lists: the enclave image was changed after it was built')
        lines.append(f'{actual}  {name}\n')
    return hashlib.sha256(''.join(lines).encode()).hexdigest()


def vmm() -> str:
    """'firecracker' or 'qemu': the one asked for, else Firecracker where it is installed."""
    asked = (os.environ.get(VMM_ENV) or '').strip().lower()
    if asked and asked not in ('firecracker', 'qemu'):
        raise EnclaveVMError(f'{VMM_ENV} is firecracker or qemu')
    return asked or ('firecracker' if shutil.which(FIRECRACKER) else 'qemu')


def missing(which: str | None = None) -> str | None:
    """Why a micro VM cannot be started on this machine, or None. The caller says so and does not pretend: without the enclave
    the vault is what it was before, and is labelled that way."""
    which = which or vmm()
    program = FIRECRACKER if which == 'firecracker' else QEMU
    if not shutil.which(program):
        return f'{program} is not installed'
    for device in ('/dev/kvm',) if which == 'firecracker' else ('/dev/kvm', '/dev/vhost-vsock'):
        if not os.access(device, os.R_OK | os.W_OK):
            return f'{device} is not here or not usable by this account'
    return None


def from_env(on_event=None, shared: bool = True) -> 'Supervisor | None':
    """STORAGEFORGE_ENCLAVE=vm asks this process to run the enclave itself: the image is in STORAGEFORGE_ENCLAVE_IMAGE_DIR, and
    STORAGEFORGE_ENCLAVE_IMAGE pins its digest. The address replaces `vm` in this process's environment, where vault.py reads it.
    Raises EnclaveVMError where it cannot be started: what was asked for the enclave does not go on without it.
    shared: its files go in the server's runtime folder. A command beside a running server passes False and gets a folder of
    its own, so that it cannot take the server's socket away."""
    if os.environ.get(enclave.ADDRESS_ENV) != 'vm':
        return None
    folder = os.environ.get('STORAGEFORGE_ENCLAVE_IMAGE_DIR')
    if not folder:
        raise EnclaveVMError('STORAGEFORGE_ENCLAVE=vm needs STORAGEFORGE_ENCLAVE_IMAGE_DIR: the folder enclave/image/build.sh wrote')
    supervisor = Supervisor(folder, expect=os.environ.get('STORAGEFORGE_ENCLAVE_IMAGE') or None, on_event=on_event, runtime_dir=enclave.run_dir() if shared else None)
    os.environ[enclave.ADDRESS_ENV] = 'vm:starting'          # until it is up, nothing may take `vm` for no enclave at all
    try:
        os.environ[enclave.ADDRESS_ENV] = supervisor.start()
    except EnclaveVMError:
        supervisor.stop()
        raise
    return supervisor


_own: 'Supervisor | None' = None
_own_lock = threading.Lock()


def on_demand() -> str:
    """The address of an enclave this process started for itself because something asked for a key: started at the first
    call, stopped when the process ends. It comes up locked like any other, and the vault hands it the secret."""
    global _own
    with _own_lock:
        if os.environ.get(enclave.ADDRESS_ENV) == 'vm':
            import atexit
            _own = from_env(shared=False)
            atexit.register(_own.stop)
        return os.environ[enclave.ADDRESS_ENV]


class Supervisor:
    def __init__(self, image_dir, expect: str | None = None, on_event=None, runtime_dir=None, memory_mib: int = MEMORY_MIB, vmm_name: str | None = None):
        """expect: the image digest to insist on (image_digest). on_event(kind, detail): 'up', 'down', 'failed'. vmm_name: 'firecracker' or 'qemu'."""
        self.vmm = vmm_name or vmm()
        self._made = None
        self.image, self.expect, self.memory = Path(image_dir), expect, memory_mib
        self.on_event = on_event or (lambda kind, detail: None)
        self.runtime = Path(runtime_dir) if runtime_dir else None
        self.proc: subprocess.Popen | None = None
        self.cid: int | None = None
        self.digest: str | None = None
        self.restarts = 0
        self._stop = threading.Event()
        self._watcher: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def address(self) -> str | None:
        if not self.cid:
            return None
        return f'fc:{self.runtime / "enclave-vsock.sock"}:{PORT}' if self.vmm == 'firecracker' else f'vsock:{self.cid}:{PORT}'

    def _firecracker(self, cid: int) -> list[str]:
        # One device, the vsock. No drive, no network interface, no balloon, no API socket to configure it by afterwards, and
        # Firecracker's own seccomp filter, which is on unless asked off
        sock, conf = self.runtime / 'enclave-vsock.sock', self.runtime / 'enclave-vm.json'
        sock.unlink(missing_ok=True)                        # Firecracker makes it, and stops if it is there
        conf.write_text(json.dumps({
            'boot-source': {'kernel_image_path': str(self.image / 'vmlinux'), 'initrd_path': str(self.image / 'initramfs.cpio.gz'), 'boot_args': 'console=ttyS0 panic=-1 quiet reboot=k'},
            'drives': [], 'network-interfaces': [], 'machine-config': {'vcpu_count': 1, 'mem_size_mib': self.memory, 'smt': False},
            'vsock': {'guest_cid': cid, 'uds_path': str(sock)}}))
        return [FIRECRACKER, '--no-api', '--config-file', str(conf), '--id', 'storageforge-enclave', '--level', 'Warning']

    def _argv(self, cid: int) -> list[str]:
        if self.vmm == 'firecracker':
            return self._firecracker(cid)
        # No -netdev, no -drive, no -virtfs, no balloon, no monitor, no display. The serial port is the kernel's console and goes
        # nowhere it could be typed into; the program itself prints nothing there.
        serial = f'file:{self.runtime / "enclave-console.log"}' if self.runtime else 'null'
        return [QEMU, '-M', 'microvm,rtc=off,pit=off,pic=off,acpi=off', '-enable-kvm', '-cpu', 'host', '-m', str(self.memory), '-smp', '1', '-nodefaults', '-no-user-config',
                '-display', 'none', '-monitor', 'none', '-no-reboot', '-kernel', str(self.image / 'bzImage'), '-initrd', str(self.image / 'initramfs.cpio.gz'),
                '-append', 'console=ttyS0 panic=-1 quiet', '-serial', serial, '-device', f'vhost-vsock-device,guest-cid={cid}',
                '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']

    def _boot(self, cid: int) -> dict:
        """One attempt at this CID. Returns the enclave's status, or raises with what QEMU said."""
        if self.runtime is None:
            self._made = tempfile.mkdtemp(prefix='sf-enclave-')          # 0700: the vsock socket is the way to the enclave
            self.runtime = Path(self._made)
        argv = self._argv(cid)
        quiet = {'stdin': subprocess.DEVNULL, 'start_new_session': True, 'env': {'PATH': os.environ.get('PATH', '/usr/bin:/bin')}}          # nothing of this process's environment: no secret, no STORAGEFORGE_*
        if self.vmm == 'firecracker':
            # Firecracker writes its log and the guest's console to stdout. To a file, not a pipe nobody reads, which would fill and stop it
            with open(self.runtime / 'enclave-console.log', 'wb') as log:
                proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, **quiet)
        else:
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **quiet)
        until, last = time.time() + BOOT_SECONDS, None
        self.cid, was = cid, self.cid
        client = enclave.Enclave(self.address, timeout=3)
        # A VM this starts makes a new key for its channel. The first answer from it, over the socket this just made for it, is the
        # key that is pinned: every later client, in this process or beside it, refuses anything else at this address
        enclave.forget_pin(self.address)
        self.cid = was
        while time.time() < until:
            if proc.poll() is not None:
                if proc.stderr:
                    said = proc.stderr.read().decode(errors='replace').strip()[-400:]
                    proc.stderr.close()
                else:
                    said = (self.runtime / 'enclave-console.log').read_text(errors='replace').strip()[-400:]
                raise EnclaveVMError(f'the enclave VM stopped as it started: {said or "no message"}')
            try:
                status = client.status()
            except enclave.EnclaveError as exc:
                last = exc
                time.sleep(0.05)
                continue
            finally:
                client.close()
            if status.get('pid1') is not True or status.get('memory_locked') is not True:
                self._kill(proc)
                raise EnclaveVMError('what answered is not the enclave in its own VM: it is not PID 1, or its memory is not locked')
            self.proc, self.cid = proc, cid
            return status
        self._kill(proc)
        raise EnclaveVMError(f'the enclave VM did not answer within {BOOT_SECONDS} seconds: {last}')

    @staticmethod
    def _kill(proc):
        proc.kill()
        proc.wait()
        for pipe in (proc.stdout, proc.stderr):
            if pipe:
                pipe.close()

    def start(self) -> str:
        """Check the image, boot it, and begin watching. Returns the address to put in STORAGEFORGE_ENCLAVE."""
        why = missing(self.vmm)
        if why:
            raise EnclaveVMError(f'no micro VM can be started here: {why}')
        self.digest = image_digest(self.image)
        if self.expect and not secrets.compare_digest(self.digest, self.expect.strip().lower()):
            raise EnclaveVMError(f'the enclave image is not the one pinned: it is {self.digest}')
        with self._lock:
            status = self._start_vm()
        self.on_event('up', {'address': self.address, 'image': self.digest, 'version': status.get('version')})
        self._watcher = threading.Thread(target=self._watch, name='enclave-watch', daemon=True)
        self._watcher.start()
        return self.address

    def _start_vm(self) -> dict:
        # The same CID after a restart, so the address everything was given still names the enclave. A CID another VM holds
        # makes QEMU stop at once; the first start tries a few.
        # Firecracker's guest is reached through its own socket file, so its CID meets nobody else's
        tries = [self.cid] if self.cid else [3] if self.vmm == 'firecracker' else [3 + secrets.randbelow((1 << 31) - 4) for _ in range(5)]
        error = None
        for cid in tries:
            try:
                return self._boot(cid)
            except EnclaveVMError as exc:
                error = exc
                if 'guest cid' not in str(exc).lower() and 'address already in use' not in str(exc).lower():
                    break
        raise error

    def _watch(self):
        while not self._stop.is_set():
            proc = self.proc
            if proc is not None and proc.poll() is None:
                self._stop.wait(0.5)
                continue
            if self._stop.is_set():
                return
            code = proc.returncode if proc else None
            for pipe in (proc.stdout, proc.stderr) if proc else ():
                if pipe:
                    pipe.close()
            self.on_event('down', {'address': self.address, 'exit': code})
            # It is started again, more slowly each time it fails: an enclave that will not stay up is not hammered at
            delay = 1.0
            while not self._stop.is_set():
                try:
                    if image_digest(self.image) != self.digest:
                        raise EnclaveVMError('the enclave image changed while it ran: it is not started from a different image')
                    with self._lock:
                        if self._stop.is_set():
                            return
                        status = self._start_vm()
                    self.restarts += 1
                    self.on_event('up', {'address': self.address, 'image': self.digest, 'version': status.get('version'), 'restarts': self.restarts, 'state': status.get('state')})
                    break
                except EnclaveVMError as exc:
                    self.on_event('failed', {'address': self.address, 'why': str(exc)})
                    self._stop.wait(delay)
                    delay = min(delay * 2, 60.0)

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        self._stop.set()
        with self._lock:
            if self.proc is not None and self.proc.poll() is None:
                self._kill(self.proc)
        if self.address:
            try:
                enclave.forget_pin(self.address)
            except OSError:
                pass
        if self._watcher is not None:
            self._watcher.join(5)
        if self._made:
            shutil.rmtree(self._made, ignore_errors=True)
