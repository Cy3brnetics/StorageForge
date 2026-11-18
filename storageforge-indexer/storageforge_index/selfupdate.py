"""Which StorageForge this is, and whether the git repository it is released from has a newer one.

    STORAGEFORGE_UPDATE_URL=https://github.com/Cy3brnetics/StorageForge.git      (or a Forgejo, Gitea or GitLab on the LAN)

A release is a tag `vX.Y.Z` or `vX.Y.Z.N` in that repository. The server asks the repository for its list of tags, the same
request `git ls-remote` makes over http, a few minutes after it starts and every six hours after. It sends nothing about this
installation, and it is off until the address is set: StorageForge calls nothing on its own.

This module only reads and tells: a newer tag is a notification and a line beside the name in the header. It never installs
anything. The web application runs in a container with a read-only root and no way to reach Docker, and stays that way. What
installs a release is on the Docker host: `docker/update.sh` and its timer, or the stack manager the installation is run by.
docs/operations.md "Updates".
"""
from __future__ import annotations

import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

SOURCE_ENV = 'STORAGEFORGE_UPDATE_URL'
INTERVAL = 6 * 3600
FIRST_AFTER = 120
MAX_ANSWER = 4 * 1024 * 1024          # a repository with tens of thousands of refs is not this one
# Release tags only. `v0.5.5-rc1`, `nightly` and the like are not offered to anyone.
TAG_RE = re.compile(rb'^(?:0000)?[0-9a-f]{4}[0-9a-f]{40,64} refs/tags/(v\d{1,5}(?:\.\d{1,5}){2,3})(\^\{\})?$', re.MULTILINE)
VERSION_RE = re.compile(r'v?(\d{1,5}(?:\.\d{1,5}){2,3})')

_lock = threading.Lock()
_state: dict = {'latest': None, 'checked_at': None, 'error': None}


class UpdateCheckError(RuntimeError):
    pass


def as_numbers(version: str) -> tuple[int, ...]:
    """'v0.5.4.1' → (0, 5, 4, 1), and '0.5.4' → (0, 5, 4, 0), so the two compare."""
    m = VERSION_RE.fullmatch(version) if isinstance(version, str) else None
    if not m:
        raise ValueError(f'not a release version: {version!r}')
    parts = tuple(int(p) for p in m.group(1).split('.'))
    return parts + (0,) * (4 - len(parts))


def releases(advertisement: bytes) -> list[str]:
    """The release versions in a repository's answer to `info/refs?service=git-upload-pack`, oldest first."""
    found = {m.group(1).decode()[1:] for m in TAG_RE.finditer(advertisement.replace(b'\x00', b'\n'))}
    return sorted(found, key=as_numbers)


def source() -> str | None:
    """The repository address, or None when checking is off. An address with a password in it is refused: it would be shown."""
    url = (os.environ.get(SOURCE_ENV) or '').strip()
    if not url:
        return None
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise UpdateCheckError(f'{SOURCE_ENV} must be an http or https address of a git repository, with no user name or password in it')
    return url.rstrip('/')


def fetch(url: str) -> list[str]:
    """Ask the repository for its tags. The request goes out the way alerts do: resolved once, never to this container or a
    link-local address, and never following a redirect."""
    from . import alerts
    request = urllib.request.Request(url + '/info/refs?service=git-upload-pack', headers={'User-Agent': 'git/2.0 (StorageForge)', 'Accept': '*/*'})
    try:
        alerts._check_target(url)
        with alerts._opener.open(request, timeout=15) as answer:
            kind = answer.headers.get('Content-Type', '')
            body = answer.read(MAX_ANSWER + 1)
    except urllib.error.HTTPError as exc:
        raise UpdateCheckError(f'the repository answered HTTP {exc.code}' + (': it is private, or the address is wrong' if exc.code in (401, 403, 404) else '')) from None
    except (OSError, ValueError) as exc:
        raise UpdateCheckError(f'the repository could not be reached: {exc}'[:300]) from None
    if 'git-upload-pack-advertisement' not in kind:
        raise UpdateCheckError('what answered at that address is not a git repository')
    if len(body) > MAX_ANSWER:
        raise UpdateCheckError('the repository lists more than is read here')
    return releases(body)


def check() -> dict:
    """One check, now. The result is kept for status() and problems(); a failed check keeps the last answer and says why it failed."""
    try:
        url = source()
        if url is None:
            return status()
        found = fetch(url)
        with _lock:
            _state.update(latest=found[-1] if found else None, checked_at=time.time(), error=None if found else 'the repository has no release tags')
    except UpdateCheckError as exc:
        with _lock:
            _state.update(error=str(exc), failed_at=time.time())
    return status()


def status() -> dict:
    """What /api/version answers."""
    try:
        url, wrong = source(), None
    except UpdateCheckError as exc:
        url, wrong = None, str(exc)
    with _lock:
        latest, checked, error = _state['latest'], _state['checked_at'], wrong or _state['error']
    behind = bool(latest) and as_numbers(latest) > as_numbers(__version__)
    return {'version': __version__, 'checking': url is not None, 'source': urllib.parse.urlsplit(url).hostname if url else None,
            'latest': latest, 'update_available': behind, 'checked_at': checked, 'error': error}


def problems() -> dict:
    """A newer release is a notification until this is that release. A check that keeps failing is one too, because an
    installation that cannot see releases looks exactly like one that is up to date."""
    s = status()
    if s['update_available']:
        return {'update-available': ('update-available', 'storageforge', f'StorageForge {s["latest"]} is released',
                                     f'This is {s["version"]}. Read the changelog for what it fixes; docs/operations.md "Updates" has how it is installed', 'warn')}
    with _lock:
        failing_since = _state.get('failed_at') if _state['error'] else None
        last_good = _state['checked_at']
    if s['checking'] and s['error'] and failing_since and (last_good is None or failing_since - last_good > 2 * INTERVAL):
        return {'update-check': ('update-check', 'storageforge', 'Releases cannot be checked', s['error'], 'warn')}
    return {}


def run(stop: threading.Event | None = None, wake=None):
    """The server's thread: a first check soon after start, then one every INTERVAL. `wake()` is called when the answer changed."""
    stop = stop or threading.Event()
    if stop.wait(FIRST_AFTER):
        return
    while True:
        before = status()
        after = check()
        if wake and (before['latest'], bool(before['error'])) != (after['latest'], bool(after['error'])):
            wake()
        if stop.wait(INTERVAL):
            return
