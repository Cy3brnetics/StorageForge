"""The container panels StorageForge recognises, in one table: how each is told from its image, its container labels, its systemd
units and the folder it keeps compose projects in, and the API connection kind that reads it. A leaf: it imports nothing of ours.

Each column matches its own way, and that stays: an image is a case-insensitive regular expression found anywhere in the image name, a
label or a unit is a prefix, and a folder is a substring of the lowercased compose folder. Where two panels could both match, each
lookup has its own order (the *_ORDER tuples below), kept as it was when these were four separate lists.

Two copies stay literal on purpose and a test holds them to this table: the label filter in runtimes/docker.py (KEEP_LABELS decides
which labels are stored at all) and the unit grep in the scan script wlread.BODY (it runs on scanned hosts, so no table data is put
into it).
"""
from __future__ import annotations

from typing import NamedTuple


class Panel(NamedTuple):
    name: str                       # the title shown, as label evidence and the API connection kind both name it
    image: str = ''                 # a regular expression searched in the image name, case-insensitive
    labels: tuple[str, ...] = ()    # container label prefixes
    units: tuple[str, ...] = ()     # systemd unit name prefixes
    folders: tuple[str, ...] = ()   # substrings of the lowercased folder a compose project was started from
    api: str = ''                   # the API connection kind (apiconn.KINDS) that reads it, if there is one


PANELS = (
    Panel('Dockhand', r'dockhand', ('dockhand.',), ('dockhand',), ('dockhand',), 'dockhand'),
    Panel('Portainer', r'portainer', ('io.portainer.',), ('portainer',), ('portainer', '/data/compose/'), 'portainer'),
    Panel('Komodo', r'komodo', ('komodo.',), ('komodo-periphery', 'periphery.'), ('komodo',), 'komodo'),
    Panel('Dockge', r'dockge', ('dev.dockge.',), ('dockge',), ('/opt/stacks', 'dockge')),
    Panel('Dokploy', r'dokploy'),
    Panel('Coolify', r'coolify', ('coolify.',), ('coolify',), ('coolify',)),
    Panel('CasaOS', r'casaos', folders=('casaos',)),
)
BY_NAME = {p.name: p for p in PANELS}

# which panel wins when a container matches two, per lookup
IMAGE_ORDER = tuple(p.name for p in PANELS)
LABEL_ORDER = ('Komodo', 'Portainer', 'Coolify', 'Dockhand', 'Dockge')
UNIT_ORDER = ('Komodo', 'Portainer', 'Dockhand', 'Dockge', 'Coolify')
FOLDER_ORDER = ('Dockhand', 'Komodo', 'Portainer', 'Dockge', 'CasaOS', 'Coolify')


def pairs(column: str, order: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """(key, panel name) for one column, panels in the given order and each panel's keys in its own order."""
    return tuple((key, name) for name in order for key in getattr(BY_NAME[name], column))


IMAGES = tuple((p.name, p.image) for name in IMAGE_ORDER for p in (BY_NAME[name],) if p.image)   # (name, regex), as workloads.PANELS was
LABELS = pairs('labels', LABEL_ORDER)       # (prefix, name)
UNITS = pairs('units', UNIT_ORDER)          # (prefix, name)
FOLDERS = pairs('folders', FOLDER_ORDER)    # (substring, name)


def of_folder(path: str | None) -> str:
    """The panel that keeps a compose project in this folder, or 'compose' when none does."""
    p = (path or '').lower()
    return next((name for key, name in FOLDERS if key in p), 'compose')
