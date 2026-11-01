#!/usr/bin/env python3
"""The configs of the KVM lab, which of them this build runs, and what each can do, so tests never name a host for its
abilities. Run directly, it picks a build: sf-ctl, sf-alpine (the only host without systemd) and 5 more at random, with
at least two btrfs hosts and one each of ZFS, LVM and SELinux. The same seed always gives the same build.

    roles.py pick <seed>
"""
import os
import random
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
ALWAYS = ('sf-ctl', 'sf-alpine')
BUILD_SIZE = 7
NEEDS = {'btrfs': 2, 'zfs': 1, 'lvm': 1, 'selinux': 1}


def rows(name):
    lines = (HERE / name).read_text().splitlines()
    return [r.split('|') for r in lines if r.strip() and not r.startswith('#')]


@dataclass
class Node:
    name: str
    ip: str
    abilities: frozenset
    pm: str
    data: str
    room: str
    subvol: str
    snaps: str
    recv: str
    fill: str
    topology: list

    def can(self, ability):
        return ability in self.abilities

    def tag(self, prefix):
        """The value of an ability like zfs-pool:tank."""
        return next((a.split(':', 1)[1] for a in self.abilities if a.startswith(prefix + ':')), None)


def pool():
    ips = {r[0]: r[6] for r in rows('nodes.conf')}
    out = {}
    for name, abilities, pm, data, room, subvol, snaps, recv, fill, topology in rows('roles.conf'):
        out[name] = Node(name, ips[name], frozenset(abilities.split(',')), pm, data, room, subvol, snaps, recv, fill,
                         [t for t in topology.split(',') if t])
    return out


def state_dir():
    return Path(os.environ.get('SFLAB_STATE', Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local' / 'state')) / 'sflab'))


def build():
    """The nodes of this build, in nodes.conf order. Every config, if no build has been picked."""
    everything = pool()
    path = state_dir() / 'selection'
    if not path.exists():
        return everything
    chosen = path.read_text().split()[1:]
    return {name: node for name, node in everything.items() if name in chosen}


def seed():
    path = state_dir() / 'selection'
    return path.read_text().split()[0] if path.exists() else ''


def having(ability):
    return [n for n in build().values() if n.can(ability)]


def deployable():
    """The hosts deploys can run on, without the controller: tests that need several take them in order."""
    return [n for n in having('deploy') if not n.can('controller')]


def other_than(node, among=None):
    return next(n for n in (deployable() if among is None else among) if n.name != node.name)


def sender():
    return next(n for n in having('btrfs') if n.subvol)


def receiver():
    return other_than(sender(), having('btrfs'))


def smb_server():
    """An SELinux host whose share has a labelled path above it: tier 3 tests the other kind apart."""
    return next((n for n in having('selinux') if not n.can('btrfs-nested')), None) or next(n for n in deployable() if not n.can('btrfs-nested'))


def fill_host():
    return having('zfs')[0]


def pick(number):
    everything = pool()
    rng = random.Random(number)
    rest = sorted(set(everything) - set(ALWAYS))
    while True:
        names = {*ALWAYS, *rng.sample(rest, BUILD_SIZE - len(ALWAYS))}
        chosen = [everything[n] for n in names]
        if all(sum(n.can(a) for n in chosen) >= count for a, count in NEEDS.items()):
            return [n for n in everything if n in names]


if __name__ == '__main__':
    print(*pick(sys.argv[2]))
