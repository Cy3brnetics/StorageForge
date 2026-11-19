"""A desktop profile (roadmap section 7, phase 9): keybindings, window rules and the display layout, written once in a form no
compositor owns, and rendered as the configuration of the one a machine runs. A fleet then has the same keys whichever of them
each machine has.

    {'name': 'fleet', 'mod': 'super',
     'binds':    [{'keys': 'mod+Return', 'action': 'spawn', 'arg': 'ghostty'}, {'keys': 'mod+shift+2', 'action': 'move-to-workspace', 'arg': '2'}],
     'rules':    [{'app': 'firefox', 'title': '', 'workspace': '2', 'floating': False, 'fullscreen': False}],
     'displays': [{'output': 'DP-1', 'mode': '2560x1440@144', 'position': '0,0', 'scale': '1', 'transform': 'normal', 'enabled': True}]}

    normalize(profile)        the profile with every value checked, or ValueError saying which one
    render(profile, 'niri')   the text of a configuration fragment: 'niri' or 'sway'

Everything in a profile ends up in a configuration file that a compositor reads as the user, and a `spawn` is a command that
compositor runs. So a profile is checked like a plan: keys, names and modes are matched against what they can be, and a
command is letters, digits and a few signs, with no quote, backslash, dollar, semicolon or line break in it. Nothing is passed
through that could close a string or a block in either format and start a line of its own.

Hyprland is not rendered yet. Its configuration language changed more than once in the last year and the current one has to
be read from its own documentation before anything is written for it; a renderer written from memory would be a guess.
"""
from __future__ import annotations

import re

COMPOSITORS = ('niri', 'sway')
MODS = ('super', 'alt')
# action -> takes an argument
ACTIONS = {'spawn': True, 'close': False, 'fullscreen': False, 'toggle-floating': False, 'exit': False,
           'focus-left': False, 'focus-right': False, 'focus-up': False, 'focus-down': False,
           'move-left': False, 'move-right': False, 'move-up': False, 'move-down': False,
           'workspace': True, 'move-to-workspace': True}
TRANSFORMS = ('normal', '90', '180', '270', 'flipped', 'flipped-90', 'flipped-180', 'flipped-270')
MAX = {'binds': 300, 'rules': 200, 'displays': 16}

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}')
# a key as xkb names it: a letter, a digit, or a name such as Return, Left, F11, XF86AudioMute, bracketleft
KEY = re.compile(r'[A-Za-z0-9]|[A-Za-z][A-Za-z0-9_]{1,30}')
COMMAND = re.compile(r'[A-Za-z0-9_./:=@%+,-]+( [A-Za-z0-9_./:=@%+,-]+){0,30}')
APP = re.compile(r'[A-Za-z0-9][A-Za-z0-9 _.@+-]{0,99}')
TITLE = re.compile(r'[A-Za-z0-9(][A-Za-z0-9 _.@+():,/&!-]{0,99}')
WORKSPACE = re.compile(r'[1-9]|1[0-9]|20')
OUTPUT = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,30}')
MODE = re.compile(r'([1-9]\d{2,4})x([1-9]\d{2,4})(?:@(\d{1,3}(?:\.\d{1,3})?))?')
POSITION = re.compile(r'(-?\d{1,5}),(-?\d{1,5})')
SCALE = re.compile(r'[1-9](?:\.\d{1,3})?|0\.[2-9]\d{0,2}')


def _text(value, what: str, pattern: re.Pattern, empty: bool = False) -> str:
    if value is None or value == '':
        if empty:
            return ''
        raise ValueError(f'{what} is missing')
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f'{what} {str(value)[:60]!r} is not valid')
    return value


def _keys(value, what: str) -> str:
    """'mod+shift+Return' → the same with the modifiers in one order, or ValueError."""
    if not isinstance(value, str) or not value or len(value) > 80:
        raise ValueError(f'{what}: keys are missing')
    *mods, key = value.split('+')
    mods = [m.lower() for m in mods]
    if any(m not in ('mod', 'shift', 'ctrl', 'alt') for m in mods) or len(set(mods)) != len(mods):
        raise ValueError(f'{what}: the modifiers of {value!r} are mod, shift, ctrl and alt, each once')
    if not KEY.fullmatch(key):
        raise ValueError(f'{what}: {key!r} is not a key name')
    return '+'.join([m for m in ('mod', 'ctrl', 'alt', 'shift') if m in mods] + [key])


def normalize(profile) -> dict:
    if not isinstance(profile, dict):
        raise ValueError('a profile is an object')
    out = {'name': _text(profile.get('name'), 'the name', NAME), 'mod': profile.get('mod') or 'super', 'binds': [], 'rules': [], 'displays': []}
    if out['mod'] not in MODS:
        raise ValueError('mod is super or alt')
    for part in ('binds', 'rules', 'displays'):
        if not isinstance(profile.get(part) or [], list) or len(profile.get(part) or []) > MAX[part]:
            raise ValueError(f'{part} is a list of at most {MAX[part]}')
    seen = set()
    for i, b in enumerate(profile.get('binds') or [], 1):
        what = f'bind {i}'
        if not isinstance(b, dict):
            raise ValueError(f'{what} is not an object')
        keys, action = _keys(b.get('keys'), what), b.get('action')
        if action not in ACTIONS:
            raise ValueError(f'{what}: the action is one of {", ".join(ACTIONS)}')
        if keys.lower() in seen:
            raise ValueError(f'{what}: {keys} is bound twice')
        seen.add(keys.lower())
        arg = ''
        if ACTIONS[action]:
            arg = _text(b.get('arg'), f'{what}: what to {"run" if action == "spawn" else "switch to"}', COMMAND if action == 'spawn' else WORKSPACE)
        elif b.get('arg'):
            raise ValueError(f'{what}: {action} takes nothing')
        out['binds'].append({'keys': keys, 'action': action, 'arg': arg})
    for i, r in enumerate(profile.get('rules') or [], 1):
        what = f'rule {i}'
        if not isinstance(r, dict):
            raise ValueError(f'{what} is not an object')
        rule = {'app': _text(r.get('app'), f'{what}: the application', APP, empty=True), 'title': _text(r.get('title'), f'{what}: the title', TITLE, empty=True),
                'workspace': _text(r.get('workspace'), f'{what}: the workspace', WORKSPACE, empty=True)}
        for flag in ('floating', 'fullscreen'):
            if not isinstance(r.get(flag, False), bool):
                raise ValueError(f'{what}: {flag} is true or false')
            rule[flag] = r.get(flag, False)
        if not (rule['app'] or rule['title']):
            raise ValueError(f'{what} matches every window: name an application or a title')
        if not (rule['workspace'] or rule['floating'] or rule['fullscreen']):
            raise ValueError(f'{what} does nothing')
        out['rules'].append(rule)
    names = set()
    for i, d in enumerate(profile.get('displays') or [], 1):
        what = f'display {i}'
        if not isinstance(d, dict):
            raise ValueError(f'{what} is not an object')
        display = {'output': _text(d.get('output'), f'{what}: the output', OUTPUT), 'mode': _text(d.get('mode'), f'{what}: the mode', MODE, empty=True),
                   'position': _text(d.get('position'), f'{what}: the position', POSITION, empty=True), 'scale': _text(d.get('scale'), f'{what}: the scale', SCALE, empty=True),
                   'transform': d.get('transform') or 'normal', 'enabled': d.get('enabled', True)}
        if display['transform'] not in TRANSFORMS:
            raise ValueError(f'{what}: the transform is one of {", ".join(TRANSFORMS)}')
        if not isinstance(display['enabled'], bool):
            raise ValueError(f'{what}: enabled is true or false')
        if display['output'] in names:
            raise ValueError(f'{what}: {display["output"]} is there twice')
        names.add(display['output'])
        out['displays'].append(display)
    return out


def _match(value: str) -> str:
    """A name as a regular expression that matches it and nothing longer. A sign that means something in an expression is put
    in a class of its own, not behind a backslash: the two formats do not agree on what a backslash in a string is."""
    return '^' + ''.join(f'[{c}]' if c in '.()+|*?{}$' else c for c in value) + '$'


# ── niri (KDL) ───────────────────────────────────────────────────────
_NIRI = {'close': 'close-window', 'fullscreen': 'fullscreen-window', 'toggle-floating': 'toggle-window-floating', 'exit': 'quit',
         'focus-left': 'focus-column-left', 'focus-right': 'focus-column-right', 'focus-up': 'focus-window-up', 'focus-down': 'focus-window-down',
         'move-left': 'move-column-left', 'move-right': 'move-column-right', 'move-up': 'move-window-up', 'move-down': 'move-window-down'}


def _niri(p: dict) -> str:
    mods = {'mod': 'Mod', 'ctrl': 'Ctrl', 'alt': 'Alt', 'shift': 'Shift'}
    lines = [f'// {p["name"]}: written by StorageForge from the desktop profile. Change the profile, not this file.', '']
    if p['mod'] == 'alt':
        lines += ['input {', '    mod-key "Alt"', '}', '']
    if p['binds']:
        lines.append('binds {')
        for b in p['binds']:
            *m, key = b['keys'].split('+')
            combo = '+'.join([mods[x] for x in m] + [key])
            if b['action'] == 'spawn':
                act = 'spawn ' + ' '.join(f'"{w}"' for w in b['arg'].split(' '))
            elif b['action'] == 'workspace':
                act = f'focus-workspace {b["arg"]}'
            elif b['action'] == 'move-to-workspace':
                act = f'move-column-to-workspace {b["arg"]}'
            else:
                act = _NIRI[b['action']]
            lines.append(f'    {combo} {{ {act}; }}')
        lines += ['}', '']
    for r in p['rules']:
        match = ' '.join(f'{k}=r#"{_match(v)}"#' for k, v in (('app-id', r['app']), ('title', r['title'])) if v)
        lines.append('window-rule {')
        lines.append(f'    match {match}')
        if r['workspace']:
            lines.append(f'    open-on-workspace "{r["workspace"]}"')
        if r['floating']:
            lines.append('    open-floating true')
        if r['fullscreen']:
            lines.append('    open-fullscreen true')
        lines += ['}', '']
    for d in p['displays']:
        lines.append(f'output "{d["output"]}" {{')
        if not d['enabled']:
            lines.append('    off')
        else:
            if d['mode']:
                w, h, hz = MODE.fullmatch(d['mode']).groups()
                lines.append(f'    mode "{w}x{h}' + (f'@{float(hz):.3f}"' if hz else '"'))
            if d['scale']:
                lines.append(f'    scale {float(d["scale"])}')
            if d['transform'] != 'normal':
                lines.append(f'    transform "{d["transform"]}"')
            if d['position']:
                x, y = POSITION.fullmatch(d['position']).groups()
                lines.append(f'    position x={int(x)} y={int(y)}')
        lines += ['}', '']
    return '\n'.join(lines).rstrip('\n') + '\n'


# ── sway ────────────────────────────────────────────────────────────
_SWAY = {'close': 'kill', 'fullscreen': 'fullscreen toggle', 'toggle-floating': 'floating toggle', 'exit': 'exit',
         'focus-left': 'focus left', 'focus-right': 'focus right', 'focus-up': 'focus up', 'focus-down': 'focus down',
         'move-left': 'move left', 'move-right': 'move right', 'move-up': 'move up', 'move-down': 'move down'}


def _sway(p: dict) -> str:
    mods = {'mod': '$mod', 'ctrl': 'Ctrl', 'alt': 'Mod1', 'shift': 'Shift'}
    lines = [f'# {p["name"]}: written by StorageForge from the desktop profile. Change the profile, not this file.', '',
             f'set $mod {"Mod4" if p["mod"] == "super" else "Mod1"}', '']
    for b in p['binds']:
        *m, key = b['keys'].split('+')
        combo = '+'.join([mods[x] for x in m] + [key])
        if b['action'] == 'spawn':
            act = f'exec {b["arg"]}'
        elif b['action'] == 'workspace':
            act = f'workspace number {b["arg"]}'
        elif b['action'] == 'move-to-workspace':
            act = f'move container to workspace number {b["arg"]}'
        else:
            act = _SWAY[b['action']]
        lines.append(f'bindsym {combo} {act}')
    if p['binds']:
        lines.append('')
    for r in p['rules']:
        match = ' '.join(f'{k}="{_match(v)}"' for k, v in (('app_id', r['app']), ('title', r['title'])) if v)
        does = ([f'move container to workspace number {r["workspace"]}'] if r['workspace'] else []) + (['floating enable'] if r['floating'] else []) + (['fullscreen enable'] if r['fullscreen'] else [])
        lines.append(f'for_window [{match}] {", ".join(does)}')
    if p['rules']:
        lines.append('')
    for d in p['displays']:
        if not d['enabled']:
            lines.append(f'output {d["output"]} disable')
            continue
        words = [f'output {d["output"]}']
        if d['mode']:
            w, h, hz = MODE.fullmatch(d['mode']).groups()
            words.append(f'mode {w}x{h}' + (f'@{hz}Hz' if hz else ''))
        if d['position']:
            x, y = POSITION.fullmatch(d['position']).groups()
            words.append(f'position {int(x)} {int(y)}')
        if d['scale']:
            words.append(f'scale {d["scale"]}')
        if d['transform'] != 'normal':
            words.append(f'transform {d["transform"]}')
        if len(words) > 1:
            lines.append(' '.join(words))
    return '\n'.join(lines).rstrip('\n') + '\n'


def render(profile, compositor: str) -> str:
    """The profile as that compositor's configuration. The profile is checked again here: nothing is rendered unchecked."""
    if compositor not in COMPOSITORS:
        raise ValueError(f'the compositor is one of {", ".join(COMPOSITORS)}' + (': Hyprland is not rendered yet' if compositor == 'hyprland' else ''))
    return {'niri': _niri, 'sway': _sway}[compositor](normalize(profile))
