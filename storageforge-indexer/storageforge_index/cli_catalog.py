"""Describe the installed CLI for the web command builder without reading controller settings."""
import argparse
from functools import lru_cache

GROUPS = {
    'Discovery and files': 'scan search changes dupes folders copies archive hosts export-markdown report graph canvas',
    'Planning and transfers': 'moves tasks shares plan deploy blueprint clone schedule',
    'Infrastructure': 'docker git vm sfnet site remote',
    'Security and access': 'clamav access rotate vault user audit',
    'Monitoring': 'log hostlogs healthcheck',
    'Controller maintenance': 'backup config restore reset prune migrate serve',
}


@lru_cache(maxsize=1)
def catalog():
    from .cli import build_parser
    root = build_parser()
    commands = []

    def visit(parser, path, inherited):
        fields = []
        children = {}
        can_run = True
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                children = action.choices
                can_run = not action.required
            elif action.dest not in ('help', 'version') and action.help != argparse.SUPPRESS:
                fields.append(dict(name=action.dest, flag=next((s for s in action.option_strings if s.startswith('--')), ''),
                                   numeric=action.type in (int, float), integer=action.type is int,
                                   required=action.required, repeat=isinstance(action, argparse._AppendAction),
                                   toggle=action.nargs == 0, choices=list(action.choices or ()), help=action.help or ''))
        levels = [*inherited, fields]
        if can_run:
            group = next((g for g, names in GROUPS.items() if path[0] in names.split()), 'Other')
            commands.append(dict(path=path, group=group, levels=levels, help=parser.format_help()))
        for name, child in children.items():
            visit(child, [*path, name], levels)

    visit(root, [], [])
    return commands
