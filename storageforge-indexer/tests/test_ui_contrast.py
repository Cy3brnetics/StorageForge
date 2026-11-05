"""The UI's text colours keep their contrast (UX-19 of the UI audit of 2026-11-04).

Every text token against the surfaces it sits on, in both themes, at WCAG AA for small text: 4.5 to 1. The rail's group
labels are 10 px and not faded, because 8.5 px at 70% opacity read as 3.1 to 1. A colour that only marks something (a dot,
a bar) needs 3 to 1 and is not in this table. The stylesheets are read as text: no browser needed."""
import re
import unittest
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / 'storageforge_index' / 'static'
AA = 4.5


def channel(v):
    v /= 255
    return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4


def luminance(hex_):
    r, g, b = (int(hex_.lstrip('#')[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def ratio(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def block(css, opener):
    """The text between the braces of the rule that starts with `opener`."""
    start = css.index('{', css.index(opener))
    depth = 0
    for i in range(start, len(css)):
        depth += css[i] == '{'
        depth -= css[i] == '}'
        if depth == 0:
            return css[start + 1:i]
    raise ValueError(opener)


def tokens(text):
    out = {}
    for name, value in re.findall(r'--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,6})\b', text):
        if len(value) == 4:                       # #fff is #ffffff
            value = '#' + ''.join(c * 2 for c in value[1:])
        if len(value) == 7:
            out[name] = value
    return out


def themes(name):
    """(dark, light) tokens of a stylesheet: the light theme is the dark one with its own values over it."""
    css = (STATIC / name).read_text()
    dark = tokens(block(css, ':root'))
    if name == 'planner.css':
        light = dict(dark, **tokens(block(css, ':root:not([data-theme="dark"])')))
    else:
        light = dict(dark, **tokens(block(block(css, '@media (prefers-color-scheme: light)'), ':root')))
    return {'dark': dark, 'light': light}


# each stylesheet: the text tokens, and the surfaces they are drawn on
TEXT = {
    'style.css': ([('fg', ['bg', 'panel', 'panel-2']), ('muted', ['bg', 'panel', 'panel-2']), ('accent', ['panel']), ('accent-ink', ['accent']),
                   ('protected', ['panel']), ('local-only', ['panel']), ('broken', ['panel'])]),
    'planner.css': ([('fg', ['bg', 'panel', 'panel-2']), ('muted', ['bg', 'panel', 'panel-2']), ('faint', ['bg', 'panel', 'panel-2']), ('accent', ['panel']),
                     ('accent-ink', ['accent']), ('ok', ['panel']), ('warn', ['panel']), ('crit', ['panel']), ('info', ['panel'])]),
    'manage.css': ([('text', ['bg', 'panel', 'panel-2']), ('muted', ['bg', 'panel', 'panel-2']), ('pri', ['panel']), ('pri-ink', ['pri']),
                    ('bad', ['bg', 'panel']), ('warn', ['bg', 'panel']), ('ok', ['bg', 'panel'])]),
}


class TextContrast(unittest.TestCase):
    def test_every_text_token_clears_aa_on_the_surfaces_it_sits_on(self):
        failures = []
        for sheet, pairs in TEXT.items():
            for theme, tok in themes(sheet).items():
                for fg, surfaces in pairs:
                    for surface in surfaces:
                        r = ratio(tok[fg], tok[surface])
                        if r < AA:
                            failures.append(f'{sheet} {theme}: --{fg} {tok[fg]} on --{surface} {tok[surface]} is {r:.2f}')
        self.assertEqual(failures, [], '\n' + '\n'.join(failures))

    def test_the_stylesheets_define_the_tokens_this_test_reads(self):
        """A renamed token must not make the test above pass by finding nothing."""
        for sheet, pairs in TEXT.items():
            for theme, tok in themes(sheet).items():
                for fg, surfaces in pairs:
                    for name in [fg, *surfaces]:
                        self.assertIn(name, tok, f'{sheet} {theme} has no --{name}')

    def test_the_access_badge_is_dark_on_amber_in_both_themes(self):
        css = (STATIC / 'style.css').read_text()
        m = re.search(r'#naccess\s*\{\s*background:\s*(#[0-9a-fA-F]{6});\s*color:\s*(#[0-9a-fA-F]{6})', css)
        self.assertIsNotNone(m, 'the badge colours are fixed hex values, the same in both themes')
        self.assertGreaterEqual(ratio(m.group(1), m.group(2)), AA)

    def test_the_security_banner_chips_clear_aa_in_both_themes(self):          # UX-09
        """The header's security chip: white on a fixed red or amber for the two states that need a look, and the theme's own green when
        nothing is wrong. It was a fixed light green (#6c6), which is 2.0 to 1 on the light theme's white panel."""
        css = (STATIC / 'style.css').read_text()
        full = lambda h: '#' + ''.join(c * 2 for c in h[1:]) if len(h) == 4 else h          # #fff is #ffffff
        for state in ('critical', 'warning'):
            rule = block(css, f'.threat.sec-{state} ')
            bg, fg = (full(re.search(rf'{prop}:\s*(#[0-9a-fA-F]{{3,6}})\b', rule).group(1)) for prop in ('background', r'(?<!-)color'))
            self.assertGreaterEqual(ratio(bg, fg), AA, state)
        self.assertRegex(block(css, '.threat.sec-secure '), r'color:\s*var\(--protected\)')     # the token the test above holds, in both themes

    def test_the_rail_group_labels_are_readable(self):
        rule = block((STATIC / 'style.css').read_text(), '.rgroup {')
        self.assertNotIn('opacity', rule, 'the labels were faded to 70%, which is what failed')
        size = float(re.search(r'font-size:\s*([0-9.]+)px', rule).group(1))
        self.assertGreaterEqual(size, 10)


if __name__ == '__main__':
    unittest.main()
