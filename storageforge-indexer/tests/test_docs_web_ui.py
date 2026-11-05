"""docs/web-ui.md names every view and every panel the main page has, and the counts it gives are true (UX-39 of the UI audit of 2026-11-04:
it said three views and no row for Infra, Malware, Security or Logs, when the page had five views and eighteen panels).

The page is read as text, with no browser: index.html says what exists, the Markdown says what is documented."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HTML = (ROOT / 'storageforge-indexer' / 'storageforge_index' / 'static' / 'index.html').read_text()
DOC = (ROOT / 'docs' / 'web-ui.md').read_text()
WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten']


def views():
    group = re.search(r'<div id="viewmode"[^>]*>(.*?)</div>', HTML, re.S).group(1)
    return re.findall(r'data-mode="\w+"[^>]*>([^<]+)</button>', group)


def panels():
    """(group, label) for every rail button, in order."""
    out, group = [], None
    for m in re.finditer(r'<span class="rgroup"[^>]*>([^<]+)</span>|<button[^>]*role="tab" data-tab="\w+".*?</svg><span[^>]*>([^<]+)</span>', HTML, re.S):
        if m.group(1):
            group = m.group(1)
        else:
            out.append((group, m.group(2)))
    return out


class WebUiPage(unittest.TestCase):
    def test_the_page_finds_what_it_checks(self):
        """A changed markup must not make the tests below pass by finding nothing."""
        self.assertGreaterEqual(len(views()), 5)
        self.assertGreaterEqual(len(panels()), 18)

    def test_every_view_is_named_and_the_count_is_true(self):
        for label in views():
            self.assertIn(f'**{label}**', DOC, f'the {label} view is not named')
            self.assertRegex(DOC, rf'(?m)^## {re.escape(label)}$', f'the {label} view has no section')
        self.assertIn(f'{WORDS[len(views())]} views in the header', DOC)

    def test_every_panel_has_a_row_in_its_group_and_the_count_is_true(self):
        rows = {}
        for group, label in panels():
            rows.setdefault(group, []).append(label)
        for group, labels in rows.items():
            section = re.search(rf'(?ms)^### {re.escape(group)}\n(.*?)(?=^##)', DOC)
            self.assertIsNotNone(section, f'no "### {group}" heading')
            for label in labels:
                self.assertIn(f'| **{label}** |', section.group(1), f'{label} has no row under {group}')
        self.assertIn(f'a rail of {len(panels())} panels', DOC)
        self.assertIn(f'{len(panels())} of them in {WORDS[len(rows)]} groups', DOC)

    def test_the_other_pages_the_header_links_to_are_described(self):
        for href in re.findall(r'<a id="to\w+" class="btn" href="(/\w+)"', HTML):
            self.assertIn(f'| `{href}` |', DOC, f'{href} is linked from the header and not described')


if __name__ == '__main__':
    unittest.main()
