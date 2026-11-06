"""The UI kernel's rules (UX-10, UX-11 and UX-23 of the UI audit of 2026-11-04), read from the scripts as text, with no browser.

kernel.js is the one place that talks to the server and the one place that raises a dialog. These tests fail when a script reaches for
fetch() or a native confirm(), alert() or prompt() again, when a page forgets to load the kernel, or when the server would not serve a
file a page names (a page with a script that answers 404 stays blank, and nothing says why)."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / 'storageforge_index' / 'static'
SERVER = (ROOT / 'storageforge_index' / 'server.py').read_text()
PAGES = ['index.html', 'planner.html', 'manage.html', 'search.html']
SIGN_IN_PAGES = ['login.html', 'enroll.html']
# the scripts that may call fetch(): the kernel, the session guard that runs before it, and the two pages that have no session to lose
MAY_FETCH = {'kernel.js', 'session.js', 'login.js', 'enroll.js'}


def code(path):
    """A script without its comments, so that a sentence about confirm() is not taken for a call to it."""
    text = path.read_text()
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'(?m)^\s*//.*$|(?<=[;{}\s])//[^\n\'"`]*$', '', text)


def scripts():
    return sorted(STATIC.glob('*.js'))


class Kernel(unittest.TestCase):
    def test_the_scripts_are_found(self):
        self.assertGreaterEqual(len(scripts()), 20)
        self.assertIn(STATIC / 'kernel.js', scripts())

    def test_no_script_uses_a_native_dialog(self):                                   # UX-10
        found = []
        for path in scripts():
            for m in re.finditer(r'(?<![\w$.])(?:confirm|alert|prompt)\s*\(|\b(?:window|globalThis|self)\.(?:confirm|alert|prompt)\s*\(', code(path)):
                found.append(f'{path.name}: {m.group(0)}')
        self.assertEqual(found, [], 'use confirmDialog(), formDialog(), noticeDialog() or notify() from kernel.js')

    def test_only_the_kernel_and_the_session_guard_call_fetch(self):                  # UX-23
        found = {path.name for path in scripts() if re.search(r'\bfetch\s*\(|\bXMLHttpRequest\b|\bsendBeacon\b', code(path))}
        self.assertEqual(found - MAY_FETCH, set(), 'a page that makes its own call to the server skips the 401, the password dialog and the host key: use api()')
        self.assertIn('kernel.js', found)

    def test_no_page_defines_a_fetch_wrapper_of_its_own(self):                        # UX-23
        for path in scripts():
            if path.name in MAY_FETCH | {'manage.js', 'planner.js', 'search.js'}:       # the three below keep a one-line adapter, and that is tested next
                continue
            self.assertNotRegex(code(path), r'(?m)^(?:async function|function|const|let)\s+(?:api|getJSON|postJSON|apiJSON|call)\b', f'{path.name} should call the kernel')

    def test_the_wrappers_that_remain_only_adapt_the_kernel(self):                    # UX-23
        """/manage, the planner and the search page keep a one-line wrapper for the shape their views were written for; each must go through api()."""
        for name, wrapper in (('manage.js', 'call'), ('planner.js', 'apiJSON'), ('search.js', 'call')):
            text = code(STATIC / name)
            m = re.search(rf'(?:async )?function {wrapper}\b.*?\n\}}', text, re.S)
            self.assertIsNotNone(m, f'{name} has no {wrapper}()')
            self.assertIn('await api(', m.group(0), f'{name}: {wrapper}() does not go through api()')
            self.assertNotIn('fetch(', m.group(0))

    def test_no_global_shortcut_is_registered_outside_the_registry(self):             # UX-20, UX-40, UX-41
        """A key handler on the document that forgot to ask whether somebody is typing took a slash from a path and from a password. Each global
        one is declared with sfShortcut(), and the kernel's one listener asks. A widget's own keys, on its own element, are not global."""
        found = []
        for path in scripts():
            if path.name == 'kernel.js':
                continue
            for m in re.finditer(r"(?:document|window|document\.body|document\.documentElement)\.addEventListener\(\s*['\"](?:keydown|keyup|keypress)['\"]", code(path)):
                found.append(f'{path.name}: {m.group(0)}')
        self.assertEqual(found, [], 'declare it with sfShortcut()')
        self.assertEqual(len(re.findall(r"document\.addEventListener\(\s*'keydown'", code(STATIC / 'kernel.js'))), 1, 'one listener applies the rule')

    def test_times_and_sizes_have_one_formatter(self):                                # UX-16
        """Seven small time formatters showed a time three ways, UTC with no label in one panel and local in the next. A time is shown by
        fmtTime(), fmtDate(), fmtClock(), fmtAgo() or timeEl() from kernel.js, and a size by fmtBytes(). The date of today, for a name, is not a display."""
        found = []
        for path in scripts():
            if path.name == 'kernel.js':
                continue
            text = code(path)
            for m in re.finditer(r"new Date\((?!\))[^;\n]*?\)\.(?:toLocale\w*String|toISOString\(\)\.(?:slice|replace))", text):
                found.append(f'{path.name}: {m.group(0)[:70]}')
            if re.search(r'(?m)^\s*(?:function|const)\s+(?:fmtBytes|fmtTime|fmtDate|fmtAgo)\b', text):
                found.append(f'{path.name}: defines its own formatter')
        self.assertEqual(found, [], 'use the kernel\'s formatter')

    def test_the_kernel_builds_no_markup_from_text(self):
        """Dialog titles and bodies carry paths and host names that machines report: they are shown as text, never parsed."""
        self.assertNotRegex(code(STATIC / 'kernel.js'), r'innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function')

    def test_a_cut_list_is_a_component_of_the_kernel_and_builds_no_markup(self):        # UX-13
        """A list that shows the first rows says so with one button, sfMoreList(), not a line of text that cannot be opened. It is made with
        DOM calls and textContent only, and its button is a real <button> that says whether it is expanded."""
        kernel = code(STATIC / 'kernel.js')
        m = re.search(r'function sfMoreList\(.*?\n\}\n', kernel, re.S)
        self.assertIsNotNone(m, 'kernel.js has no sfMoreList()')
        body = m.group(0)
        self.assertNotRegex(body, r'innerHTML|outerHTML|insertAdjacentHTML|document\.write')
        for needle in ("'button'", "type: 'button'", 'sf-btn ghost', 'aria-expanded', 'aria-controls', 'announce(', 'Show fewer', 'Show ${hidden} more', 'limit = 12'):
            self.assertIn(needle, body, f'sfMoreList() lacks {needle}')
        self.assertIn('.sf-more', (STATIC / 'components.css').read_text())

    def test_every_page_loads_what_the_kernel_needs_in_order(self):
        for page in PAGES:
            html = (STATIC / page).read_text()
            tags = re.findall(r'<(?:script src|link rel="stylesheet" href)="(/[^"]+)"', html)
            self.assertLess(tags.index('/session.js'), tags.index('/kernel.js'), f'{page}: the kernel comes after the session guard')
            for later in tags[tags.index('/kernel.js') + 1:]:
                self.assertNotEqual(later, '/session.js', page)
            scripts_ = [t for t in tags if t.endswith('.js')]
            self.assertEqual(scripts_.index('/kernel.js'), scripts_.index('/session.js') + 1, f'{page}: the kernel is the script after session.js')
            self.assertEqual(scripts_.index('/chrome.js'), scripts_.index('/kernel.js') + 1, f'{page}: the shared chrome is the script after the kernel')
            sheets = [t for t in tags if t.endswith('.css')]
            self.assertEqual(sheets[:2], ['/tokens.css', '/components.css'], f'{page}: tokens, then components, then the page\'s own sheet')
            self.assertEqual(len(sheets), 3, page)

    def test_the_sign_in_pages_take_their_colours_from_the_tokens(self):
        for page in SIGN_IN_PAGES:
            sheets = re.findall(r'<link rel="stylesheet" href="(/[^"]+)"', (STATIC / page).read_text())
            self.assertEqual(sheets, ['/tokens.css', '/style.css'], page)

    def test_the_palette_is_registered_like_any_shortcut_and_builds_no_markup(self):      # phase 5
        """Ctrl+K is declared with sfShortcut() (so the one listener and the help know it), is a native <dialog> through sfModal(), exposes the
        combobox and listbox roles, and sets every label as text."""
        kernel = code(STATIC / 'kernel.js')
        self.assertRegex(kernel, r"sfShortcut\(\{ id: 'palette', key: 'k', mods: 'mod'")
        m = re.search(r'function sfPalette\(.*?\n\}\n', kernel, re.S)
        self.assertIsNotNone(m)
        body = m.group(0)
        for needle in ("role: 'combobox'", "role: 'listbox'", "role: 'option'", 'aria-activedescendant', 'sfModal(', "'ArrowDown'", "'Enter'", 'aria-selected'):
            self.assertIn(needle, body, f'sfPalette() lacks {needle}')
        self.assertNotRegex(body, r'innerHTML|outerHTML|insertAdjacentHTML')
        self.assertIn('sfShortcuts()', kernel[kernel.index('function sfShortcutHelp'):], 'the help is generated from the registry')

    def test_preferences_are_kept_per_user_in_the_browser_and_never_sent_to_the_server(self):      # phase 5
        kernel, chrome = code(STATIC / 'kernel.js'), code(STATIC / 'chrome.js')
        body = re.search(r'function sfPrefsSave\(.*?\n\}\n', kernel, re.S).group(0)
        self.assertIn('sfStash(', body)
        self.assertNotRegex(body + chrome[chrome.index('async function sfPreferences'):], r'api\(|postJSON|getJSON|fetch\(')
        self.assertIn("sfPrefKey = (user) => `sf.prefs.${user}`", kernel)
        self.assertRegex((STATIC / 'tokens.css').read_text(), r':root\[data-density="compact"\]')

    def test_a_dot_is_never_only_a_colour(self):                                          # phase 5, colour never alone
        css = (STATIC / 'style.css').read_text()
        for health in ('local-only', 'broken', 'unknown'):
            self.assertRegex(css, rf'\.dot\.{health}[^{{]*\{{[^}}]*(?:clip-path|box-shadow)', f'.dot.{health} has no shape of its own')

    def test_the_server_serves_every_file_a_page_names(self):
        served = set(re.findall(r'"([\w.-]+\.(?:js|css|svg))"', ' '.join(re.findall(r'@web\.get\(\'/<any\(([^)]*)\):name>\'\)', SERVER))))
        for page in PAGES + SIGN_IN_PAGES:
            for path in re.findall(r'<(?:script src|link rel="stylesheet" href)="/([^"]+)"', (STATIC / page).read_text()):
                self.assertTrue((STATIC / path).exists(), f'{page} names {path}, which is not there')
                self.assertIn(path, served, f'{page} names {path}, which server.py does not serve: the page would load without it')

    def test_the_tokens_and_components_are_public_because_the_sign_in_page_uses_them(self):
        m = re.search(r'@web\.get\(\'/<any\(([^)]*)\):name>\'\)\s*\n\s*def public_static', SERVER)
        self.assertIsNotNone(m)
        for name in ('tokens.css', 'style.css', 'login.js'):
            self.assertIn(f'"{name}"', m.group(1))
        self.assertNotIn('"kernel.js"', m.group(1), 'the kernel only goes to a signed-in page')


if __name__ == '__main__':
    unittest.main()
