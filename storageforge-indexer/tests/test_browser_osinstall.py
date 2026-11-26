"""Rebuild → a second system beside the first, and desktop profiles, in a real browser (roadmap section 7, phases 8 and 9): the
form becomes change plans, a system that is there is started or removed through a plan, a cancelled question changes nothing on
the page, and a profile is made, shown as a compositor would get it, saved, edited and deleted. Needs playwright and its chromium."""
import json
import tempfile
import threading
import unittest

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

from storageforge_index import changes, desktop, server, users
from storageforge_index.db import Database
from test_osoffer import KEY, NAS

PW = 'correct horse battery staple'
FOCUS = "() => { const a = document.activeElement; return a ? (a.id || a.getAttribute('aria-label') || a.textContent) : '' }"


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserOsInstall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        users.create(conn, 'viewer', PW, 'viewer')
        for name, inv in (('nas', NAS), ('pi', {})):
            conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ip_address, ssh_user, os_info, inventory_json, last_scanned_at)
                             VALUES (:h, :h, '10.0.0.9', 'scan', 'Debian 13', :i, {cls.db.ts(':t')})""", {'h': name, 'i': json.dumps(inv), 't': 1700000000})
        conn.close()
        cls.http = make_server('127.0.0.1', 0, server.create_app(server.App(cls.db), 's' * 48), threaded=True)
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()
        cls.base = f'http://127.0.0.1:{cls.http.server_port}'
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.http.shutdown()
        cls.tmp.cleanup()

    def setUp(self):
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.conn.execute('DELETE FROM change_plans')
        self.conn.execute(f"DELETE FROM settings WHERE key = '{desktop.KEY_SETTING}'")
        self.errors = []

    def tearDown(self):
        self.assertEqual(self.errors, [], 'no script error and nothing the content security policy refused')

    def sign_in(self, who='admin'):
        self.page = self.browser.new_page()
        self.addCleanup(self.page.close)
        self.page.set_default_timeout(30000)
        self.page.on('pageerror', lambda e: self.errors.append(e.stack or str(e)))      # the stack names the line when CI catches one
        self.page.on('console', lambda m: self.errors.append(m.text) if 'Content Security Policy' in m.text else None)
        self.page.goto(self.base + '/login')
        self.page.fill('input[type=text], input[name=username], #username', who)
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_url(self.base + '/**')
        self.page.wait_for_selector('.tabs button')
        self.page.wait_for_selector('html[data-route-ready]', state='attached')
        self.page.click('#tabbtn-rebuild')
        self.page.click('#rebuild-sub-os2')
        self.page.wait_for_selector('#os2-form')
        self.page.click('#rebuild-sub-desk')
        self.page.wait_for_selector('#desk-list')
        self.page.click('#rebuild-sub-os2')

    def plans(self):
        return {p['name']: changes.get_plan(self.conn, p['id']) for p in changes.list_plans(self.conn)}

    def message(self, box='#os2msg'):
        self.page.wait_for_selector(f'{box}:not([hidden])')
        return self.page.inner_text(box)

    def test_the_form_offers_what_the_scan_saw_and_becomes_a_plan(self):
        self.sign_in()
        page = self.page
        self.assertEqual(page.locator('#os2-host option').all_inner_texts(), ['nas · Debian 13', 'pi · Debian 13'])
        disks = page.locator('#os2-disk option').all_inner_texts()
        self.assertEqual([d.split(' · ')[0] for d in disks], ['/dev/nvme0n1', '/dev/sda', '/dev/sde'])
        self.assertIn('unpartitioned · this system runs from it', disks[0])
        self.assertIn('blank disk', disks[1])
        notes = page.inner_text('#os2-notdisks')
        for why in ('/dev/sdb', 'the whole disk holds ZFS', 'its partition table is dos, not GPT', 'under 3 GiB of unpartitioned space, and nothing is shrunk'):
            self.assertIn(why, notes)
        self.assertIn('started by UEFI', page.inner_text('#os2-facts'))
        self.assertEqual(page.input_value('#os2-user'), 'scan', 'the account scans log in with')
        labels = page.locator('#os2-image option').all_inner_texts()
        for name in ('Fedora 44', 'Rocky Linux 10', 'AlmaLinux 10', 'Debian 13', 'Ubuntu 24.04', 'openSUSE Leap 16'):
            self.assertIn(name, labels)
        page.select_option('#os2-image', 'fedora44')
        self.assertIn('checked on the host against https://download.fedoraproject.org/', page.inner_text('#os2-imageinfo'))
        self.assertTrue(page.is_hidden('#os2-custom'))
        page.select_option('#os2-image', 'custom')
        self.assertTrue(page.is_visible('#os2-url'))
        page.select_option('#os2-image', 'fedora44')

        page.fill('#os2-name', 'nas-fedora')
        page.select_option('#os2-disk', '/dev/sda')
        page.fill('#os2-key', KEY)
        page.click('#os2-make')
        self.assertIn('type /dev/sda again to confirm the disk', self.message(), 'the disk has to be typed, as in any plan that writes to one')
        self.assertEqual(self.plans(), {})
        self.assertEqual((page.input_value('#os2-name'), page.input_value('#os2-key')), ('nas-fedora', KEY), 'a refusal leaves the form as it was typed')
        page.fill('#os2-confirm', '/dev/sda')
        page.fill('#os2-size', '40')
        page.select_option('#os2-network', 'fixed')
        page.select_option('#os2-start', 'once')
        page.click('#os2-make')
        page.wait_for_selector('#os2msg.st-ok')
        self.assertIn('Plan “nas: install nas-fedora”', self.message())
        self.assertIn('Nothing has run yet', self.message())
        tasks = self.plans()['nas: install nas-fedora']['tasks']
        self.assertEqual([t['type'] for t in tasks], ['os-install', 'os-boot'])
        p = tasks[0]['params']
        self.assertEqual((p['name'], p['image'], p['disk'], p['size_gb'], p['user'], p['ssh_key'], p['network'], p['host_keys'], p['carry']),
                         ('nas-fedora', 'fedora44', '/dev/sda', '40', 'scan', KEY, 'fixed', 'same', 'mount'))
        self.assertEqual(tasks[1]['params'], {'name': 'nas-fedora', 'when': 'once', 'restart': 'no'})
        # the panel opened again keeps what was typed
        page.click('#tabbtn-changes')
        page.click('#tabbtn-rebuild')
        page.click('#rebuild-sub-os2')
        page.wait_for_selector('#os2-form')
        self.assertEqual((page.input_value('#os2-name'), page.input_value('#os2-disk'), page.input_value('#os2-confirm')), ('nas-fedora', '/dev/sda', '/dev/sda'))
        page.click('#os2msg button:has-text("Open Changes")')
        page.wait_for_selector('#tab-changes:not([hidden])')

    def test_a_host_with_no_scan_of_its_disks_says_so(self):
        self.sign_in()
        self.page.select_option('#os2-host', 'pi')
        self.assertIn('pi has no scan with its disks in it', self.page.inner_text('#os2-facts'))
        self.assertEqual(self.page.locator('#os2-disk option').all_inner_texts(), ['This host has not been scanned'])
        self.assertIn('None that the last scan saw', self.page.inner_text('#os2-systems'))

    def test_a_desktop_is_a_second_plan(self):
        desktop.save(self.conn, {'name': 'fleet', 'binds': [{'keys': 'mod+Return', 'action': 'spawn', 'arg': 'ghostty'}]}, 'gabe')
        self.sign_in()
        page = self.page
        page.fill('#os2-name', 'nas-rocky')
        page.select_option('#os2-image', 'rocky10')
        page.select_option('#os2-disk', '/dev/sda')
        page.fill('#os2-confirm', '/dev/sda')
        page.fill('#os2-key', KEY)
        self.assertTrue(page.is_hidden('#os2-duxpart'))
        page.check('#os2-dux')
        page.select_option('#os2-compositor', 'hyprland')
        self.assertEqual(page.input_value('#os2-profcomp'), 'hyprland', 'the profile is written for the compositor Dux installs')
        page.fill('#os2-duxver', 'v2.1.2')
        page.fill('#os2-duxsha', 'a' * 64)
        self.assertEqual(page.locator('#os2-profile option').all_inner_texts(), ['No profile', 'fleet'])
        page.select_option('#os2-profile', 'fleet')
        page.click('#os2-make')
        page.wait_for_selector('#os2msg.st-ok')
        self.assertIn('Plans “nas: install nas-rocky”', self.message())
        self.assertIn('“nas: desktop on nas-rocky”', self.message())
        plans = self.plans()
        self.assertEqual([t['type'] for t in plans['nas: install nas-rocky']['tasks']], ['os-install'])
        after = plans['nas: desktop on nas-rocky']['tasks']
        self.assertEqual([t['type'] for t in after], ['os-running', 'dux-install', 'desktop-profile'])
        self.assertEqual((after[1]['params']['compositor'], after[1]['params']['user'], after[2]['params']), ('hyprland', 'scan', {'profile': 'fleet', 'user': 'scan', 'compositor': 'hyprland'}))

    def test_a_system_that_is_there_is_started_or_removed_by_a_plan_and_a_cancelled_question_changes_nothing(self):
        self.sign_in()
        page = self.page
        row = page.locator('#os2-systems li[data-system="nas-fedora"]')
        self.assertIn('/dev/sde · 3 partitions', row.inner_text())
        page.fill('#os2-name', 'typed-before')
        page.evaluate("() => { document.querySelector('#os2-systems li').dataset.mark = 'same'; }")
        row.locator('button:has-text("Remove")').click()
        dialog = page.locator('dialog[open]')
        self.assertIn('deletes the 3 partitions of nas-fedora on /dev/sde', dialog.inner_text())
        self.assertTrue(dialog.locator('button[type=submit]').is_disabled(), 'the name is typed first')
        dialog.locator('button:has-text("Cancel")').click()
        page.wait_for_selector('dialog[open]', state='detached')
        self.assertEqual(page.evaluate(FOCUS), 'Remove', 'focus is back on the button that asked')
        self.assertEqual(page.get_attribute('#os2-systems li', 'data-mark'), 'same', 'the list was not drawn again')
        self.assertEqual(page.input_value('#os2-name'), 'typed-before')
        self.assertTrue(page.is_hidden('#os2msg'))
        self.assertEqual(self.plans(), {})
        # Escape is a cancel too
        row.locator('button:has-text("Start once and restart")').click()
        self.assertIn('restarts nas one minute later', page.locator('dialog[open]').inner_text())
        page.keyboard.press('Escape')
        page.wait_for_selector('dialog[open]', state='detached')
        self.assertEqual(page.evaluate(FOCUS), 'Start once and restart')
        self.assertEqual(self.plans(), {})

        row.locator('button:has-text("Start once")').first.click()
        page.locator('dialog[open] button[type=submit]').click()
        page.wait_for_selector('#os2msg.st-ok')
        self.assertIn('“nas: start nas-fedora once”', self.message())
        self.assertEqual(page.get_attribute('#os2-systems li', 'data-mark'), 'same', 'and a plan that was saved changes nothing on a host, so nothing here either')
        row.locator('button:has-text("Remove")').click()
        page.locator('dialog[open] input[type=text]').fill('nas-fedora')
        page.locator('dialog[open] button[type=submit]').click()
        page.wait_for_function("() => document.querySelector('#os2msg').textContent.includes('remove nas-fedora')")
        got = {n: [(t['type'], t['params']) for t in p['tasks']] for n, p in self.plans().items()}
        self.assertEqual(got, {'nas: start nas-fedora once': [('os-boot', {'name': 'nas-fedora', 'when': 'once', 'restart': 'no'})],
                               'nas: remove nas-fedora': [('os-remove', {'name': 'nas-fedora'})]})

    def test_a_profile_is_made_shown_saved_edited_and_deleted(self):
        self.sign_in()
        page = self.page
        page.click('#rebuild-sub-desk')
        self.assertIn('No profiles yet', page.inner_text('#desk-list'))
        page.click('#desk-new')
        page.wait_for_selector('#desk-editor')
        self.assertEqual(page.evaluate(FOCUS), 'desk-name')
        page.fill('#desk-name', 'fleet')
        page.click('#desk-binds button:has-text("Add a key")')
        self.assertEqual(page.evaluate(FOCUS), 'Keys of key 1', 'focus is in the row that was added')
        page.fill('[aria-label="Keys of key 1"]', 'mod+Return')
        page.fill('[aria-label="Command of key 1"]', 'ghostty')
        page.click('#desk-binds button:has-text("Add a key")')
        page.fill('[aria-label="Keys of key 2"]', 'mod+q')
        page.select_option('[aria-label="What key 2 does"]', 'close')
        self.assertEqual(page.locator('[aria-label="Command of key 2"]').count(), 0, 'closing a window takes nothing')
        self.assertEqual(page.evaluate(FOCUS), 'What key 2 does')
        self.assertEqual(page.input_value('[aria-label="Keys of key 1"]'), 'mod+Return', 'the other rows keep what was typed')
        page.click('#desk-rules button:has-text("Add a window rule")')
        page.fill('[aria-label="Application of rule 1"]', 'firefox')
        page.fill('[aria-label="Workspace of rule 1"]', '2')
        page.click('#desk-displays button:has-text("Add a display")')
        page.fill('[aria-label="Output of display 1 for every host"]', 'DP-1')
        page.fill('[aria-label="Mode of display 1 for every host"]', '2560x1440@144')
        # one host has a screen of its own
        page.select_option('#desk-addhost', 'pi')
        page.click('button:has-text("Give this host displays of its own")')
        self.assertEqual(page.input_value('#desk-layout'), 'pi')
        page.click('#desk-displays button:has-text("Add a display")')
        page.fill('[aria-label="Output of display 1 on pi"]', 'eDP-1')
        page.fill('[aria-label="Scale of display 1 on pi"]', '1.5')

        page.select_option('#desk-comp', 'sway')
        page.click('button:has-text("Show the text")')
        page.wait_for_selector('#desk-preview:not([hidden])')
        shown = page.inner_text('#desk-preview')
        for line in ('bindsym $mod+Return exec ghostty', 'bindsym $mod+q kill', 'output DP-1 mode 2560x1440@144Hz'):
            self.assertIn(line, shown)
        self.assertNotIn('eDP-1', shown)
        page.select_option('#desk-comp', 'niri')
        page.select_option('#desk-prevhost', 'pi')
        page.click('button:has-text("Show the text")')
        page.wait_for_function("() => document.querySelector('#desk-preview').textContent.includes('eDP-1')")
        self.assertNotIn('DP-1"', page.inner_text('#desk-preview').replace('eDP-1"', ''), 'on pi its own displays are used in place of the others')
        self.assertEqual(desktop.profiles(self.conn), {}, 'showing it saved nothing')
        # what the server refuses is said, and the form stays
        page.fill('[aria-label="Command of key 1"]', 'sh -c "rm"')
        page.click('#desk-save')
        self.assertIn('is not valid', self.message('#deskmsg'))
        self.assertTrue(page.is_visible('#desk-editor'))
        page.fill('[aria-label="Command of key 1"]', 'ghostty')
        page.click('#desk-save')
        page.wait_for_selector('#desk-list li[data-profile="fleet"]')
        self.assertIn('Profile fleet saved', self.message('#deskmsg'))
        self.assertIn('2 keys · 1 window rule · 1 display · own displays for pi', page.inner_text('#desk-list'))
        saved = desktop.get(self.conn, 'fleet')
        self.assertEqual(saved['binds'], [{'keys': 'mod+Return', 'action': 'spawn', 'arg': 'ghostty'}, {'keys': 'mod+q', 'action': 'close', 'arg': ''}])
        self.assertEqual(saved['rules'], [{'app': 'firefox', 'title': '', 'workspace': '2', 'floating': False, 'fullscreen': False}])
        self.assertEqual((saved['displays'][0]['output'], saved['hosts']['pi'][0]['scale']), ('DP-1', '1.5'))
        page.click('#rebuild-sub-os2')
        self.assertEqual(page.locator('#os2-profile option').all_inner_texts(), ['No profile', 'fleet'], 'and the form above offers it')
        page.click('#rebuild-sub-desk')

        page.click('[aria-label="Edit the profile fleet"]')
        page.wait_for_selector('#desk-editor')
        self.assertEqual(page.get_attribute('#desk-name', 'readonly'), '', 'a profile keeps its name')
        self.assertEqual(page.input_value('[aria-label="Keys of key 2"]'), 'mod+q')
        page.click('[aria-label="Remove key 2"]')
        self.assertEqual(page.evaluate(FOCUS), 'Add a key', 'focus goes to the button beside the list, not to the top of the page')
        page.click('#desk-save')
        page.wait_for_function("() => document.querySelector('#desk-list')?.textContent.includes('1 key ·')")
        self.assertEqual(len(desktop.get(self.conn, 'fleet')['binds']), 1)

        page.evaluate("() => { document.querySelector('#desk-list').dataset.mark = 'same'; }")
        page.click('[aria-label="Delete the profile fleet"]')
        page.locator('dialog[open] button:has-text("Cancel")').click()
        page.wait_for_selector('dialog[open]', state='detached')
        self.assertEqual(page.evaluate(FOCUS), 'Delete the profile fleet')
        self.assertEqual(page.get_attribute('#desk-list', 'data-mark'), 'same', 'a cancelled delete draws nothing again')
        self.assertIn('fleet', desktop.profiles(self.conn))
        page.click('[aria-label="Delete the profile fleet"]')
        page.locator('dialog[open] button[type=submit]').click()
        page.wait_for_function("() => document.querySelector('#desk-list')?.textContent.includes('No profiles yet')")
        self.assertEqual(desktop.profiles(self.conn), {})
        self.assertEqual(page.evaluate(FOCUS), 'desk-new')

    def test_an_account_that_may_only_read_sees_no_button_that_would_be_refused(self):
        desktop.save(self.conn, {'name': 'fleet', 'binds': [{'keys': 'mod+q', 'action': 'close'}]}, 'gabe')
        self.sign_in('viewer')
        page = self.page
        self.assertEqual(page.locator('#os2-make').count(), 0)
        self.assertEqual(page.locator('#os2-systems button').count(), 0)
        self.assertIn('nas-fedora', page.inner_text('#os2-systems'))
        page.click('#rebuild-sub-desk')
        self.assertEqual(page.locator('#desk-new').count(), 0)
        self.assertEqual(page.locator('[aria-label="Delete the profile fleet"]').count(), 0)
        page.click('[aria-label="Open the profile fleet"]')
        page.wait_for_selector('#desk-editor')
        self.assertEqual(page.locator('#desk-save').count(), 0)
        page.click('button:has-text("Show the text")')
        page.wait_for_selector('#desk-preview:not([hidden])')
        self.assertIn('close-window', page.inner_text('#desk-preview'), 'reading what a host would get is reading')

    def test_every_control_has_a_name_and_the_parts_have_headings(self):
        self.sign_in()
        page = self.page
        page.click('#rebuild-sub-desk')
        page.click('#desk-new')
        for add in ('Add a key', 'Add a window rule', 'Add a display'):
            page.click(f'#desk-editor button:has-text("{add}")')
        unnamed = page.evaluate("""() => [...document.querySelectorAll('#os2 input, #os2 select, #os2 button, #desk input, #desk select, #desk button')]
            .filter((e) => !(e.getAttribute('aria-label') || e.closest('label')?.textContent.trim() || e.textContent.trim()))
            .map((e) => e.outerHTML.slice(0, 120))""")
        self.assertEqual(unnamed, [])
        self.assertEqual(page.get_attribute('#os2', 'aria-labelledby'), 'os2head')
        self.assertEqual(page.get_attribute('#os2msg', 'role'), 'status')
        self.assertEqual(page.get_attribute('#deskmsg', 'role'), 'status')


if __name__ == '__main__':
    unittest.main()
