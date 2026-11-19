"""The desktop profile (desktop.py): one description of keys, window rules and displays, rendered for the compositor a machine
runs. What must hold: nothing in a profile can close a string or a block in a configuration file and start a line of its own;
a profile says the same thing in each format; and what is rendered for niri is a configuration niri itself accepts."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import desktop

PROFILE = {'name': 'fleet', 'mod': 'super',
           'binds': [{'keys': 'mod+Return', 'action': 'spawn', 'arg': 'ghostty'}, {'keys': 'mod+d', 'action': 'spawn', 'arg': 'dms ipc call spotlight toggle'}, {'keys': 'mod+q', 'action': 'close'},
                     {'keys': 'mod+f', 'action': 'fullscreen'}, {'keys': 'mod+v', 'action': 'toggle-floating'}, {'keys': 'mod+Left', 'action': 'focus-left'}, {'keys': 'mod+Right', 'action': 'focus-right'},
                     {'keys': 'mod+Up', 'action': 'focus-up'}, {'keys': 'mod+Down', 'action': 'focus-down'}, {'keys': 'mod+shift+Left', 'action': 'move-left'}, {'keys': 'mod+shift+Right', 'action': 'move-right'},
                     {'keys': 'mod+shift+Up', 'action': 'move-up'}, {'keys': 'mod+shift+Down', 'action': 'move-down'}, {'keys': 'mod+2', 'action': 'workspace', 'arg': '2'},
                     {'keys': 'shift+mod+2', 'action': 'move-to-workspace', 'arg': '2'}, {'keys': 'mod+ctrl+alt+shift+e', 'action': 'exit'}, {'keys': 'XF86AudioMute', 'action': 'spawn', 'arg': 'wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle'}],
           'rules': [{'app': 'firefox', 'workspace': '2'}, {'app': 'org.gnome.Calculator', 'title': 'Calc (1)', 'floating': True}, {'title': 'Picture-in-Picture', 'floating': True, 'fullscreen': True}],
           'displays': [{'output': 'DP-1', 'mode': '2560x1440@144', 'position': '0,0', 'scale': '1'}, {'output': 'HDMI-A-1', 'mode': '1920x1080', 'position': '2560,-200', 'transform': '90', 'scale': '1.5'},
                        {'output': 'eDP-1', 'enabled': False}]}


def changed(**parts):
    return PROFILE | parts


class Checked(unittest.TestCase):
    def test_a_profile_comes_back_whole_with_its_modifiers_in_one_order(self):
        got = desktop.normalize(PROFILE)
        self.assertEqual(got['binds'][14], {'keys': 'mod+shift+2', 'action': 'move-to-workspace', 'arg': '2'})
        self.assertEqual(got['binds'][15]['keys'], 'mod+ctrl+alt+shift+e')
        self.assertEqual(got['rules'][0], {'app': 'firefox', 'title': '', 'workspace': '2', 'floating': False, 'fullscreen': False})
        self.assertEqual(got['displays'][2], {'output': 'eDP-1', 'mode': '', 'position': '', 'scale': '', 'transform': 'normal', 'enabled': False})
        self.assertEqual(desktop.normalize(got), got, 'checking it twice changes nothing')

    def test_nothing_that_could_start_a_line_of_its_own_gets_in(self):
        bad = [('a command that closes its string', {'binds': [{'keys': 'mod+a', 'action': 'spawn', 'arg': 'ghostty"; } Mod+b { spawn "sh'}]}),
               ('a command with a second command', {'binds': [{'keys': 'mod+a', 'action': 'spawn', 'arg': 'true; rm -rf ~'}]}),
               ('a command with a substitution', {'binds': [{'keys': 'mod+a', 'action': 'spawn', 'arg': 'echo $(id)'}]}),
               ('a command of two lines', {'binds': [{'keys': 'mod+a', 'action': 'spawn', 'arg': 'ghostty\nexec id'}]}),
               ('a command with a backtick', {'binds': [{'keys': 'mod+a', 'action': 'spawn', 'arg': 'echo `id`'}]}),
               ('a key that is a block', {'binds': [{'keys': 'mod+a { quit; }', 'action': 'close'}]}),
               ('a key with a line break', {'binds': [{'keys': 'mod+a\nbindsym b', 'action': 'close'}]}),
               ('a modifier that is not one', {'binds': [{'keys': 'hyper+a', 'action': 'close'}]}),
               ('a modifier twice', {'binds': [{'keys': 'mod+mod+a', 'action': 'close'}]}),
               ('a key bound twice', {'binds': [{'keys': 'mod+shift+a', 'action': 'close'}, {'keys': 'shift+mod+a', 'action': 'exit'}]}),
               ('an action that does not exist', {'binds': [{'keys': 'mod+a', 'action': 'reboot'}]}),
               ('an action given something it does not take', {'binds': [{'keys': 'mod+a', 'action': 'close', 'arg': 'x'}]}),
               ('a workspace that is a command', {'binds': [{'keys': 'mod+a', 'action': 'workspace', 'arg': '1; exec id'}]}),
               ('a spawn of nothing', {'binds': [{'keys': 'mod+a', 'action': 'spawn', 'arg': ''}]}),
               ('an application that closes the raw string', {'rules': [{'app': 'x"# } spawn-at-startup "sh', 'floating': True}]}),
               ('an application that closes the criteria', {'rules': [{'app': 'x"] exec id', 'floating': True}]}),
               ('a title with a backslash', {'rules': [{'title': 'a\\"b', 'floating': True}]}),
               ('a rule for every window', {'rules': [{'floating': True}]}),
               ('a rule that does nothing', {'rules': [{'app': 'firefox'}]}),
               ('a flag that is a word', {'rules': [{'app': 'firefox', 'floating': 'yes'}]}),
               ('an output that is a block', {'displays': [{'output': 'DP-1" { off }'}]}),
               ('an output twice', {'displays': [{'output': 'DP-1'}, {'output': 'DP-1'}]}),
               ('a mode that is words', {'displays': [{'output': 'DP-1', 'mode': '1920x1080 disable'}]}),
               ('a position with a third number', {'displays': [{'output': 'DP-1', 'position': '0,0,0'}]}),
               ('a scale of nothing', {'displays': [{'output': 'DP-1', 'scale': '0'}]}),
               ('a transform that is not one', {'displays': [{'output': 'DP-1', 'transform': 'sideways'}]}),
               ('a name with a comment end', {'name': 'a\n// b'}), ('no name', {'name': ''}), ('a third mod key', {'mod': 'hyper'}),
               ('more binds than a keyboard has', {'binds': [{'keys': f'mod+F{i}', 'action': 'close'} for i in range(301)]}), ('binds that are not a list', {'binds': {'a': 1}})]
        for why, part in bad:
            with self.subTest(why), self.assertRaises(ValueError):
                desktop.normalize(changed(**part))
        for value in ('not an object', None, []):
            with self.assertRaises(ValueError):
                desktop.normalize(value)

    def test_nothing_is_rendered_unchecked_and_only_for_a_compositor_it_knows(self):
        with self.assertRaises(ValueError):
            desktop.render(changed(binds=[{'keys': 'mod+a', 'action': 'spawn', 'arg': 'a"b'}]), 'niri')
        with self.assertRaises(ValueError):
            desktop.render(PROFILE, 'kwin')


class Rendered(unittest.TestCase):
    def test_one_profile_says_the_same_in_both(self):
        niri, sway = desktop.render(PROFILE, 'niri'), desktop.render(PROFILE, 'sway')
        for n, s in (('Mod+Return { spawn "ghostty"; }', 'bindsym $mod+Return exec ghostty'), ('Mod+d { spawn "dms" "ipc" "call" "spotlight" "toggle"; }', 'bindsym $mod+d exec dms ipc call spotlight toggle'),
                     ('Mod+q { close-window; }', 'bindsym $mod+q kill'), ('Mod+Shift+2 { move-column-to-workspace 2; }', 'bindsym $mod+Shift+2 move container to workspace number 2'),
                     ('Mod+Ctrl+Alt+Shift+e { quit; }', 'bindsym $mod+Ctrl+Mod1+Shift+e exit'), ('XF86AudioMute { spawn "wpctl" "set-mute" "@DEFAULT_AUDIO_SINK@" "toggle"; }', 'bindsym XF86AudioMute exec wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle'),
                     ('match app-id=r#"^org[.]gnome[.]Calculator$"# title=r#"^Calc [(]1[)]$"#', 'for_window [app_id="^org[.]gnome[.]Calculator$" title="^Calc [(]1[)]$"] floating enable'),
                     ('open-on-workspace "2"', 'for_window [app_id="^firefox$"] move container to workspace number 2'),
                     ('mode "2560x1440@144.000"', 'output DP-1 mode 2560x1440@144Hz position 0 0 scale 1'), ('position x=2560 y=-200', 'output HDMI-A-1 mode 1920x1080 position 2560 -200 scale 1.5 transform 90'),
                     ('output "eDP-1" {\n    off\n}', 'output eDP-1 disable')):
            with self.subTest(n):
                self.assertIn(n, niri)
                self.assertIn(s, sway)
        self.assertNotIn('\\', niri + sway, 'no backslash: the two formats read one differently')
        self.assertEqual(sway.count('set $mod Mod4'), 1)
        self.assertIn('set $mod Mod1', desktop.render(changed(mod='alt'), 'sway'))
        self.assertIn('mod-key "Alt"', desktop.render(changed(mod='alt'), 'niri'))

    def test_an_empty_profile_is_a_file_that_says_whose_it_is(self):
        for compositor in desktop.COMPOSITORS:
            text = desktop.render({'name': 'empty'}, compositor)
            self.assertIn('empty: written by StorageForge', text.splitlines()[0])
            self.assertNotIn('binds {', text)

    @unittest.skipUnless(shutil.which('niri'), 'needs niri to check its configuration')
    def test_niri_itself_accepts_what_is_rendered_for_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, profile in (('full', PROFILE), ('alt', changed(mod='alt')), ('empty', {'name': 'empty'})):
                path = Path(tmp) / f'{name}.kdl'
                path.write_text(desktop.render(profile, 'niri'))
                ran = subprocess.run(['niri', 'validate', '-c', str(path)], capture_output=True, text=True)
                with self.subTest(name):
                    self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)

    def test_hyprland_says_the_same_in_its_lua(self):
        lua = desktop.render(PROFILE, 'hyprland')
        for want in ('hl.bind("SUPER + Return", hl.dsp.exec_cmd("ghostty"))', 'hl.bind("SUPER + SHIFT + 2", hl.dsp.window.move({ workspace = 2 }))', 'hl.bind("SUPER + Left", hl.dsp.focus({ direction = "left" }))',
                     'hl.bind("SUPER + SHIFT + Down", hl.dsp.window.move({ direction = "down" }))', 'hl.bind("SUPER + CTRL + ALT + SHIFT + e", hl.dsp.exit())',
                     'hl.window_rule({ name = "storageforge-2", match = { class = "^org[.]gnome[.]Calculator$", title = "^Calc [(]1[)]$" }, float = true })',
                     'hl.monitor({ output = "HDMI-A-1", mode = "1920x1080", position = "2560x-200", scale = 1.5, transform = 1 })', 'hl.monitor({ output = "eDP-1", disabled = true })'):
            with self.subTest(want):
                self.assertIn(want, lua)
        self.assertIn('hl.bind("ALT + Return"', desktop.render(changed(mod='alt'), 'hyprland'))

    @unittest.skipUnless(shutil.which('Hyprland'), 'needs Hyprland to check its configuration')
    def test_hyprland_itself_accepts_what_is_rendered_for_it(self):
        """--verify-config refuses a field, a match property, a key or a direction it does not know (tried by hand on 0.57)."""
        with tempfile.TemporaryDirectory() as tmp:
            for name, profile in (('full', PROFILE), ('alt', changed(mod='alt')), ('empty', {'name': 'empty'})):
                path = Path(tmp) / f'{name}.lua'
                path.write_text(desktop.render(profile, 'hyprland'))
                ran = subprocess.run(['Hyprland', '--verify-config', '-c', str(path)], capture_output=True, text=True, timeout=60)
                with self.subTest(name):
                    self.assertIn('config ok', ran.stdout + ran.stderr, (ran.stdout + ran.stderr)[-600:])


if __name__ == '__main__':
    unittest.main()
