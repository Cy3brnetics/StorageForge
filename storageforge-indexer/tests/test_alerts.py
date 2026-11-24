"""Alert channels (alerts.py): what saving the settings keeps and refuses, what each channel is sent, which channels a route picks, and what
drift reads from a host's managed files. Nothing is sent anywhere: alerts._post is replaced by a recorder, and the addresses are the
documentation ranges (192.0.2.0/24, 198.51.100.0/24), which the destination check allows and nothing answers."""
import json
import shutil
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import alerts

TOKEN = 'tk_' + 'a' * 29
KEY = 'R' * 32


class Db(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.db = dbfactory.make(self, tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)

    def save(self, **alerts_body):
        return alerts.save_settings(self.conn, {'alerts': alerts_body}, 'test')

    def stored(self):
        return alerts.settings(self.conn, reveal=True)['alerts']


class SavingSettings(Db):
    def test_upgrade_preserves_old_channels_and_initializes_new_ones(self):
        alerts.set_setting(self.conn, 'alerts', {'ntfy': {'topic': 'old', 'token': TOKEN}}, 'test')
        self.assertEqual(self.save(ntfy={'topic': 'new'})['alerts']['ntfy']['token'], '••••••')
        self.assertEqual(self.stored()['ntfy']['token'], TOKEN)
        self.assertEqual(self.stored()['sms']['token'], '')

    def test_a_token_is_write_only_and_kept_while_the_server_is_the_same(self):
        self.save(ntfy={'url': 'https://192.0.2.10/', 'topic': 'nas', 'token': TOKEN})
        self.assertEqual(alerts.settings(self.conn)['alerts']['ntfy']['token'], '••••••', 'never shown back')
        self.save(ntfy={'url': 'https://192.0.2.10', 'topic': 'nas2', 'token': '••••••'})
        self.assertEqual((self.stored()['ntfy']['token'], self.stored()['ntfy']['topic'], self.stored()['ntfy']['url']), (TOKEN, 'nas2', 'https://192.0.2.10'))

    def test_a_token_is_not_sent_to_another_server_until_it_is_typed_again(self):
        """https to http would send it in clear, and another host or port can be another service."""
        for url in ('http://192.0.2.10', 'https://192.0.2.11', 'https://192.0.2.10:8443'):
            with self.subTest(url):
                self.save(ntfy={'url': 'https://192.0.2.10', 'topic': 'nas', 'token': TOKEN})
                self.save(ntfy={'url': url, 'topic': 'nas', 'token': '••••••'})
                self.assertEqual(self.stored()['ntfy']['token'], '')
        self.save(ntfy={'url': 'https://192.0.2.10:443', 'topic': 'nas', 'token': TOKEN})
        self.save(ntfy={'url': 'https://192.0.2.10', 'topic': 'nas', 'token': '••••••'})
        self.assertEqual(self.stored()['ntfy']['token'], TOKEN, '443 is https\'s own port: the same server')

    def test_what_is_refused(self):
        for body, why in (({'ntfy': {'url': 'ftp://192.0.2.10', 'topic': 'x'}}, 'must start with http'),
                          ({'ntfy': {'url': 'https://192.0.2.10', 'topic': 'a b'}}, 'letters, digits'),
                          ({'webhook': {'url': 'http://127.0.0.1:8080/hook'}}, 'not an allowed alert destination'),
                          ({'gotify': {'url': 'http://[::ffff:127.0.0.1]/', 'token': 'x'}}, 'not an allowed alert destination'),
                          ({'webhook': {'url': 'http://169.254.169.254/latest'}}, 'not an allowed alert destination'),
                          ({'pagerduty': {'routing_key': 'short'}}, 'not a routing key'),
                          ({'routes': [{'level': 'crit', 'channels': ['email']}]}, 'at least one channel')):
            with self.subTest(body), self.assertRaisesRegex(ValueError, why):
                self.save(**body)

    def test_routes_are_cleaned_and_kept_to_fifty(self):
        self.save(routes=[{'level': 'loud', 'host': 'nas-*;rm -rf', 'channels': ['ntfy', 'email']}] * 60)
        routes = self.stored()['routes']
        self.assertEqual(len(routes), 50)
        self.assertEqual(routes[0], {'level': 'any', 'host': 'nas-*rm-rf', 'channels': ['ntfy']})

    def test_a_pagerduty_key_and_whether_resolved_alerts_are_sent(self):
        self.save(pagerduty={'routing_key': KEY}, notify_resolved=False)
        self.assertEqual((self.stored()['pagerduty']['routing_key'], self.stored()['notify_resolved']), (KEY, False))
        self.save(pagerduty={'routing_key': '••••••'})
        self.assertEqual(self.stored()['pagerduty']['routing_key'], KEY, 'the placeholder keeps it')

    def test_others_see_which_channels_are_on_and_nothing_to_post_with(self):
        self.save(ntfy={'url': 'https://user:pw@192.0.2.10/base', 'topic': 'secret-topic', 'token': TOKEN}, webhook={'url': 'https://192.0.2.20/hook/abc123'})
        s = alerts.public_settings(self.conn)['alerts']
        self.assertEqual((s['ntfy']['url'], s['ntfy']['topic'], s['ntfy']['token'], s['webhook']['url']),
                         ('https://192.0.2.10', '••••••', '••••••', 'https://192.0.2.20'))


class Sending(unittest.TestCase):
    CFG = {'ntfy': {'url': 'https://192.0.2.10', 'topic': 'nas', 'token': TOKEN}, 'gotify': {'url': 'https://192.0.2.11', 'token': 'gt'},
           'webhook': {'url': 'https://192.0.2.12/hook'}, 'pagerduty': {'routing_key': KEY}, 'routes': []}

    def send(self, cfg=None, level='warn', post=None, **kw):
        sent = []
        with mock.patch.object(alerts, '_post', post or (lambda url, data, headers: sent.append((url, data, headers)))):
            out = alerts.send(cfg or self.CFG, kw.get('title', 'Pool degraded'), kw.get('message', 'tank lost a disk'), level, kw.get('extra'))
        return out, {url: (data, headers) for url, data, headers in sent}

    def test_every_channel_is_sent_what_it_takes(self):
        out, sent = self.send(level='crit', title='Pool degraded é', extra={'ref': 'nas', 'key': 'pool:tank'})
        self.assertEqual(out, ['pagerduty: sent', 'ntfy: sent', 'gotify: sent', 'webhook: sent'])
        data, headers = sent['https://192.0.2.10/nas']
        self.assertEqual((data, headers['Authorization'], headers['Priority'], headers['Title']), (b'tank lost a disk', f'Bearer {TOKEN}', '5', 'Pool degraded ?'))
        data, headers = sent['https://192.0.2.11/message']
        self.assertEqual((json.loads(data)['priority'], headers['X-Gotify-Key']), (10, 'gt'))
        hook = json.loads(sent['https://192.0.2.12/hook'][0])
        self.assertEqual((hook['level'], hook['ref'], hook['source']), ('crit', 'nas', 'storageforge'))
        pd = json.loads(sent[alerts.PAGERDUTY_URL][0])
        self.assertEqual((pd['routing_key'], pd['payload']['severity'], pd['dedup_key']), (KEY, 'critical', 'pool:tank'))

    def test_a_resolved_alert_is_not_a_pagerduty_trigger(self):
        out, sent = self.send(level='ok')
        self.assertNotIn(alerts.PAGERDUTY_URL, sent)
        self.assertEqual(sent['https://192.0.2.10/nas'][1]['Tags'], 'white_check_mark')

    def test_a_route_picks_the_channels_and_with_none_matching_all_get_it(self):
        cfg = {**self.CFG, 'routes': [{'level': 'crit', 'host': 'nas*', 'channels': ['pagerduty']}, {'level': 'any', 'host': 'pc', 'channels': ['ntfy']}]}
        self.assertEqual(set(self.send(cfg, 'crit', extra={'ref': 'nas-01'})[1]), {alerts.PAGERDUTY_URL})
        self.assertEqual(set(self.send(cfg, 'warn', extra={'ref': 'pc'})[1]), {'https://192.0.2.10/nas'})
        self.assertEqual(len(self.send(cfg, 'warn', extra={'ref': 'other'})[1]), 4, 'an alert nobody receives is worse than one too many')
        self.assertIsNone(alerts.routed({'routes': []}, 'crit', 'x'))

    def test_a_channel_that_fails_says_why_without_saying_too_much(self):
        def post(url, data, headers):
            if 'pagerduty' in url:
                raise urllib.error.HTTPError(url, 429, 'Too Many', {}, None)
            if '192.0.2.10' in url:
                raise ConnectionRefusedError('[Errno 111] Connection refused to 192.0.2.10:443')
            if '192.0.2.11' in url:
                raise ValueError('192.0.2.11 is not an allowed alert destination')
        out, _ = self.send(post=post, level='crit')
        self.assertEqual(out, ['pagerduty: the server answered HTTP 429', 'ntfy: could not deliver it',
                               'gotify: 192.0.2.11 is not an allowed alert destination', 'webhook: sent'])

    def test_with_no_channel_set_up_it_says_so(self):
        self.assertEqual(self.send(cfg={'routes': []})[0], ['no channel is set up'])

    def test_the_forms_that_hide_a_loopback_address_are_refused(self):
        for addr in ('127.0.0.1', '::1', '::ffff:127.0.0.1', '2002:7f00:1::', '169.254.169.254', 'fe80::1%eth0', '0.0.0.0', '224.0.0.1'):
            with self.subTest(addr):
                self.assertTrue(alerts._refused(addr))
        for addr in ('192.168.1.10', '10.0.0.5', '192.0.2.10', '2001:db8::1'):
            with self.subTest(addr):
                self.assertFalse(alerts._refused(addr))

    def test_a_redirect_is_not_followed(self):
        """It could point anywhere the destination check refuses."""
        self.assertIsNone(alerts._NoRedirect().redirect_request(None, None, 302, 'Found', {}, 'http://127.0.0.1/'))


class Drift(Db):
    def host(self, name, managed):
        self.conn.execute('INSERT INTO hosts (hostname, inventory_json) VALUES (:h, :i)', {'h': name, 'i': json.dumps({'managed': managed})})

    def test_what_a_host_says_about_its_managed_files_is_drift(self):
        self.host('nas', '## shares\n/etc/exports.d/storageforge.exports: OK\n/etc/samba/sf.conf: FAILED\n'
                         'sha256sum: /etc/fstab.d/sf: No such file or directory\nLINE-MISSING UUID=abc /srv ext4 defaults 0 2\n'
                         '/etc/x: FAILED open or read\n')
        self.host('pc', None)
        got = [(d['host'], d['ref'], d['text']) for d in alerts.drift(self.conn)]
        self.assertIn(('nas', 'shares', '/etc/samba/sf.conf was changed by hand'), got)
        self.assertIn(('nas', 'shares', '/etc/fstab.d/sf was removed by hand'), got)
        self.assertIn(('nas', 'shares', 'fstab line gone: UUID=abc /srv ext4 defaults 0 2'), got)
        self.assertFalse([g for g in got if '/etc/x' in g[2]], 'a file that could not be read is not called changed')
        self.assertFalse([g for g in got if g[0] == 'pc'], 'a host whose scan read no managed files has none')


if __name__ == '__main__':
    unittest.main()
