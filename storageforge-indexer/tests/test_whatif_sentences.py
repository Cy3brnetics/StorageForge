"""The what-if in plain words (roadmap A4 phase 4, UX-27): sentences() is pure, so these build the answer by hand, and one test goes
through the real route to prove the new fields sit beside the old ones."""
import unittest

from storageforge_index import whatif
from test_security import Base

EMPTY = {'ghost': {'add': [], 'remove': [], 'edges': [], 'changed': [], 'stops': []}, 'exposure': [], 'flows': [], 'conflicts': [], 'blocked': False, 'not_modelled': []}


def answer(**over):
    return {**EMPTY, **over, 'ghost': {**EMPTY['ghost'], **over.get('ghost', {})}}


def texts(res):
    return [s['text'] for s in whatif.sentences(res)]


class Sentences(unittest.TestCase):
    def test_nothing_staged_says_so_and_no_more(self):
        got = whatif.sentences(answer())
        self.assertEqual([s['level'] for s in got], ['ok'])
        self.assertIn('nothing is staged', got[0]['text'])

    def test_a_step_with_no_consequence_says_nothing_else_is_affected(self):
        got = whatif.sentences(answer(ghost={'changed': [{'id': 'fw:nas', 'what': 'Deny tcp/9999'}]}))
        self.assertEqual(got[-1]['level'], 'ok')
        self.assertIn('nothing else is affected', got[-1]['text'])

    def test_it_does_not_say_nothing_else_when_something_is_wider_or_unmodelled(self):
        wider = answer(exposure=[{'host': 'nas', 'changes': [{'port': 9000, 'proto': 'tcp', 'before': 'blocked', 'after': 'lan', 'wider': True}]}])
        self.assertFalse(any('nothing else' in t for t in texts(wider)))
        blind = answer(not_modelled=['the firewall has not been read, so "deny tcp/22" cannot be shown'])
        self.assertFalse(any('nothing else' in t for t in texts(blind)))
        self.assertTrue(any(t.startswith('Note: not shown here') for t in texts(blind)))

    def test_a_closed_port_is_a_sentence_with_words_for_the_levels(self):
        got = texts(answer(exposure=[{'host': 'nas', 'changes': [{'port': 445, 'proto': 'tcp', 'before': 'lan', 'after': 'blocked', 'wider': False}]}]))
        self.assertEqual(got[0], 'Note: on nas, port 445/tcp goes from private networks to blocked, so nothing else can reach it.')

    def test_a_widened_port_is_a_warning(self):
        got = whatif.sentences(answer(exposure=[{'host': 'nas', 'changes': [{'port': 9000, 'proto': 'tcp', 'before': 'blocked', 'after': 'any', 'wider': True, 'container': 'web'}]}]))
        self.assertEqual(got[0]['level'], 'warn')
        self.assertTrue(got[0]['text'].startswith('Careful: on nas, port 9000/tcp (container web) goes from blocked to any address'))

    def test_a_new_and_a_vanished_listener(self):
        got = texts(answer(exposure=[{'host': 'a', 'changes': [{'port': 80, 'proto': 'tcp', 'before': None, 'after': 'lan', 'wider': True}, {'port': 81, 'proto': 'tcp', 'before': 'lan', 'after': None, 'wider': False}]}]))
        self.assertIn('on a, port 80/tcp would start listening', got[0])
        self.assertIn('on a, port 81/tcp would stop listening, so nothing can reach it', got[1])

    def test_a_cut_ssh_is_danger_and_comes_first_with_the_way_out(self):
        res = answer(conflicts=[{'level': 'warn', 'text': 'x is already held by y'}, {'level': 'crit', 'text': 'this cuts SSH from 10.0.0.5 to nas, which is how StorageForge reaches it: ufw', 'host': 'nas', 'blocks_ssh': True}],
                     exposure=[{'host': 'nas', 'changes': [{'port': 22, 'proto': 'tcp', 'before': 'lan', 'after': 'blocked', 'wider': False}]}])
        got = whatif.sentences(res)
        self.assertEqual([s['level'] for s in got], ['crit', 'warn', 'info'])
        self.assertTrue(got[0]['text'].startswith('Danger: this cuts SSH from 10.0.0.5 to nas'))
        self.assertTrue(got[0]['text'].endswith('Stage a rollback timer first, or do not apply it.'))
        self.assertEqual(got[1]['text'], 'Careful: x is already held by y.')       # a text that already ends in a stop is not given a second one

    def test_the_order_is_by_severity_and_keeps_the_order_of_the_steps_inside_a_level(self):
        res = answer(ghost={'add': [{'kind': 'Bridge', 'label': 'br1', 'host': 'nas'}, {'kind': 'Listener', 'label': '80/tcp', 'host': 'nas'}], 'changed': [{'id': 'nic:nas:eth0', 'what': 'MTU 9000'}]},
                     conflicts=[{'level': 'crit', 'text': 'one'}, {'level': 'crit', 'text': 'two'}])
        got = texts(res)
        self.assertEqual(got[:2], ['Danger: one.', 'Danger: two.'])
        self.assertEqual(got[2:], ['Note: it adds a bridge called br1 on nas.', 'Note: on nas, eth0 is set to MTU 9000.'])      # the listener is the exposure's to say

    def test_a_service_that_goes_away_names_the_ports_that_stop_answering(self):
        res = answer(ghost={'stops': [{'host': 'nas', 'name': 'web', 'how': 'removed', 'ports': ['8080/tcp', '8443/tcp']}, {'host': 'nas', 'name': 'job', 'how': 'stopped', 'ports': []}]})
        got = whatif.sentences(res)
        self.assertEqual(got[0], {'level': 'warn', 'label': 'Careful', 'text': 'Careful: if web is removed from nas, 8080/tcp, 8443/tcp stops answering.'})
        self.assertIn('if job is stopped on nas, no port stops answering', got[1]['text'])
        self.assertFalse(any('nothing else' in t for t in texts(res)))        # the ports are an effect

    def test_paths_that_were_asked_about(self):
        flows = [{'from': 'web1', 'to': 'nas', 'port': 445, 'proto': 'tcp', 'before': 'allowed', 'after': 'blocked', 'decided_by': 'ufw: deny 445'},
                 {'from': 'web1', 'to': 'db', 'port': 5432, 'proto': 'tcp', 'before': 'allowed', 'after': 'allowed'},
                 {'from': 'a', 'to': 'b', 'port': 1, 'proto': 'udp', 'before': 'blocked', 'after': 'allowed'},
                 {'from': 'c', 'to': 'd', 'port': 2, 'proto': 'tcp', 'before': 'allowed', 'after': 'unknown'},
                 {'from': 'e', 'to': 'f', 'port': 3, 'proto': 'tcp', 'before': 'blocked', 'after': 'blocked'}]
        got = texts(answer(flows=flows))
        self.assertIn('Careful: web1 would no longer be able to reach nas on 445/tcp, by ufw: deny 445.', got)
        self.assertIn('Note: web1 can still reach db on 5432/tcp.', got)
        self.assertIn('Careful: a would be able to reach b on 1/udp, which was blocked before.', got)
        self.assertIn('Careful: whether c can reach d on 2/tcp cannot be told from what was read.', got)
        self.assertIn('Note: e still cannot reach f on 3/tcp.', got)

    def test_a_flow_that_stays_as_it_was_leaves_the_claim_standing(self):
        got = whatif.sentences(answer(flows=[{'from': 'web1', 'to': 'db', 'port': 5432, 'proto': 'tcp', 'before': 'allowed', 'after': 'allowed'}]))
        self.assertEqual(got[-1]['level'], 'ok')

    def test_host_text_is_data_and_stays_as_it_is(self):
        got = texts(answer(ghost={'stops': [{'host': 'n<b>', 'name': '<img src=x>', 'how': 'stopped', 'ports': ['1/tcp']}]}))
        self.assertIn('<img src=x>', got[0])           # the page builds it with text nodes, so it is never markup

    def test_every_sentence_carries_its_severity_word_and_nothing_else_does(self):
        for s in whatif.sentences(answer(conflicts=[{'level': 'crit', 'text': 'a'}, {'level': 'warn', 'text': 'b'}], not_modelled=['c'])):
            self.assertTrue(s['text'].startswith(s['label'] + ': '), s)
            self.assertEqual(whatif.SEVERITY[s['level']], s['label'])


class SentencesInTheAnswer(Base):
    def post(self, *tasks):
        r = self.client.post('/api/map/whatif', json={'tasks': [{'host': 'nas', **t} for t in tasks]})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return r.get_json()

    def test_the_old_fields_are_all_still_there_and_the_new_ones_come_with_them(self):
        got = self.post({'type': 'workload-remove', 'params': {'runtime': 'docker', 'name': 'web'}})
        for key in ('ghost', 'exposure', 'flows', 'conflicts', 'blocked', 'not_modelled', 'caveat'):
            self.assertIn(key, got)
        self.assertEqual(got['ghost']['remove'], [{'id': 'wl:nas:docker::web'}])
        self.assertEqual(got['steps'], [whatif.changes.title({'type': 'workload-remove', 'params': {'runtime': 'docker', 'name': 'web'}})])
        self.assertEqual(got['sentences'], whatif.sentences({k: v for k, v in got.items() if k not in ('steps', 'sentences')}))
        self.assertIn('if web is removed from nas', got['sentences'][0]['text'])

    def test_an_unread_firewall_is_said_and_never_called_harmless(self):
        got = self.post({'type': 'fw-rule', 'params': {'action': 'deny', 'proto': 'tcp', 'port': '8000'}})
        self.assertTrue(any(s['text'].startswith('Note: not shown here') for s in got['sentences']), got['sentences'])
        self.assertFalse(any('nothing else' in s['text'] for s in got['sentences']))

    def test_nothing_staged_is_one_fine_sentence(self):
        got = self.post()
        self.assertEqual(got['sentences'], [{'level': 'ok', 'label': 'Fine', 'text': 'Fine: nothing is staged, so nothing would change.'}])
        self.assertEqual(got['steps'], [])


if __name__ == '__main__':
    unittest.main()
