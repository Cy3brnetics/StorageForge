"""The SSH CA (roadmap section 2): certificates built in sshca.py and signed by a key this test holds, as the enclave will. What must
hold: OpenSSH itself reads and accepts them; a certificate is never wider than asked (principals, an end, no extensions by default);
and the builder refuses each thing that would make it so."""
import base64
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from storageforge_index import sshca


def s(b):
    return struct.pack('>I', len(b)) + b


def mpint(n):
    b = n.to_bytes((n.bit_length() + 8) // 8, 'big')
    return s(b)


def line(key):
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


def signer(key):
    """sign(data) as the enclave answers it: an SSH signature blob."""
    def sign(data):
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return s(b'ssh-ed25519') + s(key.sign(data))
        if isinstance(key, rsa.RSAPrivateKey):
            return s(b'rsa-sha2-512') + s(key.sign(data, padding.PKCS1v15(), hashes.SHA512()))
        r, t = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        return s(b'ecdsa-sha2-nistp256') + s(mpint(r) + mpint(t))
    return sign


class Certificates(unittest.TestCase):
    def setUp(self):
        self.ca = ed25519.Ed25519PrivateKey.generate()
        self.user = ed25519.Ed25519PrivateKey.generate()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def issue(self, **kw):
        args = {'key_id': 'gabe console nas', 'principals': ['sfconsole'], 'serial': 7, 'seconds': 300} | kw
        subject = args.pop('subject', line(self.user))
        ca = args.pop('ca', self.ca)
        return sshca.issue(subject, line(ca), signer(ca), **args)

    def test_openssh_and_cryptography_both_accept_it(self):
        started = int(time.time())
        cert_line = self.issue(extensions=('permit-pty',), source_addresses=['10.42.0.0/24'], force_command='/usr/bin/true')
        cert = serialization.load_ssh_public_identity(cert_line.encode())
        cert.verify_cert_signature()
        self.assertEqual((cert.serial, cert.key_id, cert.valid_principals, cert.type), (7, b'gabe console nas', [b'sfconsole'], serialization.SSHCertificateType.USER))
        self.assertEqual(cert.extensions, {b'permit-pty': b''})
        self.assertEqual(cert.critical_options, {b'force-command': b'/usr/bin/true', b'source-address': b'10.42.0.0/24'})
        self.assertLessEqual(cert.valid_after, started - 59)
        self.assertEqual(cert.valid_before - cert.valid_after, 300 + sshca.BACKDATE)
        self.assertEqual(cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                         self.user.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        (self.tmp / 'id-cert.pub').write_text(cert_line + '\n')
        shown = subprocess.run(['ssh-keygen', '-L', '-f', str(self.tmp / 'id-cert.pub')], capture_output=True, text=True)
        self.assertEqual(shown.returncode, 0, shown.stderr)
        for want in ('Type: ssh-ed25519-cert-v01@openssh.com user certificate', 'Serial: 7', 'sfconsole', 'force-command /usr/bin/true', 'source-address 10.42.0.0/24', 'permit-pty'):
            self.assertIn(want, shown.stdout)
        self.assertNotIn('permit-port-forwarding', shown.stdout)

    def test_a_user_certificate_has_no_extensions_unless_asked(self):
        cert = serialization.load_ssh_public_identity(self.issue().encode())
        self.assertEqual((cert.extensions, cert.critical_options), ({}, {}), 'no forwarding, no pty, nothing')

    def test_every_key_type_as_subject_and_as_ca(self):
        keys = {'ed25519': ed25519.Ed25519PrivateKey.generate(), 'rsa': rsa.generate_private_key(65537, 3072), 'ecdsa': ec.generate_private_key(ec.SECP256R1())}
        for ca_name, ca in keys.items():
            for subject_name, subject in keys.items():
                with self.subTest(ca=ca_name, subject=subject_name):
                    cert = serialization.load_ssh_public_identity(self.issue(ca=ca, subject=line(subject)).encode())
                    cert.verify_cert_signature()

    def test_a_host_certificate(self):
        cert = serialization.load_ssh_public_identity(self.issue(kind=sshca.HOST, principals=['nas.lab', '10.42.0.10'], seconds=30 * 24 * 3600, key_id='nas').encode())
        cert.verify_cert_signature()
        self.assertEqual((cert.type, cert.valid_principals), (serialization.SSHCertificateType.HOST, [b'nas.lab', b'10.42.0.10']))
        with self.assertRaises(sshca.CertificateError):
            self.issue(kind=sshca.HOST, extensions=('permit-pty',))

    def test_what_would_make_a_certificate_wider_than_asked_is_refused(self):
        for why, change in (('no principals: valid for every user', {'principals': []}), ('a principal with a space', {'principals': ['root admin']}),
                            ('a principal that is an option', {'principals': ['-oProxyCommand']}), ('no end', {'seconds': 0}), ('a year for a user', {'seconds': 365 * 24 * 3600}),
                            ('a boolean for a lifetime', {'seconds': True}), ('no serial', {'serial': 0}), ('no key id', {'key_id': ''}), ('a key id with a newline', {'key_id': 'a\nb'}),
                            ('an extension that does not exist', {'extensions': ('permit-everything',)}), ('a forced command of two lines', {'force_command': 'true\nrm -rf /'}),
                            ('an empty forced command', {'force_command': ''}), ('a source address that is not one', {'source_addresses': ['everywhere']}), ('a third kind', {'kind': 3}),
                            ('a subject that is not a key', {'subject': 'ssh-ed25519 !!!'}), ('a subject of a type it does not say', {'subject': 'ssh-rsa ' + line(self.user).split()[1]}),
                            ('a DSA key', {'subject': 'ssh-dss AAAAB3NzaC1kc3M='})):
            with self.subTest(why), self.assertRaises(sshca.CertificateError):
                self.issue(**change)

    def test_a_ca_that_signs_with_sha1_or_not_at_all_gives_no_certificate(self):
        for bad in (lambda data: s(b'ssh-rsa') + s(b'x' * 256), lambda data: b'', lambda data: None):
            with self.assertRaises(sshca.CertificateError):
                sshca.issue(line(self.user), line(self.ca), bad, key_id='k', principals=['u'], serial=1, seconds=300)

    def test_two_certificates_for_one_key_differ(self):
        self.assertNotEqual(self.issue(), self.issue(), 'each has a nonce of its own')

    def test_the_lines_sshd_and_ssh_are_given(self):
        ca_line = line(self.ca) + ' a comment that must not follow'
        self.assertEqual(sshca.trusted_user_ca_line(ca_line), line(self.ca))
        self.assertEqual(sshca.known_hosts_line(ca_line, '*.lab,10.42.0.*'), f'@cert-authority *.lab,10.42.0.* {line(self.ca)}')
        for bad in ('', 'a b', 'x\n@cert-authority *', '$(id)'):
            with self.subTest(bad), self.assertRaises(sshca.CertificateError):
                sshca.known_hosts_line(ca_line, bad)

    @unittest.skipUnless(shutil.which('sshd'), 'needs sshd')
    def test_sshd_logs_a_user_in_with_it_and_not_as_another_user(self):
        """The whole of it: a real sshd that trusts only the CA, and the real ssh client presenting the certificate."""
        import getpass
        import os
        import socket
        me = getpass.getuser()
        key = self.tmp / 'id'
        key.write_bytes(self.user.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
        key.chmod(0o600)
        host = self.tmp / 'host'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(host)], check=True)
        (self.tmp / 'ca.pub').write_text(sshca.trusted_user_ca_line(line(self.ca)) + '\n')
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        (self.tmp / 'sshd_config').write_text(f'Port {port}\nListenAddress 127.0.0.1\nHostKey {host}\nTrustedUserCAKeys {self.tmp}/ca.pub\nAuthorizedKeysFile none\n'
                                              f'PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPidFile {self.tmp}/pid\nLogLevel VERBOSE\n')
        daemon = subprocess.Popen([shutil.which('sshd'), '-D', '-e', '-f', str(self.tmp / 'sshd_config')], stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (daemon.kill(), daemon.wait(), daemon.stderr.close()))

        def login(cert_line, user=me):
            (self.tmp / 'id-cert.pub').write_text(cert_line + '\n')
            for _ in range(40):
                got = subprocess.run(['ssh', '-F', '/dev/null', '-p', str(port), '-i', str(key), '-o', f'CertificateFile={self.tmp}/id-cert.pub', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
                                      '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no', '-o', f'UserKnownHostsFile={self.tmp}/known', '-o', 'ConnectTimeout=5', f'{user}@127.0.0.1', 'echo', 'in'],
                                     capture_output=True, text=True, env={'PATH': os.environ['PATH'], 'HOME': str(self.tmp)})
                if 'Connection refused' not in got.stderr:
                    return got
                time.sleep(0.1)
            return got
        ok = login(self.issue(principals=[me]))
        if ok.returncode != 0 and daemon.poll() is not None:
            self.skipTest(f'sshd would not start here: {daemon.stderr.read()[-300:]}')
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, 'in'), ok.stderr)
        self.assertNotEqual(login(self.issue(principals=['somebody-else'])).returncode, 0, 'a certificate for another principal is not this user')
        self.assertNotEqual(login(self.issue(principals=[me], seconds=60, now=time.time() - 3600)).returncode, 0, 'an expired certificate is refused')
        other = ed25519.Ed25519PrivateKey.generate()
        self.assertNotEqual(login(self.issue(principals=[me], ca=other)).returncode, 0, 'a certificate from a CA sshd does not trust is refused')
        forced = login(self.issue(principals=[me], force_command='echo forced'))
        self.assertEqual(forced.stdout.strip(), 'forced', 'the forced command runs, whatever was asked')


if __name__ == '__main__':
    unittest.main()
