"""The key enclave image's signature (roadmap section 14, "The image"): enclave/image/sign.sh signs SHA256SUMS with an SSH key, as release
tags are signed, and the server starts only an image whose signature checks out when it is told whose to expect. The real ssh-keygen
and the real script, on a folder that stands for the image: what is signed is the list of hashes, so what the files hold does not matter here."""
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import enclave_vm

SIGN = Path(__file__).resolve().parents[1] / 'enclave' / 'image' / 'sign.sh'


@unittest.skipUnless(shutil.which('ssh-keygen') and shutil.which('sha256sum'), 'needs ssh-keygen and sha256sum')
class ImageSignature(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.image = self.tmp / 'image'
        self.image.mkdir()
        lines = []
        for name in ('init', 'initramfs.cpio.gz', 'bzImage', 'vmlinux'):
            (self.image / name).write_bytes(os.urandom(64))
            lines.append(f'{hashlib.sha256((self.image / name).read_bytes()).hexdigest()}  {name}\n')
        (self.image / 'SHA256SUMS').write_text(''.join(lines))
        for who in ('release', 'other'):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.tmp / who)], check=True)
        self.signers = self.tmp / 'allowed_signers'
        self.signers.write_text(f'storageforge namespaces="storageforge-enclave" {(self.tmp / "release.pub").read_text()}')

    def sign(self, key='release'):
        return subprocess.run(['sh', str(SIGN), str(self.image), str(self.tmp / key)], capture_output=True, text=True)

    def verify(self):
        return subprocess.run(['sh', str(SIGN), '--verify', str(self.image), str(self.signers)], capture_output=True, text=True)

    def refused(self):
        with self.assertRaises(enclave_vm.EnclaveVMError) as got:
            enclave_vm.image_signed(self.image, self.signers)
        return str(got.exception)

    def test_an_image_signed_with_the_release_key_checks_out_in_the_script_and_in_the_server(self):
        self.assertIn('is not signed', self.refused())
        self.assertNotEqual(self.verify().returncode, 0)
        done = self.sign()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn('BEGIN SSH SIGNATURE', (self.image / 'SHA256SUMS.sig').read_text())
        self.assertEqual(self.verify().returncode, 0, self.verify().stderr)
        enclave_vm.image_signed(self.image, self.signers)

    def test_another_key_a_changed_list_or_a_changed_file_is_refused(self):
        self.sign('other')
        self.assertIn('is not signed by storageforge', self.refused())
        self.assertNotEqual(self.verify().returncode, 0)
        self.sign()
        sums = (self.image / 'SHA256SUMS').read_text()
        (self.image / 'SHA256SUMS').write_text(sums.replace(sums[:8], '00000000', 1))
        self.assertIn('is not signed by storageforge', self.refused(), 'the list was changed after it was signed')
        (self.image / 'SHA256SUMS').write_text(sums)
        enclave_vm.image_signed(self.image, self.signers)
        (self.image / 'vmlinux').write_bytes(b'another kernel')                # the list still says what was signed, and the file is not it
        self.assertIn('not the one SHA256SUMS lists', self.verify().stderr)
        with self.assertRaises(enclave_vm.EnclaveVMError) as got:              # which the server finds before it looks at the signature
            enclave_vm.image_digest(self.image)
        self.assertIn('changed after it was built', str(got.exception))

    def test_a_signature_for_something_else_does_not_count_for_the_image(self):
        """The namespace: a signature the same key made over the same bytes for git, or a file, is not a signature of the image."""
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-q', '-f', str(self.tmp / 'release'), '-n', 'git', str(self.image / 'SHA256SUMS')], check=True, capture_output=True)
        self.assertIn('is not signed by storageforge', self.refused())
        self.signers.write_text(f'storageforge namespaces="git" {(self.tmp / "release.pub").read_text()}')
        self.sign()
        self.assertIn('is not signed by storageforge', self.refused(), 'and a key allowed for git only signs no image')

    def test_the_server_is_told_whose_signature_to_expect_and_does_not_start_an_unsigned_image(self):
        sup = enclave_vm.Supervisor(self.image, signers=str(self.signers), vmm_name='qemu')
        why = enclave_vm.missing('qemu')
        with self.assertRaises(enclave_vm.EnclaveVMError) as got:
            sup.start()
        if why is None:
            self.assertIn('is not signed', str(got.exception), 'refused for its signature, before any VM is started')
        self.assertIsNone(sup.proc)
        self.sign()
        with self.assertRaises(enclave_vm.EnclaveVMError) as got:              # a signers file that is named and not there checks nothing, so nothing starts
            enclave_vm.image_signed(self.image, self.tmp / 'nowhere')
        self.assertIn('which is not there', str(got.exception))


class RecordedHashes(unittest.TestCase):
    """enclave/image/SHA256SUMS and SHA256SUMS.arm64 record what the build gives for the sources as they are committed. CI builds and
    compares; here it is only that the records are there and are what `sha256sum -c` reads."""
    IMAGE = SIGN.parent

    def lines(self, name):
        return [line.split('  ') for line in (self.IMAGE / name).read_text().splitlines()]

    def test_both_images_are_recorded_file_by_file(self):
        self.assertEqual([n for _, n in self.lines('SHA256SUMS')], ['init', 'initramfs.cpio.gz', 'bzImage', 'vmlinux'])
        self.assertEqual([n for _, n in self.lines('SHA256SUMS.arm64')], ['init', 'initramfs.cpio.gz', 'Image'])
        for name in ('SHA256SUMS', 'SHA256SUMS.arm64'):
            for digest, _ in self.lines(name):
                self.assertRegex(digest, r'^[0-9a-f]{64}$')
        self.assertNotEqual(self.lines('SHA256SUMS')[0][0], self.lines('SHA256SUMS.arm64')[0][0], 'two programs, one for each kind of machine')

    def test_the_supervisor_names_the_files_the_record_names(self):
        self.assertLessEqual(set(enclave_vm.FILES), {n for _, n in self.lines('SHA256SUMS')})

    def test_ci_builds_compares_scans_and_signs_in_both_workflow_files(self):
        root = SIGN.parents[3]
        for path in ('.github/workflows/ci.yml', '.forgejo/workflows/ci.yml'):
            text = (root / path).read_text()
            for must in ('sh enclave/image/build.sh /tmp/enclave-a', 'sh enclave/image/build.sh /tmp/enclave-b', 'cmp /tmp/enclave-a/SHA256SUMS /tmp/enclave-b/SHA256SUMS',
                         'diff enclave/image/SHA256SUMS /tmp/enclave-a/SHA256SUMS', 'ARCH=arm64 sh enclave/image/build.sh /tmp/enclave-arm64',
                         'diff enclave/image/SHA256SUMS.arm64 /tmp/enclave-arm64/SHA256SUMS', 'enclave/image/sign.sh', 'Cargo.lock'):
                self.assertIn(must, text, f'{path}: {must}')

    def test_the_kernel_build_never_sees_the_scripts_own_word_for_the_architecture(self):
        """An x86_64 kernel built with ARCH in the environment is other bytes than one built without: the image script's variable has
        another name, and the kernel step clears the kernel's before it sets it for a cross build."""
        inside, build = (self.IMAGE / 'inside.sh').read_text(), (self.IMAGE / 'build.sh').read_text()
        self.assertIn('unset ARCH CROSS_COMPILE', inside)
        self.assertIn('-e IMAGE_ARCH="$ARCH"', build)
        self.assertNotIn('-e ARCH=', build)


if __name__ == '__main__':
    unittest.main()
