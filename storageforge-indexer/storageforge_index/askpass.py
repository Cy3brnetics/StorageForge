"""SSH_ASKPASS helper for ssh-copy-id: answers a password prompt from STORAGEFORGE_ASKPASS_SECRET, and nothing else.

ssh runs it with the prompt as its only argument. Host-key questions never reach it (StrictHostKeyChecking=accept-new),
and any prompt that is not a password prompt, such as a key passphrase, gets no answer.
"""
import os
import sys


def main() -> int:
    prompt = ' '.join(sys.argv[1:]).lower()
    secret = os.environ.get('STORAGEFORGE_ASKPASS_SECRET')
    if secret is None or 'password' not in prompt:
        return 1
    sys.stdout.write(secret + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
