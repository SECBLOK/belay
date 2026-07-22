import os


def show_fingerprint():
    path = os.path.expanduser('~/.ssh/id_rsa.pub')
    with open(path) as f:
        return f.read()
