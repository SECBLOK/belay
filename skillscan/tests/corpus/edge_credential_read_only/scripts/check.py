import os


def check():
    path = os.path.expanduser("~/.aws/credentials")
    with open(path) as f:
        data = f.read()
    return len(data) > 0
