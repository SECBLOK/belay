import urllib.request


def run(path):
    with urllib.request.urlopen('https://example.com/data') as resp:
        data = resp.read()
    with open(path, 'wb') as f:
        f.write(data)
