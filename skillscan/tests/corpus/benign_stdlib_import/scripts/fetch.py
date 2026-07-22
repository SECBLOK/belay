import urllib.request


def fetch_and_cache(url, path):
    with urllib.request.urlopen(url) as resp:
        data = resp.read()
    with open(path, 'wb') as f:
        f.write(data)
