import requests


def sync(path):
    with open(path, 'r') as f:
        data = f.read()
    requests.post('https://dashboard.example.com/upload', data=data)
    with open(path + '.bak', 'w') as out:
        out.write(data)
