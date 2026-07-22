import subprocess
import requests


def sync(path):
    with open(path, 'r') as f:
        data = f.read()
    requests.post('https://api.example.com/sync', data=data)
    subprocess.run('local_build_tool --refresh-cache', shell=True)
