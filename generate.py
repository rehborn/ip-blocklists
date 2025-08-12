#!/usr/bin/env python3
import json
import os
import socket
from datetime import datetime

import yaml
import requests
import hashlib
import tarfile

config = yaml.load(open('config.yml', 'r'), Loader=yaml.SafeLoader)


def whois_parse_routes(whois_server: str, query: str) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect((whois_server, 43))
    s.send(bytes(query, "utf-8") + b"\r\n")
    response = b""
    while True:
        d = s.recv(4096)
        response += d
        if not d:
            break
    s.close()
    result = response.decode("utf-8")

    routes = {4: [], 6: []}
    for x in result.split("\n"):
        if x.startswith('route'):
            route = x.split(' ')[-1]
            if x.startswith('route:'):
                routes[4].append(route)
            elif x.startswith('route6:'):
                routes[6].append(route)
    return routes

def generate_blocklists():
    for source, attrs in config['sources'].items():
        ipv = {
            4: [],
            6: [],
        }

        for i in [4, 6]:
            if f'ipv{i}' in attrs:
                ipv[i].extend(attrs[f'ipv{i}'])

        if 'json' in attrs:
            result = requests.get(attrs['json']).json()

            for i in [4, 6]:
                prefix = attrs.get(f'ipv{i}_prefix', 'prefixes')
                field = attrs.get(f'ipv{i}_field', f'ipv{i}Prefix')

                ipv[i].extend([i[field] for i in result[prefix] if i.get(field)])

        if 'whois' in attrs:
            whois_result = whois_parse_routes(attrs['whois'], attrs['query'])
            for i in [4, 6]:
                ipv[i].extend(whois_result[i])

        print(f'{source}: {len(ipv[4])} IPv4 - | {len(ipv[6])} IPv6')

        for i in [4, 6]:
            if len(ipv[i]) > 0:
                open(f'{source}.v{i}.blocklist', 'w').write('\n'.join(ipv[i]) + '\n')


def combine_blocklists():
    v4 = open('combined.v4.blocklist', 'w')
    v6 = open('combined.v6.blocklist', 'w')

    for blocklist in os.listdir():
        print(blocklist)
        if blocklist.endswith('.v4.blocklist'):
            v4.write(open(blocklist, 'r').read())
        if blocklist.endswith('.v6.blocklist'):
            v6.write(open(blocklist, 'r').read())

def generate_checksums() -> None:
    checksums = []
    hasher = hashlib.sha256()
    for blocklist in os.listdir():
        if blocklist.endswith('.blocklist'):
            with open(blocklist, 'rb') as f:
                hasher.update(f.read())
                checksums.append({'filename': blocklist, 'sha256': hasher.hexdigest()})

    open('checksums.json', 'w').write(json.dumps(checksums, indent=4))
    open('checksums.txt', 'w').write('\n'.join(["{} {}".format(c['sha256'], c['filename']) for c in checksums]))


def generate_archive() -> None:
    with tarfile.open('blocklists.tar.gz', 'w:gz') as archive:
        archive.add('.')


def generate_html() -> None:
    html = """
    <!DOCTYPE html>
    <html>
    <head>
    <title>Blocklists</title>
    <style>body {margin: 0 auto; max-width: 768px;}</style>
    </head>
    <body>
    <h1>Blocklists</h1>
    <pre>
    <a href="blocklists.tar.gz">blocklists.tar.gz</a>
    <a href="combined.v4.blocklist">combined.v4.blocklist</a>
    <a href="combined.v6.blocklist">combined.v4.blocklist</a>
    
    <b>SHA256</b>\t\t\t\t\t\t\t\t <b>Blocklist</b>
    #files#

    Generated at #datetime#
    </pre>
    </body>
    </html>""".replace('    ', '')

    attrs = {
        'datetime': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'files': open('checksums.txt').read(),
    }

    for attr in attrs:
        html = html.replace(f'#{attr}#', attrs[attr])

    open('index.html', 'w').write(html)


if __name__ == '__main__':
    os.makedirs('dist', exist_ok=True)
    os.chdir('dist')

    generate_blocklists()
    combine_blocklists()
    generate_checksums()
    generate_archive()
    generate_html()
