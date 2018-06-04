#!/usr/bin/python
# pylint: disable=invalid-name

"""
 ct-submit.py - Submit pem certificates to CT logs.
 Code forked from:
 https://gist.github.com/rraptorr/2efaaf21caaf6574e8ff
"""

from __future__ import print_function
from argparse import ArgumentParser, FileType
from base64 import b64decode, b64encode
from datetime import datetime
from json import dumps, loads
from random import random
from struct import pack
try:  # Python 3 and newer only
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen
except ImportError:  # Python 2.7 and older
    from urllib2 import HTTPError, Request, urlopen, URLError


# https://crt.sh/monitored-logs
LOGS = {
    'argon2018': 'https://ct.googleapis.com/logs/argon2018',
    'argon2019': 'https://ct.googleapis.com/logs/argon2019',
    'argon2020': 'https://ct.googleapis.com/logs/argon2020',
    'argon2021': 'https://ct.googleapis.com/logs/argon2021',
    'digicert1': 'https://ct1.digicert-ct.com/log',
    'digicert2': 'https://ct2.digicert-ct.com/log',
    'icarus': 'https://ct.googleapis.com/icarus',
    'mammoth': 'https://mammoth.ct.comodo.com',
    'nimbus2018': 'https://ct.cloudflare.com/logs/nimbus2018',
    'nimbus2019': 'https://ct.cloudflare.com/logs/nimbus2019',
    'nimbus2020': 'https://ct.cloudflare.com/logs/nimbus2020',
    'nimbus2021': 'https://ct.cloudflare.com/logs/nimbus2021',
    'nessie2019': 'https://nessie2019.ct.digicert.com/log',
    'nessie2020': 'https://nessie2020.ct.digicert.com/log',
    'nessie2021': 'https://nessie2021.ct.digicert.com/log',
    'nordunet': 'https://plausible.ct.nordu.net',
    'pilot': 'https://ct.googleapis.com/pilot',
    'rocketeer': 'https://ct.googleapis.com/rocketeer',
    'sabre': 'https://sabre.ct.comodo.com',
    'skydiver': 'https://ct.googleapis.com/skydiver',
    'xenon2018': 'https://ct.googleapis.com/logs/xenon2018',
    'xenon2019': 'https://ct.googleapis.com/logs/xenon2019',
    'xenon2020': 'https://ct.googleapis.com/logs/xenon2020',
    'xenon2021': 'https://ct.googleapis.com/logs/xenon2021',
    'yeti2018': 'https://yeti2018.ct.digicert.com/log',
    'yeti2019': 'https://yeti2019.ct.digicert.com/log',
    'yeti2020': 'https://yeti2020.ct.digicert.com/log',
    'yeti2021': 'https://yeti2021.ct.digicert.com/log',
}

PARSER = ArgumentParser(description='Certificate Transparency submission client')
PARSER.add_argument('pem', type=FileType('r'),
                    help='PEM files forming a certificate chain (with or without root)', nargs='+')
PARSER.add_argument('-o', dest='output', type=FileType('w'),
                    help='output raw TLS extension data with all the SCTs (compatible with haproxy)')
PARSER.add_argument('-O', dest='output_dir',
                    help='output individual SCTs to a directory (compatible with nginx-ct module)')

ARGS = PARSER.parse_args()

CHAIN = []
CERT = None
for pem in ARGS.pem:
    for line in pem.readlines():
        line = line.strip()
        if len(line) == 0:
            continue

        if line == '-----BEGIN CERTIFICATE-----':
            CERT = []
        elif line == '-----END CERTIFICATE-----':
            b64 = ''.join(CERT)
            CHAIN.append(b64)
            CERT = None
        elif CERT is not None:
            CERT.append(line)

if len(CHAIN) == 0:
    print("no certificates found")
    exit(1)

SCTS = []
for logname, logurl in sorted(LOGS.items(), key=lambda x: random()):
    print("sending request to %s" % logname)

    request = Request(logurl + '/ct/v1/add-chain',
                      data=dumps({'chain': CHAIN}).encode('utf8'),
                      headers={'Content-Type': 'application/json'})
    try:
        response = urlopen(request)
        jsonResponse = response.read().decode('utf8')
    except HTTPError as err:
        if err.code >= 400 and err.code < 500:
            print("  unable to submit certificate to log, HTTP error %d %s: %s" %
                  (err.code, err.reason, err.read()))
        else:
            print("  unable to submit certificate to log, HTTP error %d %s" %
                  (err.code, err.reason))
        continue
    except URLError as err:
        print("  unable to submit certificate to log, error %s" % err.reason)
        continue

    sct = loads(jsonResponse)
    print("  version: %d" % sct['sct_version'])
    print("  log ID: %s" % sct['id'])
    print("  timestamp: %d (%s)" % (sct['timestamp'], datetime.fromtimestamp(sct['timestamp'] / 1000)))
    print("  extensions: %s" % sct['extensions'])
    print("  signature: %s" % sct['signature'])

    logId = b64decode(sct['id'])
    timestamp = sct['timestamp']
    extensions = b64decode(sct['extensions'])
    signature = b64decode(sct['signature'])
    sct = pack('> B 32s Q H ' + str(len(extensions)) + 's ' + str(len(signature)) + 's', 0,
               logId, timestamp, len(extensions), extensions, signature)
    SCTS.append((logname, sct))

    print("  SCT (%d bytes): %s" % (len(sct), b64encode(sct)))

if ARGS.output:
    SIZE = 0
    for log, sct in SCTS:
        SIZE += 2 + len(sct)
    ARGS.output.write(pack('>H', SIZE))
    for log, sct in SCTS:
        ARGS.output.write(pack('>H ' + str(len(sct)) + 's', len(sct), sct))
    ARGS.output.close()

if ARGS.output_dir:
    for log, sct in SCTS:
        with open(ARGS.output_dir + '/' + log + '.sct', 'w') as f:
            f.write(sct)
