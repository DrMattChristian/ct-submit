#!/usr/bin/python

import sys
import argparse, json, base64, struct
import urllib2
from datetime import datetime

LOGS = [
    'https://ct.googleapis.com/aviator',
    'https://ct.googleapis.com/pilot',
    'https://ct.googleapis.com/rocketeer',
    'https://log.certly.io',
    'https://ct1.digicert-ct.com/log',     # only accepts certificates issued by some CAs
    'https://ct.izenpe.com',               # only accepts certificates issued by some CAs
]

parser = argparse.ArgumentParser(description='Certificate Transparency certificate submission client.',
                                 epilog='Please note that some logs will accept only certificates issued by some CAs.')
parser.add_argument('pem', type=argparse.FileType('r'), help='PEM files forming a certificate chain (with or without root)', nargs='+')
parser.add_argument('-o', dest='output', type=argparse.FileType('w'), help='output raw TLS extension data with all the SCTs')

args = parser.parse_args()

chain = []
for pem in args.pem:
    for line in pem.readlines():
        line = line.strip()
        if len(line) == 0:
            continue

        if line == '-----BEGIN CERTIFICATE-----':
            cert = []
            continue
        elif line == '-----END CERTIFICATE-----':
            b64 = ''.join(cert)
            chain.append(b64)
            continue
        else:
            cert.append(line)

jsonRequest = json.dumps({'chain': chain})

scts = []
for log in LOGS:
    print "sending request to %s" % log

    request = urllib2.Request(url = log + '/ct/v1/add-chain', data=jsonRequest)
    request.add_header('Content-Type', 'application/json')
    try:
        response = urllib2.urlopen(request)
        jsonResponse = response.read()
    except urllib2.HTTPError as e:
        if e.code >= 400 and e.code < 500:
            print "  unable to submit certificate to log, HTTP error %d %s: %s" % (e.code, e.reason, e.read())
        else:
            print "  unable to submit certificate to log, HTTP error %d %s" % (e.code, e.reason)
        continue

    sct = json.loads(jsonResponse)
    print "  version: %d" % sct['sct_version']
    print "  log ID: %s" % sct['id']
    print "  timestamp: %d (%s)" % (sct['timestamp'], datetime.fromtimestamp(sct['timestamp'] / 1000))
    print "  extensions: %s" % sct['extensions']
    print "  signature: %s" % sct['signature']

    logId = base64.b64decode(sct['id'])
    timestamp = sct['timestamp']
    extensions = base64.b64decode(sct['extensions'])
    signature = base64.b64decode(sct['signature'])
    sct = struct.pack('> B 32s Q H '+str(len(extensions))+'s '+str(len(signature))+'s', 0, logId, timestamp, len(extensions), extensions, signature)
    scts.append(sct)

    print "  SCT (%d bytes): %s" % (len(sct), base64.b64encode(sct))

if args.output:
    size = 0
    for sct in scts:
        size += 2 + len(sct)
    args.output.write(struct.pack('>H', size))
    for sct in scts:
        args.output.write(struct.pack('>H '+str(len(sct))+'s', len(sct), sct))
    args.output.close()