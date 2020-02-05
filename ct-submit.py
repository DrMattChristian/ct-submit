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

# Requires python2-cryptography and/or python34-cryptography
from cryptography import x509
from cryptography.x509 import ExtensionNotFound, oid
from cryptography.hazmat.backends import default_backend

# https://crt.sh/monitored-logs
# https://www.certificate-transparency.org/known-logs
# https://sslmate.com/certspotter/stats
# https://sslmate.com/labs/ct_ecosystem/ecosystem.html
# https://ct.cloudflare.com/logs

# CT logs used for archival or historical reference
ARCHIVELOGS = {
    'daedalus': 'https://ct.googleapis.com/daedalus',
    'dodo': 'https://dodo.ct.comodo.com',
    'submariner': 'https://ct.googleapis.com/submariner',
}

# CT logs used for testing and untrusted
# Primarily intended as an integration testing target for CAs
TESTLOGS = {
    'crucible': 'https://ct.googleapis.com/logs/crucible',
    'dodo': 'https://dodo.ct.comodo.com',
    'golem': 'https://golem.ct.digicert.com/log',
    'testtube': 'https://ct.googleapis.com/testtube',  # R/O ???
}

# CT logs used for testing and untrusted
# Sharded by certificate expiration year
# Become read only (R/O) after year-end passes
TESTYEARLOGS = {
    2020: {'solera': 'https://ct.googleapis.com/logs/solera2020',
           'testflume': 'https://testflume.ct.letsencrypt.org/2020', },
    2021: {'solera': 'https://ct.googleapis.com/logs/solera2021',
           'testflume': 'https://testflume.ct.letsencrypt.org/2021', },
    2022: {'solera': 'https://ct.googleapis.com/logs/solera2022',
           'testflume': 'https://testflume.ct.letsencrypt.org/2022', },
}

# CT logs sharded by certificate expiration year
# Become read only (R/O) after year-end passes, except LE oak uses Jan 7
YEARLOGS = {
    2020: {'argon': 'https://ct.googleapis.com/logs/argon2020',
           'nessie': 'https://nessie2020.ct.digicert.com/log',
           'nimbus': 'https://ct.cloudflare.com/logs/nimbus2020',
           'oak': 'https://oak.ct.letsencrypt.org/2020',
           'xenon': 'https://ct.googleapis.com/logs/xenon2020',
           'yeti': 'https://yeti2020.ct.digicert.com/log', },
    2021: {'argon': 'https://ct.googleapis.com/logs/argon2021',
           'nessie': 'https://nessie2021.ct.digicert.com/log',
           'nimbus': 'https://ct.cloudflare.com/logs/nimbus2021',
           'oak': 'https://oak.ct.letsencrypt.org/2021',
           'xenon': 'https://ct.googleapis.com/logs/xenon2021',
           'yeti': 'https://yeti2021.ct.digicert.com/log', },
    2022: {'argon': 'https://ct.googleapis.com/logs/argon2022',
           'nessie': 'https://nessie2022.ct.digicert.com/log',
           'nimbus': 'https://ct.cloudflare.com/logs/nimbus2022',
           'oak': 'https://oak.ct.letsencrypt.org/2022',
           'xenon': 'https://ct.googleapis.com/logs/xenon2022',
           'yeti': 'https://yeti2022.ct.digicert.com/log', },
    2023: {'argon': 'https://ct.googleapis.com/logs/argon2023',
           'nessie': 'https://nessie2023.ct.digicert.com/log',
           'nimbus': 'https://ct.cloudflare.com/logs/nimbus2023',
           'xenon': 'https://ct.googleapis.com/logs/xenon2023',
           'yeti': 'https://yeti2023.ct.digicert.com/log', },
}

# CT logs which are the non-sharded defaults
# Most will become read only (R/O) at some point
LOGS = {
    'digicert1': 'https://ct1.digicert-ct.com/log',  # R/O ???
    'digicert2': 'https://ct2.digicert-ct.com/log',  # R/O ???
    'mammoth': 'https://mammoth.ct.comodo.com',  # R/O ???
    'sabre': 'https://sabre.ct.comodo.com',  # R/O ???
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
NOW = datetime.now()  # Naive date due to before/after compare
TYEAR = NOW.year
PEMDATA = None
X509 = None
for pem in ARGS.pem:
    PEMDATA = pem.read().encode('utf8')
    pem.seek(0)
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
    X509 = x509.load_pem_x509_certificate(PEMDATA, default_backend())
    NAL = X509.subject.get_attributes_for_oid(oid.NameOID.COMMON_NAME)
    SANC = 0
    CN = ''
    if NAL:
        CN = str(NAL[0].value)
        print("Common Name CN:\t", CN)
    else:
        print("No CN found, must be new?")
    try:
        SANEXT = X509.extensions.get_extension_for_oid(oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        SANL = SANEXT.value.get_values_for_type(x509.DNSName)
        SANC = len(SANL)
        print("%s SANs: " % SANC, end='')
        for SAN in SANL:
            print("%s " % str(SAN), end='')
        print("")
    except ExtensionNotFound:
        print("No SAN extension found, likely self-signed or ancient.")
    CA = False
    try:
        BCEXT = X509.extensions.get_extension_for_oid(oid.ExtensionOID.BASIC_CONSTRAINTS)
        BC = BCEXT.value
        if BC and BC.ca is True:
            print("Found a CA root.")
            CA = True
    except ExtensionNotFound:
        print("No Basic Constraints extension found.")
    NVB = X509.not_valid_before
    BYEAR = NVB.year
    NVA = X509.not_valid_after
    AYEAR = NVA.year
    DAYSVALID = 0
    if NVA > NVB:
        DAYSVALID = abs((NVA - NVB).days)
        print("Valid for %s days." % DAYSVALID)
    else:
        print("Not valid after is less than not valid before, date error!")
        LOGS = {}
    if NVA < NOW:
        print("Expired on %s, send to archive CT logs only." % str(NVA))
        LOGS = ARCHIVELOGS
    elif DAYSVALID > 825:
        print("Valid for %s days, send to archive CT logs only." % str(DAYSVALID))
        LOGS = ARCHIVELOGS
    elif (AYEAR >= TYEAR) and (AYEAR <= 2023):
        print("Expires in %s, send to that year CT logs as well." % str(AYEAR))
        LOGS.update(YEARLOGS[AYEAR])
    elif (CA is True) or (SANC == 0):
        print("CA root or likely self-signed, send to test CT logs only.")
        LOGS = TESTLOGS
        if (AYEAR >= TYEAR) and (AYEAR <= 2023):
            print("Expires in %s, send to that year test CT logs as well." % str(AYEAR))
            LOGS.update(TESTYEARLOGS[AYEAR])
        print("WARNING: Test CT log requests may not succeed due to trusted root requirements.")
    else:
        print("Send to default CT logs.")


if len(CHAIN) == 0:
    print("No certificates found, exiting.")
    exit(1)

SCTS = []
for logname, logurl in sorted(LOGS.items(), key=lambda x: random()):
    print("Sending request to %s" % logname)

    request = Request(logurl + '/ct/v1/add-chain',
                      data=dumps({'chain': CHAIN}).encode('utf8'),
                      headers={'Content-Type': 'application/json'})
    try:
        response = urlopen(request)
        jsonResponse = response.read().decode('utf8')
    except HTTPError as err:
        if err.code >= 400 and err.code < 500:
            print("  Unable to submit certificate to log, HTTP error %d %s: %s" %
                  (err.code, err.reason, err.read()))
        else:
            print("  Unable to submit certificate to log, HTTP error %d %s" %
                  (err.code, err.reason))
        continue
    except URLError as err:
        print("  Unable to submit certificate to log, error %s" % err.reason)
        continue

    sct = loads(jsonResponse)
    print("  Version: %d  Log ID: %s" % (sct['sct_version'], sct['id']))
    print("  Timestamp: %d (%s)  Extensions: %s" %
          (sct['timestamp'], datetime.fromtimestamp(sct['timestamp'] / 1000), sct['extensions']))
    print("  Signature: %s" % str(sct['signature']))

    logId = b64decode(sct['id'])
    timestamp = sct['timestamp']
    extensions = b64decode(sct['extensions'])
    signature = b64decode(sct['signature'])
    sct = pack('> B 32s Q H ' + str(len(extensions)) + 's ' + str(len(signature)) + 's', 0,
               logId, timestamp, len(extensions), extensions, signature)
    SCTS.append((logname, sct))

    print("  SCT (%d bytes): %s" % (len(sct), str(b64encode(sct))))

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
