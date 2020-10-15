#!/usr/bin/env python3
#

"""
Multi-Signer DNSSEC (Model 1) tool for NS1 API.

"""

import os
import sys
import json
import base64
import time
import getopt
import requests
import dns.zone


PROGNAME = os.path.basename(sys.argv[0])
VERSION = "0.0.1"

API_BASE = 'https://api.nsone.net/v1'
API_KEYFILE = "{}/.ns1/key".format(os.environ['HOME'])


class Prefs:
    """Configuration Preferences"""
    DNSKEY = True
    RRSIG = True


def usage():
    """Print usage string and terminate program."""
    print("""\
{0} version {1}
Usage: {0} [Options] <zone> <zonefile>

       Options:
       -h          Print this usage string
       -d          Update only DNSKEY RRset
       -r          Update only DNSKEY RRSIG
""".format(PROGNAME, VERSION))
    sys.exit(2)


def process_args(arg_vector):
    """Process command line options and arguments"""

    try:
        (options, args) = getopt.getopt(arg_vector, 'hdr')
    except getopt.GetoptError:
        usage()

    if len(args) != 2:
        usage()

    for (opt, _) in options:
        if opt == "-h":
            usage()
        elif opt == "-d":
            Prefs.DNSKEY = True
            Prefs.RRSIG = False
        elif opt == "-r":
            Prefs.DNSKEY = False
            Prefs.RRSIG = True

    return args[0], args[1]


def get_uri_dnskey(zone):
    """DNSKEY update URI"""
    return "{0}/zones/{1}/{1}/DNSKEY".format(API_BASE, zone)


def get_uri_rrsig(zone):
    """RRSIG update URI"""
    return "{0}/zones/{1}/{1}/RRSIG".format(API_BASE, zone)


def get_apikey():
    """Obtain API key"""
    _, key = open(API_KEYFILE, 'r').readline().split()[:2]
    return key


def get_headers():
    """Return populated API key HTTP header"""
    return {'X-NSONE-Key': get_apikey()}


def send_request(uri, data):
    """Post data to URI"""
    print("Sending to URI: {}".format(uri))
    print(data)
    resp = requests.post(uri, headers=get_headers(), data=data)
    print("Status code: {}".format(resp.status_code))
    if resp.text:
        print(resp.text)


def send_dnskey(topnode, zone):
    """Send DNSKEY RRset"""

    dnskey = topnode.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    if dnskey is None:
        print("ERROR: {} DNSKEY not found.".format(zone))
        sys.exit(1)

    data = dict(zone=zone, domain=zone, type="DNSKEY", ttl=dnskey.ttl,
                answers=[])

    for rdata in dnskey:
        keyinfo = {"answer":
                   [
                       str(rdata.flags),
                       str(rdata.protocol),
                       str(rdata.algorithm.value),
                       base64.standard_b64encode(rdata.key).decode()
                   ]}
        data['answers'].append(keyinfo)

    uri = get_uri_dnskey(zone)
    send_request(uri, json.dumps(data))


def send_rrsig(topnode, zone):
    """Send DNSKEY RRSIG"""

    rrsig = topnode.get_rdataset(dns.rdataclass.IN,
                                 dns.rdatatype.RRSIG,
                                 covers=dns.rdatatype.DNSKEY)
    if rrsig is None:
        print("ERROR: {} DNSKEY RRSIG not found.".format(zone))
        sys.exit(1)

    data = dict(zone=zone, domain=zone, type="RRSIG", ttl=rrsig.ttl,
                answers=[])

    for rdata in rrsig:
        rrsiginfo = {"answer":
                     [
                         "DNSKEY",
                         str(rdata.algorithm.value),
                         str(rdata.labels),
                         str(rdata.original_ttl),
                         time.strftime("%Y%m%d%H%M%S",
                                       time.gmtime(rdata.expiration)),
                         time.strftime("%Y%m%d%H%M%S",
                                       time.gmtime(rdata.inception)),
                         str(rdata.key_tag),
                         str(rdata.signer.to_text()),
                         base64.standard_b64encode(rdata.signature).decode()
                     ]}
        data['answers'].append(rrsiginfo)

    uri = get_uri_rrsig(zone)
    send_request(uri, json.dumps(data))


if __name__ == '__main__':

    ZONE, ZONEFILE = process_args(sys.argv[1:])
    DOTTEDZONE = "{}.".format(ZONE)
    TOP = dns.zone.from_file(ZONEFILE, origin=DOTTEDZONE,
                             relativize=False).get_node(DOTTEDZONE)
    if Prefs.DNSKEY:
        send_dnskey(TOP, ZONE)
    if Prefs.RRSIG:
        send_rrsig(TOP, ZONE)
