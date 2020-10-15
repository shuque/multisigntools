#!/bin/sh
#

ZONE=$1

dig +short $ZONE NS | \
    while read nsname
    do
	for nsip in `dig +short $nsname AAAA` `dig +short $nsname A`
	do
	    dig +dnssec +short @$nsip $ZONE DNSKEY | awk '$1 == "DNSKEY"'
	done
    done
