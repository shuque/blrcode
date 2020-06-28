#!/usr/bin/env python3

"""
Query given DNS name and type, and return the response code.
If a blacklies style NODATA response is returned, detect whether
it is actually a non-existent domain and return NXDOMAIN instead.

Author: Shumon Huque
"""

import os
import sys
import dns.resolver
import dns.name
import dns.rdatatype
import dns.rcode


# Resolver List. Note: to correctly determine Blacklies style nxdomain,
# these need to be DNSSEC validating resolvers.
RESOLVER_LIST = ['8.8.8.8', '1.1.1.1']


def get_resolver(addresses=None, lifetime=5, payload=1420):
    """
    Return resolver object configured to use given list of addresses, and
    that sets DO=1, RD=1, AD=1, and EDNS payload for queries to the resolver.
    """

    resolver = dns.resolver.Resolver()
    resolver.set_flags(dns.flags.RD | dns.flags.AD)
    resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=payload)
    resolver.lifetime = lifetime
    if addresses is not None:
        resolver.nameservers = addresses
    return resolver


def is_authenticated(msg):
    """Does DNS message have Authenticated Data (AD) flag set?"""
    return msg.flags & dns.flags.AD == dns.flags.AD


def nsec_type_set(nsec_windows):
    """
    Return set of RR types present in given NSEC rdata's windows.
    """
    type_set = set()
    for (window, bitmap) in nsec_windows:
        for i in range(0, len(bitmap)):
            for j in range(0, 8):
                if bitmap[i] & (0x80 >> j):
                    rrtype = window * 256 + i * 8 + j
                    type_set.add(dns.rdatatype.to_text(rrtype))
    return type_set


def rcode(qname, qtype, resolver=None):
    """
    Return rcode for given DNS qname and qtype. If a blacklies style
    NOERROR response is detected, return NXDOMAIN. Otherwise return
    the actual rcode observed in the DNS reply message.
    """

    qname = dns.name.from_text(qname)
    try:
        msg = resolver.query(qname, qtype, raise_on_no_answer=False).response
    except dns.resolver.NXDOMAIN:
        return dns.rcode.NXDOMAIN

    if is_authenticated(msg) and (
            msg.rcode() == dns.rcode.NOERROR and not msg.answer):
        for rrset in msg.authority:
            if rrset.rdtype == dns.rdatatype.SOA:
                continue
            elif rrset.rdtype == dns.rdatatype.RRSIG:
                continue
            if rrset.rdtype != dns.rdatatype.NSEC:
                return msg.rcode()
            if rrset.name != qname:
                continue
            for rdata in rrset.to_rdataset():
                if nsec_type_set(rdata.windows) == set({'NSEC', 'RRSIG'}):
                    return dns.rcode.NXDOMAIN
                return msg.rcode()

    return msg.rcode()


if __name__ == '__main__':

    PROGNAME = os.path.basename(sys.argv[0])
    if len(sys.argv) != 3:
        print("Usage: {} <qname> <qtype>".format(PROGNAME))
        sys.exit(-1)

    QNAME, QTYPE = sys.argv[1:3]
    RESOLVER = get_resolver(addresses=RESOLVER_LIST)
    RC = rcode(QNAME, QTYPE, resolver=RESOLVER)

    print(dns.rcode.to_text(RC))
    sys.exit(RC)
