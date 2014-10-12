#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function
"""
test_dhcp
"""

from scapy.all import (
    Ether, IP, TCP, UDP, DNS, DNSQR, BOOTP, DHCP,
    sr, sr1, srp, srp1,
    srloop, srploop,
    make_table,
    wireshark,
    get_if_raw_hwaddr,
    sniff
    )

def test_dhcp(*args):
    """

    from scapy/docs/usage
    """

    from scapy.all import conf
    conf.checkIPaddr = False

    iface = conf.iface

    fam, hw = get_if_raw_hwaddr(iface)
    dhcp_discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=hw) /
        DHCP(options=[("message-type","discover"),"end"])
    )
    ans, unans = srp(dhcp_discover, multi=True, timeout=30, iface=iface)
    # Press CTRL-C after several seconds

    for p in ans:
        print( p[1][Ether].src, p[1][IP].src )

    raise Exception()

def test_dns(self):


def test_sniff(*args):
    pkts = sniff()
    raise Exception()

import unittest
class Test_test_dhcp(unittest.TestCase):
    def test_test_dhcp(self):
        test_dhcp()


def main():
    import optparse
    import logging

    prs = optparse.OptionParser(usage="./%prog : args")

    prs.add_option('-v', '--verbose',
                    dest='verbose',
                    action='store_true',)
    prs.add_option('-q', '--quiet',
                    dest='quiet',
                    action='store_true',)
    prs.add_option('-t', '--test',
                    dest='run_tests',
                    action='store_true',)

    (opts, args) = prs.parse_args()

    if not opts.quiet:
        logging.basicConfig()

        if opts.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

    if opts.run_tests:
        import sys
        sys.argv = [sys.argv[0]] + args
        import unittest
        exit(unittest.main())

    test_dhcp(*args)

if __name__ == "__main__":
    main()
