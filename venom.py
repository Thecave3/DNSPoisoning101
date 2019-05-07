#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Venom DNS server attacker

This script makes

"""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1

TARGET_IP = "8.8.8.8"  # vulnDNS's IP
TARGET_PORT = 53
DNS_URL_BADGUY = "andrealacava.com"


def main():
    dns_req = IP(dst=TARGET_IP) / UDP(dport=TARGET_PORT) / DNS(rd=1, qd=DNSQR(qname=DNS_URL_BADGUY))
    answer = sr1(dns_req, verbose=0)
    print(answer[DNS].summary())


if __name__ == "__main__":
    main()
