#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Bait DNS client

This script makes a DNS request to vulnDNS asking information about DNS_URL_BADGUY

"""

import socket

from util import dns_request_builder

TARGET_IP = "8.8.8.8"  # vulnDNS's IP
TARGET_PORT = 53
DNS_URL_BADGUY = "www.andrealacava.com"


def main():
    # the socket will be used on internet (AF_INET) to send an UDP datagram (SOCK_DGRAM)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_query = dns_request_builder(DNS_URL_BADGUY)
    sock.sendto(dns_query, (TARGET_IP, TARGET_PORT))
    sock.close()


if __name__ == "__main__":
    main()
