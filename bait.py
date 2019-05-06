#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Bait DNS client

This script makes Python bite the DNS rat and gives us total redirect control

"""

import socket

from util import dns_query_builder

TARGET_IP = "8.8.8.8"  # vulnDNS' IP
TARGET_PORT = 53
DNS_URL_BADGUY = "www.andrealacava.com"


def main():
    # the socket will be used on internet (AF_INET) to send an UDP datagram (SOCK_DGRAM)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_query = dns_query_builder(DNS_URL_BADGUY)
    sock.sendto(dns_query, (TARGET_IP, TARGET_PORT))
    sock.close()


if __name__ == "__main__":
    main()
