#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Venom DNS server attacker

This script makes

"""

from socket import *

from util import decode_dns_message

VENOM_IP = "192.168.56.1"
VENOM_PORT = 53
BUFFER_SIZE = 1024


def main():
    sock = socket(AF_INET, SOCK_DGRAM)
    print("Initialize server...")
    sock.bind((VENOM_IP, VENOM_PORT))
    print("Server open on " + str(VENOM_PORT) + " !")

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        # print("Received from \"" + addr[0] + "\": " + str(data))

        print(decode_dns_message(data))


if __name__ == "__main__":
    main()
