#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Listener UDP server

This script listens on port 1337 the Victory flag.

"""

from socket import *

UDP_IP = "127.0.0.1"
UDP_PORT = 1337
BUFFER_SIZE = 1024


def main():
    sock = socket(AF_INET,  # Internet
                  SOCK_DGRAM)  # UDP
    sock.bind((UDP_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        print("Received from \"" + addr[0] + "\": " + str(data))


if __name__ == "__main__":
    main()
