#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Venom DNS attacker

This script makes Python bite the DNS rat and gives us total redirect control

Requirements installation :  sudo pip install -r requirements.txt
Usage  : python venom.py
"""

import socket
import struct

TARGET_IP = "8.8.8.8"
TARGET_PORT = 53
DNS_URL_BADGUY = "www.andrealacava.com"


def dns_query_builder(url, query_id="1") -> bytes:
    """This function builds a DNS packet query

    This function creates a dns packet with customizable parameters. This allows you to send dns queries directly
    from the program. The function uses the struct library to facilitate string to byte conversion to store the
    entire contents of the packet before the conversion.  This function returns the dns data in the form of byte
    stream.

    Parameters
    ----------

    url : str
         The url we're gonna lookout FOR

    query_id : str, optional
            The query_id of the packet (default is "1" and means we're not trying to attack)

    """

    packet = struct.pack(">H", 12049)  # Query Ids
    packet += struct.pack(">H", 256)  # Flags
    packet += struct.pack(">H", 1)  # Questions
    packet += struct.pack(">H", 0)  # Answers
    packet += struct.pack(">H", 0)  # Authorities
    packet += struct.pack(">H", 0)  # Additional
    split_url = url.split(".")
    for part in split_url:
        packet += struct.pack("B", len(part))
        for byte in part:
            packet += struct.pack("c", byte.encode('utf-8'))
    packet += struct.pack("B", 0)  # End of String
    packet += struct.pack(">H", 1)  # Query Type
    packet += struct.pack(">H", 1)  # Query Class

    return bytes(packet)


def main():
    # the socket will be used on internet (AF_INET) to send an UDP datagram (SOCK_DGRAM)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_query = dns_query_builder(DNS_URL_BADGUY)
    sock.sendto(dns_query, (TARGET_IP, TARGET_PORT))
    sock.close()


if __name__ == "__main__":
    main()
