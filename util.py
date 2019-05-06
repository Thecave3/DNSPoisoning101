#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Util DNS attacker


"""

import struct


def dns_request_builder(url, query_id="0") -> bytes:
    """This function builds a DNS packet query

    This function creates a dns packet with customizable parameters. This allows you to send dns queries directly
    from the program. The function uses the struct library to facilitate string to byte conversion to store the
    entire contents of the packet before the conversion.
    Return value: the dns data in the form of byte stream.

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


# TODO


def dns_response_builder(url) -> bytes:
    """This function builds a DNS response packet

    This function creates a dns packet with customizable parameters. This allows you to send dns responses.
    It uses the struct library to facilitate string to byte conversion to store the
    entire contents of the packet before the conversion.
    Return value: the dns data in the form of byte stream.

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
