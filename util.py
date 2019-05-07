#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Util DNS attacker


"""

import struct


def dns_request_builder(url, query_id=0) -> bytes:
    """This function builds a DNS packet query

    This function creates a dns packet with customizable parameters. This allows you to send dns queries directly
    from the program. The function uses the struct library to facilitate string to byte conversion to store the
    entire contents of the packet before the conversion.
    Return value: the dns data in the form of byte stream.

    Parameters
    ----------

    url : str
         The url we're gonna lookout FOR

    query_id : int, optional
            The query_id of the packet (default is "0" and means we're not trying to attack)

    """

    packet = struct.pack(">H", query_id)  # Query Ids
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


def decode_labels(message, offset):
    labels = []

    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2

            return labels + decode_labels(message, pointer & 0x3FFF), offset

        if (length & 0xC0) != 0x00:
            raise StandardError("unknown label encoding")

        offset += 1

        if length == 0:
            return labels, offset

        labels.append(*struct.unpack_from("!%ds" % length, message, offset))
        offset += length


DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")


def decode_question_section(message, offset, qdcount):
    questions = []

    for _ in range(qdcount):
        qname, offset = decode_labels(message, offset)

        qtype, qclass = DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
        offset += DNS_QUERY_SECTION_FORMAT.size

        question = {"domain_name": qname,
                    "query_type": qtype,
                    "query_class": qclass}

        questions.append(question)

    return questions, offset


DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")


def decode_dns_message(message):
    id, misc, qdcount, ancount, nscount, arcount = DNS_QUERY_MESSAGE_HEADER.unpack_from(message)

    qr = (misc & 0x8000) != 0
    opcode = (misc & 0x7800) >> 11
    aa = (misc & 0x0400) != 0
    tc = (misc & 0x200) != 0
    rd = (misc & 0x100) != 0
    ra = (misc & 0x80) != 0
    z = (misc & 0x70) >> 4
    rcode = misc & 0xF

    offset = DNS_QUERY_MESSAGE_HEADER.size
    questions, offset = decode_question_section(message, offset, qdcount)

    result = {"id": id,
              "is_response": qr,
              "opcode": opcode,
              "is_authoritative": aa,
              "is_truncated": tc,
              "recursion_desired": rd,
              "recursion_available": ra,
              "reserved": z,
              "response_code": rcode,
              "question_count": qdcount,
              "answer_count": ancount,
              "authority_count": nscount,
              "additional_count": arcount,
              "questions": questions}

    return result
