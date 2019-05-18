#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Util library

Just an utility library to parse the DNS raw request

"""
import struct


def decode_labels(message, offset):
    """Decode the various labels

    Parameters
    ----------
    message : struct
        The DNS packet in bytes

    offset : int
        offset value of the packet

    Returns
    -------
    list
        list of decoded labels

    offset : int
        offset remaining of the value
    """
    labels = []

    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2

            return labels + decode_labels(message, pointer & 0x3FFF), offset

        if (length & 0xC0) != 0x00:
            raise Exception("unknown label encoding")

        offset += 1

        if length == 0:
            return labels, offset

        labels.append(*struct.unpack_from("!%ds" % length, message, offset))
        offset += length


DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")


def decode_question_section(message, offset, qdcount):
    """Decode the question section of the DNS packet

    Parameters
    ----------
    message : struct
        The DNS packet in bytes

    offset : int
        offset value of the packet

    qdcount : int
        number of questions present in the packet


    Returns
    -------
    questions: list
        random string generated with length url_length

    offset : int
        offset remaining of the value
    """
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
    """Decode the DNS message

    Parameters
    ----------
    message : struct
        The DNS packet in bytes

    Returns
    -------
    result: dict
        dictionary representing the packet
    """
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
