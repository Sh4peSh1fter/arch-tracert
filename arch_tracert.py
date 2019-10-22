# arch_tracert.py
#
# Author: Sean S
#
# Multi-protocol traceroute function using Scapy.

# Good sources:
# https://www.jasonspencer.org/scribbles/tracey
# https://gns3.teachable.com/courses/python-network-programming-part-3-scapy-security-tools/lectures/1478199
# https://stackoverflow.com/questions/53112554/tcp-traceroute-in-python


# Imports
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
import socket
import ipaddress
import time
import os.path
from datetime import datetime


# Constants
MIN_TTL = 1
MAX_TTL = 30
TIMEOUT = 2
UNKNOWN_ADDRESS = '****'
MIN_UDP_PORT = 33434
MAX_UDP_PORT = 33464 # https://learningnetwork.cisco.com/thread/87662
DNS_TCP_PORT = 53
SYN_FLAG = 'S'
HOP_FORMAT = '{} \t---->\t {:8.3f} ms \t---->\t {}'


# Globals
tracert_list = []


def check_if_ip_valid(target):

    try:
        #socket.inet_aton(target)
        ipaddress.ip_address(target)
        #print("Great! this IP is valid.")
    #except socket.error:
    except ValueError:
        print("Seems like this IP isn't valid...\n")
        exit()


def icmp_tracert(target):
    for my_ttl in range(MIN_TTL, MAX_TTL):
        packet = IP(dst=target, ttl=my_ttl) / ICMP()
        ts = time.time()
        reply = sr1(packet, timeout=TIMEOUT, verbose=0)
        te = time.time()
        if reply:
            if reply[ICMP].type == 11 and reply[ICMP].code == 0:
                print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
                tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
            elif reply[ICMP].type == 0:
                print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
                tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
                break
        else:
            print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, UNKNOWN_ADDRESS))
            tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, UNKNOWN_ADDRESS))

def udp_tracert(target):
    udp_port = MIN_UDP_PORT

    for my_ttl in range(MIN_TTL, MAX_TTL):
        packet = IP(dst=target, ttl=my_ttl) / UDP(dport=udp_port)
        ts = time.time()
        reply = sr1(packet, timeout=TIMEOUT, verbose=0)
        te = time.time()
        if reply is None:

            # Force the packet through one of the udp ports
            for port in range(MIN_UDP_PORT, MAX_UDP_PORT):
                new_packet = IP(dst=target, ttl=my_ttl) / UDP(dport=port)
                n_ts = time.time()
                new_reply = sr1(new_packet, timeout=TIMEOUT, verbose=0)
                n_te = time.time()
                if new_reply is None and port == MAX_UDP_PORT:
                    print(HOP_FORMAT.format(my_ttl, (n_te - n_ts) * 1000, UNKNOWN_ADDRESS))
                    tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, UNKNOWN_ADDRESS))
                elif new_reply is None:
                    pass
                else:
                    reply = new_reply
                    break

        if reply.type == 3:
            print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
            tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
            break
        else:
            print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
            tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))

        udp_port += 1

def tcp_tracert(target):
    my_filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))" # https://bitbucket.org/secdev/scapy/src/cd8f482c8858e940959bf9c6c03a8d336db0edaf/scapy/layers/inet.py?at=default&fileviewer=file-view-default#inet.py-1295

    for my_ttl in range(MIN_TTL, MAX_TTL):
        packet = IP(dst=target, ttl=my_ttl) / TCP(dport=DNS_TCP_PORT, flags=SYN_FLAG)
        ts = time.time()
        reply = sr1(packet, timeout=TIMEOUT, filter=my_filter, verbose=0)
        te = time.time()
        if reply is None: # reply.flags == 'R'
            print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, UNKNOWN_ADDRESS))
            tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, UNKNOWN_ADDRESS))
        elif reply.src == target:
            print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
            tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
            break
        else: # reply.flags == 'A'
            print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
            tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))

def save_log(target, log_name, tracert_type):
    if (len(log_name.split('.')) == 1) or (len(log_name.split('.')) == 2 and log_name.split('.')[1] == 'txt'):
        if not os.path.exists('{}.txt'.format(log_name.split('.')[0])):
            with open('{}.txt'.format(log_name.split('.')[0]), 'w+') as log_file:
                log_file.write('{} traceroute from your device to {} at {}\n\n'.format(tracert_type, target, datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
                for hop in tracert_list:
                    log_file.write(hop + '\n')
        else:
            print("{}.txt is already exist.\n"
                  "To avoid overriding files, please enter a file name that isn't taken for the log to be saved in.".format(log_name.split('.')[0]))
    else:
        print("File name is invalid.\n"
              "The log file's name must be one word with or without '.txt'.")

def main():
    tracert_type = ''

    parser = argparse.ArgumentParser(description='Multi-protocol traceroute function. ICMP tracert by default.')
    parser.add_argument('-a', '--address', required=True, help='The targets IP address')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', '--icmp', action='store_true', help='ICMP traceroute')
    group.add_argument('-u', '--udp', action='store_true', help='UDP traceroute')
    group.add_argument('-t', '--tcp', action='store_true', help='TCP traceroute')
    parser.add_argument('-l', '--log', help='Save the results log in a txt file')
    args = parser.parse_args()

    check_if_ip_valid(args.address)

    if args.udp:
        udp_tracert(args.address)
        tracert_type = 'UDP'
    elif args.tcp:
        tcp_tracert(args.address)
        tracert_type = 'TCP'
    else:
        icmp_tracert(args.address)
        tracert_type = 'ICMP'

    if args.log:
        save_log(args.address, args.log, tracert_type)


if __name__ == '__main__':
    main()