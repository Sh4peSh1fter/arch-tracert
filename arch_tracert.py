# arch_tracert.py
#
# Author: Sean S
#
# Multi-protocol traceroute function using Scapy.

# Good sources:
# - https://www.jasonspencer.org/scribbles/tracey
# - https://gns3.teachable.com/courses/python-network-programming-part-3-scapy-security-tools/lectures/1478199
# - https://stackoverflow.com/questions/53112554/tcp-traceroute-in-python
# - https://stackoverflow.com/questions/24678308/how-to-find-location-with-ip-address-in-python


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
from json import load
from urllib.request import urlopen
import gmplot


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
x_location_list = []
y_location_list = []


def get_location():
    #print(list(map(type, x_location_list)))
    floated_x_location_list = list(map(float, x_location_list))
    floated_y_location_list = list(map(float, y_location_list))

    print(floated_x_location_list)
    print(floated_y_location_list)

    gmap = gmplot.GoogleMapPlotter(0, 0, 2)
    gmap.heatmap(floated_x_location_list, floated_y_location_list)
    gmap.scatter(floated_x_location_list, floated_y_location_list, '# FF0000', size=100000, marker=False)
    gmap.plot(floated_x_location_list, floated_y_location_list, 'cornflowerblue', edge_width=2.5)
    gmap.draw("tracert_map.html")


def get_info(ip_address, map=False):
    """
    Returns information of the given IP address.
    """
    url = 'https://ipinfo.io/' + ip_address + '/json'
    response = urlopen(url)
    data = load(response)
    info = "~~~~~~~~~~~~~~~~~~~~~\nInformation about {}:\n".format(ip_address)

    if map:
        for attr in data.keys():
            if attr == "loc":
                x, y = data[attr].split(",")
                x_location_list.append(x)
                y_location_list.append(y)
    else:
        print("~~~~~~~~~~~~~~~~~~~~~\n"
              "Information about {}:".format(ip_address))
        for attr in data.keys():
            if attr == "readme" or attr == "bogon":
                continue
            # will print the data line by line
            print("{}:    {}".format(attr, data[attr]))
            info += "{}: \t {}\n".format(attr, data[attr])
            #print(attr, ' ' * 13 + '\t->\t', data[attr])
        print("~~~~~~~~~~~~~~~~~~~~~\n")
        info += "~~~~~~~~~~~~~~~~~~~~~\n"

        return info


def check_if_ip_valid(target):
    try:
        #socket.inet_aton(target)
        ipaddress.ip_address(target)
        #print("Great! this IP is valid.")
    #except socket.error:
    except ValueError:
        print("Seems like this IP isn't valid...\n")
        exit()


def icmp_tracert(target, detail_flag):
    for my_ttl in range(MIN_TTL, MAX_TTL):
        packet = IP(dst=target, ttl=my_ttl) / ICMP()
        ts = time.time()
        reply = sr1(packet, timeout=TIMEOUT, verbose=0)
        te = time.time()
        if reply:
            if reply[ICMP].type == 11 and reply[ICMP].code == 0:
                print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
                tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))

                if detail_flag:
                    get_info(reply.src)
            elif reply[ICMP].type == 0:
                print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
                tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))

                if detail_flag:
                    get_info(reply.src)
                break
        else:
            print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, UNKNOWN_ADDRESS))
            tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, UNKNOWN_ADDRESS))

def udp_tracert(target, detail_flag):
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

            if detail_flag:
                get_info(reply.src)

            break
        else:
            print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
            tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))

            if detail_flag:
                get_info(reply.src)

        udp_port += 1

def tcp_tracert(target, detail_flag):
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

            if detail_flag:
                get_info(reply.src)

            break
        else: # reply.flags == 'A'
            print(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))
            tracert_list.append(HOP_FORMAT.format(my_ttl, (te - ts) * 1000, reply.src))

            if detail_flag:
                get_info(reply.src)

def save_log(target, log_name, tracert_type, detail_flag):
    if (len(log_name.split('.')) == 1) or (len(log_name.split('.')) == 2 and log_name.split('.')[1] == 'txt'):
        if not os.path.exists('{}.txt'.format(log_name.split('.')[0])):
            with open('{}.txt'.format(log_name.split('.')[0]), 'a') as log_file:

                if detail_flag:
                    log_file.write('Detailed Tracert\n'
                                   '~~~~~~~~~~~~~~~~')

                log_file.write('{} traceroute from your device to {} at {}\n\n'.format(tracert_type, target, datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
                for hop in tracert_list:
                    log_file.write(hop + '\n')
                    if detail_flag:
                        ip = hop.split(" ")[-1]
                        if "*" not in ip:
                            log_file.write(get_info(ip))
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
    parser.add_argument('-d', '--detail', action='store_true', help='Print more details about each ip in the tracert result')
    parser.add_argument('-m', '--map', action='store_true', help='Maps the ip addresses by their geographical location')
    args = parser.parse_args()

    check_if_ip_valid(args.address)

    if args.udp:
        udp_tracert(args.address, args.detail)
        tracert_type = 'UDP'
    elif args.tcp:
        tcp_tracert(args.address, args.detail)
        tracert_type = 'TCP'
    else:
        icmp_tracert(args.address, args.detail)
        tracert_type = 'ICMP'

    if args.log:
        save_log(args.address, args.log, tracert_type, args.detail)

    if args.map:
        for hop in tracert_list:
            ip = hop.split(" ")[-1]
            if "*" not in ip:
                get_info(ip, True)
        get_location()


if __name__ == '__main__':
    main()