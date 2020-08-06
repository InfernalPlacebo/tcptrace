#! /usr/bin/env python

import sys
import socket

import argparse
from scapy.all import sr1, conf
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, ICMP, TCP, UDP
from pyfiglet import Figlet
from termcolor import colored, cprint

# List used to store the hops during trace.
hops = []
# Sets scapy to 0 verbosity
conf.verb = 0
# Preloads the args variable
args = None


def ping(dst):
    """Pings the specified host.

    :param dst: The hostname or IP of the host to ping.
    """

    i = 1
    while i < 5:
        i += 1
        p = sr1(IP(dst=dst)/TCP(sport=80))
        if p:
            p.show()


def trace_tcp(dst, ttl, num, dport):
    """Begins the TCP traceroute to the specified host.

    :param dst: The hostname or IP of the host to trace.
    :param ttl: Maximum number of hops.
    :param num: Which hop number the trace is on.
    :param dport: The port to be using during the trace.
    :return:
    """

    global hops

    if ttl >= num:
        p = sr1(IP(dst=dst, ttl=num) / TCP(dport=dport))
        if p:
            if p.src in hops:
                output()
                return
            hops.append(p.src)
            if ttl > 1:
                num += 1
                trace_tcp(dst, ttl, num, dport)
    else:
        output()


def trace_udp(dst, ttl, num, dport):
    """Begins the UDP traceroute to the specified host.

    :param dst: The hostname or IP of the host to trace.
    :param ttl: Maximum number of hops.
    :param num: Which hop number the trace is on.
    :param dport: The port to be using during the trace.
    :return:
    """

    global hops

    if ttl >= num:
        p = sr1(IP(dst=dst, ttl=num) / UDP(dport=dport))
        if p:
            if p.src in hops:
                output()
                return
            hops.append(p.src)
            if ttl > 1:
                num += 1
                trace_udp(dst, ttl, num, dport)
    else:
        output()


def trace_icmp(dst, ttl, num):
    """Begins the ICP traceroute to the specified host.

    :param dst: The hostname or IP of the host to trace.
    :param ttl: Maximum number of hops.
    :param num: Which hop number the trace is on.
    :param dport: The port to be using during the trace.
    :return:
    """

    global hops

    if ttl >= num:
        p = sr1(IP(dst=dst, ttl=num) / ICMP())
        if p:
            if p.src in hops:
                output()
                return
            hops.append(p.src)
            if ttl > 1:
                num += 1
                trace_icmp(dst, ttl, num)
    else:
        output()


def output():
    """Prints the output of the hops."""

    global hops

    i = 1
    for hop in hops:
        domain = 'Not Found'
        try:
            domain = socket.gethostbyaddr(hop)[0]
        except socket.error:
            pass
        finally:
            print(f'{i}     {hop}       {domain}')

        i += 1


def head():
    """Displays the ASCII header."""

    header = Figlet(font='slant')
    print(colored(header.renderText('TCPTrace'), 'cyan'))


def menu():
    """Displays the interactive menu."""

    pass


def arguments():
    """Loads the arguments and calls the header function."""

    global args

    # Displays ASCII header
    head()

    parser = argparse.ArgumentParser(description='Network Diagnostics Toolkit.')
    parser.add_argument('--host', '-i', type=str, help='Host to trace')
    parser.add_argument('--dport', '-dp', help='Specify the destination port. Default: 80', default=80, type=int)
    # parser.add_argument('--sport', '-sp', help='Specify the source port.', type=int)
    parser.add_argument('--proto', '-p', type=str, help='Specify the networking protocol.', default='TCP')
    parser.add_argument('--ttl', '-t', help='Maximum number of jumps. Default: 30', default=30, type=int)
    parser.add_argument('--menu', '-m', help='Use interactive menu.', action='store_true')
    parser.add_argument('--license', '-l', help="Display the license information.", action='store_true')
    parser.add_argument('--github', '-g', help="Display the GitHub repository.", action='store_true')

    args = parser.parse_args()


def license():
    """Displays the license information."""

    pass


if __name__ == "__main__":
    arguments()

    if len(sys.argv) == 1:
        print('Please include arguments. "-m" for interactive mode or "-h" for help.')
    else:
        # noinspection PyUnresolvedReferences
        if args.menu:
            menu()
        elif args.license:
            print('GPL-3.0 License')
            print('https://github.com/InfernalPlacebo/tcptrace/blob/master/LICENSE')
        elif args.github:
            print("https://github.com/InfernalPlacebo/tcptrace")
        else:
            # noinspection PyUnresolvedReferences
            if args.proto.upper() == 'TCP':
                # noinspection PyUnresolvedReferences
                print(f'Beginning TCP traceroute on port {args.dport}')
                # noinspection PyUnresolvedReferences
                trace_tcp(args.host, args.ttl, 1, args.dport)
            elif args.proto.upper() == 'UDP':
                # noinspection PyUnresolvedReferences
                print(f'Beginning UDP traceroute on port {args.dport}')
                # noinspection PyUnresolvedReferences
                trace_udp(args.host, args.ttl, 1, args.dport)
            elif args.proto.upper() == 'ICMP':
                # noinspection PyUnresolvedReferences
                print(f'Beginning ICMP traceroute')
                # noinspection PyUnresolvedReferences
                trace_icmp(args.host, args.ttl, 1)
