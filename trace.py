#! /usr/bin/env python

import sys

import argparse
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from pyfiglet import Figlet
from termcolor import colored, cprint

hops = []
conf.verb = 0
args = None

def ping(dst):
    i = 1
    while i < 5:
        i += 1
        p = sr1(IP(dst=dst)/TCP(sport=80))
        if p:
            p.show()


def trace(dst, ttl, num, dport):
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
                trace(dst, ttl, num, dport)
    else:
        output()


def output():
    global hops

    print(hops)


def head():
    header = Figlet(font='slant')
    print(colored(header.renderText('TCPTrace'), 'cyan'))


def menu():
    pass


def arguments():
    global args

    # Displays ASCII header
    head()

    parser = argparse.ArgumentParser(description='Network Diagnostics Toolkit.')
    parser.add_argument('--host', '-i', type=str, help='Host to trace')
    parser.add_argument('--dport', '-dp', help='Specify the destination port. Default: 80', default=80, type=int)
    # parser.add_argument('--sport', '-sp', help='Specify the source port.', type=int)
    parser.add_argument('--ttl', '-t', help='Maximum number of jumps. Default: 30', default=30, type=int)
    parser.add_argument('--menu', '-m', help='Use interactive menu.', action='store_true')
    # parser.add_argument('--license', '-l', help="Display the license information.", action='store_true')
    parser.add_argument('--github', '-g', help="Display the GitHub repository.", action='store_true')

    args = parser.parse_args()


def license():
    pass


if __name__ == "__main__":
    arguments()

    if len(sys.argv) == 1:
        print('Please include arguments. "-m" for interactive mode or "-h" for help.')
    else:
        if args.menu:
            menu()
        elif args.license:
            license()
        elif args.github:
            print("Github, yo")
        else:
            trace(args.host, args.ttl, 1, args.dport)
