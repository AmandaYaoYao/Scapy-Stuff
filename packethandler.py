#!/bin/python2

import sys
from scapy.all import *

def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        print pkt.summary()
    else:
        print "Not an 802.11 packet!"

sniff(iface = sys.argv[1], count = int(sys.argv[2]), prn= PacketHandler)


