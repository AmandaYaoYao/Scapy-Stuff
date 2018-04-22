#!/bin/python2

import sys
from scapy.all import *

macs = set()
def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        dot11packet = pkt.getlayer(Dot11)           #we can directly use pkt.addr2 XD
        if dot11packet.addr2 and (dot11packet.addr2 not in macs):
            macs.add(dot11packet.addr2)
            print len(macs), dot11packet.addr2, dot11packet.payload.name


sniff(iface = sys.argv[1], count = int(sys.argv[2]), prn = PacketHandler)
