#!/bin/python2

import sys
from scapy.all import *

ssids = set()

def PacketHandler(pkt):
    if pkt.haslayer(Dot11Beacon):
        #if (pkt.info not in ssids) and pkt.info:
        #    ssids.add(pkt.info)
        #    print len(ssids), pkt.addr3, pkt.info
        temp = pkt
        while temp:
            temp = temp.getlayer(Dot11Elt)
            if temp and (temp.info not in ssids) and temp.ID == 0:        #As the tagged parameter with id=0 contains the ssid
                ssids.add(temp.info)
                print len(ssids), pkt.addr3, temp.info
                break
            temp = temp.payload


sniff(iface = sys.argv[1], count = int(sys.argv[2]), prn = PacketHandler)
