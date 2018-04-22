#!/bin/python2

import sys
from scapy.all import *

hiddenssids = set()
def PacketHandler(pkt):
    if pkt.haslayer(Dot11Beacon):
        if not pkt.info:
            if pkt.addr3 and (pkt.addr3 not in hiddenssids):    #addr2 is client's macid whereas addr3 is AP's macid
                hiddenssids.add(pkt.addr3)
                print "AP with a hidden ssid found -- BSSID: "+  pkt.addr3
    elif pkt.haslayer(Dot11ProbeResp) and pkt.addr3 in hiddenssids:
        print "Hidden SSID Uncovered ",pkt.info,pkt.addr3

sniff(iface = sys.argv[1], count = sys.argv[2], prn = PacketHandler)
