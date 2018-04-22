#!/bin/python2

import sys
from scapy.all import *

clientprobes = set()

def PacketHandler(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        if pkt.info:
            probe = pkt.addr2 + '---' + pkt.info
            if probe not in clientprobes:
                clientprobes.add(probe)
                print "New Probe Found: ",pkt.addr2 + "  " + pkt.info
                print "\n+++++++++++++++++Client Probes Table++++++++++++++++\n"
                c = 1
                for cp in clientprobes:
                    [client, ssid] = cp.split("---")
                    print c,client,ssid
                    c += 1
                print "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++\n"

sniff(iface = sys.argv[1], count = int(sys.argv[2]), prn = PacketHandler)