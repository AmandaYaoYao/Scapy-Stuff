#!/bin/python2

import sys
from scapy.all import *

mymac = "aa:bb:cc:aa:bb:cc"
brdmac = "ff:ff:ff:ff:ff:ff"

for ssid in open(sys.argv[1],'r').readlines():
    pkt = RadioTap() / Dot11(type = 0, subtype = 4, addr1 = brdmac, addr2 = mymac, addr3 = brdmac) / Dot11ProbeReq() / Dot11Elt(ID=0, info=ssid.strip()) / Dot11Elt(ID=1, info="\x02\x04\x0b\x16") / Dot11Elt(ID=3, info="\x01")
    print "Trying SSID: ",ssid
    sendp(pkt, iface="wlp6s0mon", count=3, inter=0.3)
