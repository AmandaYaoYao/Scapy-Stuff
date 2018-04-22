#!/bin/python2

import sys
from scapy.all import *

mymac = "aa:bb:cc:aa:bb:cc"

pkt = RadioTap() / Dot11(type = 0, subtype = 5, addr1 = mymac, addr2 = sys.argv[1], addr3 = sys.argv[1]) / Dot11ProbeResp() / Dot11Elt(ID=0, info="Cloaked!" / Dot11Elt(ID=1, info="\x02\x04\x0b\x16") / Dot11Elt(ID=3, info="\x01")
sendp(pkt, iface="wlp6s0mon", count=int(sys.argv[2]), inter=0.3)
