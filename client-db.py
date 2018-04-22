#!/bin/python2

import sqlite3
import sys
from scapy.all import *


clientprobes = set()

def InsertInDB(mac, ssid):
    connection.execute("insert into clients (location, macaddr, probedssid) values (?,?,?)", (sys.argv[4], mac, ssid))
    connection.commit()

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
                    InsertInDB(pkt.addr2,pkt.info)
                print "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++\n"

connection = sqlite3.connect(sys.argv[3])
sniff(iface = sys.argv[1], count = int(sys.argv[2]), prn = PacketHandler)
connection.close()