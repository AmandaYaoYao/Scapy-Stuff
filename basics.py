from scapy.all import *

#finding protocols and details
ls()
lsc()
conf
IP().show

#sniffing packets
pkts = sniff(iface="enp7s0", count=3)
hexdump()

#simulating sniffing with an offline pcap capture
pkts = sniff(offline="offline.pcap")

#adding filters with support of BPF(berkley packet filters)
pkts = sniff(ifcae="enp7s0", count=3, filter="arp")

#print packets live 
pkts = sniff(ifcae="enp7s0", count=3, filter="icmp", prn=lambda x: x.summary())

#reading and writing packets to a pcap file
wrpcap("demo.pcap", pkts)
readpkts = rdpcap("demo.pcap")

#exporting and importing packets as base64
icmp_str = str(pkts[0])
recon = Ether(icmp_str)

export_object(icmp_str) #base64 encoding 
new_pkt = import_object() #enter the base64 encoded pkt, it will decode automatically
Ether(new_pkt)

#packet creation
# simply remember this  ----    '''  Ether() / IP() / TCP() / DATA '''
pkt = IP(dst="google.com") / ICMP() / "Root is here XD"
send(pkt) #sends at L3

#scapy injection and forging
sendp(Ether() / IP(dst="google.com", ttl=22) / ICMP() / "XXX", iface="wlp6s0", loop=1, inter=1)

#send and receive ......sr(L3) and srp(L2) are corallary with send(L3) and sendp(L2)
srp(Ether() / IP(dst="google.com", ttl=22) / ICMP() / "XXX")
response, no_response = _                 # _ takes the result of last call ....note that srp1(or sr1) 
                                          #will contain only a single field or only 1 single response
sr(IP(dst="google.com"), timeout=5)    #without timeout it will continue infinitely as just a IP pkt 
                                        #can't initiate anything to get a response
    #in '''srp/srp1''' u have to construct a extra Ether frame .....this is not the case in '''sr/sr1'''   

conf.route #will give the routing table of ur machine 
conf.route.add(host="192.168.0.12", gw="192.168.0.14") #can add routes on fly XD 
conf.route.resync() #back to ur machine's routing table