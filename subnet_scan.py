from scapy.all import *

for lsb in range(1,50):
    ip = "192.168.0." + str(lsb)
    arpRequest = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
    arpResponse = srp1(arpRequest, timeout=1, verbose=0)
    if arpResponse:
        print("IP: {} MAC: {}".format(arpResponse.psrc,arpResponse.hwsrc))