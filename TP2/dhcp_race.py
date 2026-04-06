from scapy.all import *

def print_it_please(packet):
        if DHCP in packet and packet[DHCP].options[0][1] == 1:
                packet_source = packet['Ether'].src
                discover = packet['UDP']
                print(f"Un petit discover qui arrive  de {packet_source} : {discover}")

                trame = (
                        Ether(dst=packet_source) /
                        IP(src="10.1.20.50", dst="10.1.20.255") /
                        UDP(sport=67, dport=68) /
                        BOOTP(op=2, 
                                yiaddr="10.1.20.250", 
                                siaddr="10.1.20.50", 
                                chaddr=packet[BOOTP].chaddr, 
                                xid=packet[BOOTP].xid) /
                        DHCP(options=[
                                ("message-type", "offer"),
                                ("server_id", "10.1.20.50"),
                                ("lease_time", 3600),
                                ("subnet_mask", "255.255.255.0"),
                                ("router", "10.1.20.254"),
                                 "end"
                        ])
                )
                sendp(trame, iface="eth0", verbose=False)

        if DHCP in packet and packet[DHCP].options[0][1] == 3:
                packet_source = packet['Ether'].src
                trame = (
                        Ether(dst=packet_source) /
                        IP(src="10.1.20.50", dst="10.1.20.255") /
                        UDP(sport=67, dport=68) /
                        BOOTP(op=2, 
                                yiaddr="10.1.20.250", 
                                siaddr="10.1.20.50", 
                                chaddr=packet[BOOTP].chaddr, 
                                xid=packet[BOOTP].xid) /
                        DHCP(options=[
                                ("message-type", "ack"),
                                ("server_id", "10.1.20.50"),
                                ("lease_time", 3600),
                                ("subnet_mask", "255.255.255.0"),
                                ("router", "10.1.20.254"),
                                "end"
                        ])
                )
                sendp(trame, iface="eth0", verbose=False)
sniff(iface="eth0", filter="udp and port 68", prn=print_it_please, store=0)
