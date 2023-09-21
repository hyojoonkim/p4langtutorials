#!/usr/bin/env python3

from scapy.all import *

def main():

    s = ''
    iface = 'eth0'

    for i in range(5):
        try:
            packet = IP(dst="10.0.1.2")/ICMP()
            ans, unans = sr(packet, iface="eth0",  verbose=0)

            rx = ans[0][1]
            tx = ans[0][0]
            host_rtt = (rx.time - tx.sent_time) * 1000
            switch_rtt = rx[IP].id / 1000.0
            
            s += "============================================\n"
            s += "* ICMP RTT reported by host is:   " + str(round(host_rtt, 3)) + " ms\n"
            s += "* ICMP RTT reported by switch is:   " + str(switch_rtt) + " ms\n"
            s += "============================================\n"

            print(s)

            with open("output.txt", "w+") as fd:
                fd.write(s)

        except Exception as error:
            print(error)


if __name__ == '__main__':
    main()
