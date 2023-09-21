#!/usr/bin/env python3


from scapy.all import (
    Ether,
    IntField,
    Packet,
    StrFixedLenField,
    XByteField,
    bind_layers,
    srp1
)


class P4rps(Packet):
    name = "P4rps"
    fields_desc = [ XByteField("version", 0x01),
                    XByteField("human_choice", 0x01),
                    XByteField("switch_choice", 0x00),
                    XByteField("error", 0x00)]

bind_layers(Ether, P4rps, type=0x1234)

class Token:
    def __init__(self,type,value = None):
        self.type = type
        self.value = value

def check_and_convert(s):
    version = 0
    choice = 0
    s_list = s.split(' ')
    if s_list[0] == 'v1' or s_list[0] == 'v2':
        version = int(s_list[0][1])
        hand = s_list[1].lower()
        if hand == 'rock':
            choice = 1
        elif hand == 'paper':
            choice = 2
        elif hand == 'scissors':
            choice = 3

    return version,choice

def parse_resp(p4rps):
    switch_choice = 'Nothing'

    if p4rps.switch_choice == 1:
        switch_choice = 'rock'
    elif p4rps.switch_choice == 2: 
        switch_choice = 'paper'
    elif p4rps.switch_choice == 3:
        switch_choice = 'scissors'

    return switch_choice

def main():

    s = ''
    iface = 'eth0'

    while True:
        s = input('> ')
        if s == "quit":
            break
        print("You entered:", s)
        hand_str = ''
        ver, hand = check_and_convert(s)
        if hand == 0:
            print("Wrong format. Enter version number ('v1' or 'v2'), followed by your choice ('rock', 'paper', or 'scissors')")
            continue
        hand_str = s[3:]
        try:
            pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / P4rps(version=ver,human_choice=hand)
            pkt = pkt/' '
            
            print("======= Host Send =======")
            pkt.show()

            resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
            if resp:
                p4rps=resp[P4rps]
                if p4rps:
                    if p4rps.error:
                        print("Something went wrong. Switch responded with an error. Maybe you used an unsupported version by the switch.")
                    else:
                        print("======= Switch Response =======")
                        resp.show()
                        switch_choice = parse_resp(p4rps)
                        print("Your hand was:        ", hand_str)
                        print("The switch's hand was:", switch_choice)
                else:
                    print("cannot find P4rps header in the packet")
            else:
                print("Didn't receive response")
        except Exception as error:
            print(error)


if __name__ == '__main__':
    main()
