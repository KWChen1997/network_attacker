#!/usr/bin/env python3

import sys, os, signal
from scapy.all import *

SIZE_PKT = 4
THOLD_COLL = 120
THOLD_DNS = 10
NUM_TRACES = (3 - 1) + 36
# OFF_TIME = 90

TYPE = 'cam'
MFR = 'd_link'
MDL = 'dcs_8600lh'
MAC = 'b0:c5:54:58:af:d5'

def wrt_pkt(pkt):
    if pkt.haslayer(Ether):
        # Write size of packet first.
        sys.stdout.buffer.write(len(bytes(pkt)).to_bytes(SIZE_PKT, 'big'))
        sys.stdout.buffer.write(bytes(pkt))

def recnct(sig, frm):
    os.system('hostapd_cli deny_acl DEL_MAC {} > /dev/null'.format(MAC))
    print('Allow device [{}] to reconnect to Wi-Fi AP.'.format(MAC))

def main():
    rd, wrt = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.dup2(wrt, sys.stdout.fileno())
        os.close(rd)
        os.close(wrt)
        # Capture packets on specified network interface.
        sniff(prn=wrt_pkt, iface='wlp0s20f3')
        os.close(sys.stdout.fileno())
        os._exit(0)
    else:
        rec = False
        num = 36 # Trace 0 is collected from device with factory settings.
        strt = float()
        dns = float() # Time of last DNS packet
        wrtr = None

        os.close(wrt)
        # signal.signal(signal.SIGALRM, recnct)
        while True:
            # Read size of packet first.
            n = int.from_bytes(os.read(rd, SIZE_PKT), 'big')
            pkt = Ether(os.read(rd, n))
            if rec:
                if pkt.time - strt > THOLD_COLL and pkt.time - dns > THOLD_DNS: # Set-up of device is finished.
                    wrtr.close()
                    print('Finish writing trace to file [../trn/{}/{}/{}-{}.pcap].'.format(TYPE, MFR, MDL, num))
                    print('Set-up duration < {} sec.'.format(pkt.time - strt))
                    if num == NUM_TRACES:
                        break
                    num += 1
                    rec = False
                    # os.system('hostapd_cli deny_acl ADD_MAC {} > /dev/null'.format(MAC))
                    # Make sure device is disconnected from Wi-Fi AP.
                    # os.system('hostapd_cli disassociate {} > /dev/null'.format(MAC))
                    # print('Disconnect device [{}] from Wi-Fi AP.'.format(MAC))
                    # signal.alarm(OFF_TIME)
                    print('Waiting to start next iteration ...')
                    continue
                if pkt.haslayer(DNS) and pkt[Ether].src == MAC:
                    dns = pkt.time
                wrtr.write(pkt)
            elif pkt.haslayer(EAPOL) and pkt[Ether].dst == MAC:
                print('Device [{}] is online. Collecting its set-up network trace ...'.format(MAC))
                strt = pkt.time
                rec = True
                wrtr = PcapWriter('../trn/{}/{}/{}-{}.pcap'.format(TYPE, MFR, MDL, num))
                wrtr.write(pkt)
        os.kill(pid, signal.SIGINT)
        os.waitpid(pid, 0)

main()
