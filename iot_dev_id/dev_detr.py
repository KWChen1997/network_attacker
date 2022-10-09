#!/usr/bin/env python3

# ----- Abbreviations -----
# tc: Trace Collector
# vfyr: Verifier
# -----

# Must import Scapy packages before select.
from scapy.all import *
import sys, os, signal, socket, select, time
import vfyr

CMD_STOP = b'\x00'
CMD_RECNCT = b'\x01'
CMD_PRED = b'\x02'
CMD_CLS = b'\x00\x00\x00\x00'
CMD_VFY = b'\x00\x00\x00\x01'

WIFI = 'wlp0s20f3' # Wi-Fi interface
MAC = 'dc:21:48:59:c4:00' # MAC address of Wi-Fi interface
CLD_ADDR = '127.0.0.1'
CLD_PORT = 2000
OFF_TIME = 10 # Offine time in seconds before reconnection

stop = False

# Dictionary of Device Workers
# Key: socket object to Device Worker
# Value: [MAC address, Starting time of disconnetion]
wkrs = dict()

def hdlr(sig, frm):
    global stop
    stop = True

def recnct(sig, frm):
    global wkrs

    cur = time.time()
    for wkr in wkrs:
        info = wkrs[wkr]
        if info[1] != 0.0 and cur - info[1] >= OFF_TIME:
            #os.system('hostapd_cli deny_acl DEL_MAC {} > /dev/null'.format(info[0]))
            os.system('aireplay-ng -0 3  -a 1c:ab:c0:fa:d2:d8  -c {} -D wlx1c61b463d19a > /dev/null'.format(info[0]))
            print('<Device Detector> Allow device [{}] to reconnect to Wi-Fi network.'.format(info[0]))
            info[1] = 0.0

# Forward captured packets from Trace Collector to Device Dectector.
def wrt_pkt(pkt):
    if pkt.haslayer(Ether):
        # How many bytes packet contains is specified first.
        sys.stdout.buffer.write(len(bytes(pkt)).to_bytes(4, 'big'))
        sys.stdout.buffer.write(bytes(pkt))

def new_dev(mac, fds, devs):
    global wkrs

    print('<Device Detector> New device [{}] is online.'.format(mac))
    wkr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wkr.connect((CLD_ADDR, CLD_PORT))
    print('<Device Detector> Connect to Cloud [{}:{}] for identification of device [{}].'.format(CLD_ADDR, CLD_PORT, mac))
    fds.register(wkr.fileno(), select.EPOLLIN)
    devs[mac] = [None, None, None]
    # If file descriptor of socket is used as key, socket will be closed automatically after function returns.
    wkrs[wkr] = [mac, 0.0]
    wkr.send(mac.encode())

def discnct(wkr):
    global wkrs

    mac = wkrs[wkr][0]
    os.system('aireplay-ng -0 3  -a 1c:ab:c0:fa:d2:d8  -c {} -D wlx1c61b463d19a > /dev/null'.format(mac))
    # Make sure device is disconnected from Wi-Fi network.
    os.system('aireplay-ng -0 3  -a 1c:ab:c0:fa:d2:d8  -c {} -D wlx1c61b463d19a > /dev/null'.format(mac))
    print('<Device Detector> Disconnect device [{}] from Wi-Fi network.'.format(mac))
    wkrs[wkr][1] = time.time()
    signal.alarm(OFF_TIME)

def end_dev(wkr, fds):
    global wkrs

    print('<Device Detector> Analysis of device [{}] is finished.'.format(wkrs[wkr][0]))
    wkr.send(CMD_CLS)
    del wkrs[wkr]
    fds.unregister(wkr.fileno())
    wkr.close()
    print('<Device Detector> Disconnect from Cloud [{}:{}].'.format(CLD_ADDR, CLD_PORT))

def main():
    detr2vfyr_rd, detr2vfyr_wrt = os.pipe()
    vfyr2detr_rd, vfyr2detr_wrt = os.pipe()
    vfyr_pid = os.fork()
    # ----- Verifier -----
    if vfyr_pid == 0:
        os.close(detr2vfyr_wrt)
        os.close(vfyr2detr_rd)
        vfyr.run(detr2vfyr_rd, vfyr2detr_wrt)
        os.close(detr2vfyr_rd)
        os.close(vfyr2detr_wrt)
        sys.exit(0)
    # -----

    tc_rd, tc_wrt = os.pipe()
    tc_pid = os.fork()
    # ----- Trace Collector -----
    if tc_pid == 0:
        os.close(detr2vfyr_rd)
        os.close(detr2vfyr_wrt)
        os.close(vfyr2detr_rd)
        os.close(vfyr2detr_wrt)
        # Print log before dup2() so that log is not sent to pipe.
        print('<Trace Collector> Collecting network traffic ...')
        os.dup2(tc_wrt, sys.stdout.fileno())
        os.close(tc_rd)
        os.close(tc_wrt)
        sniff(prn=wrt_pkt, iface=WIFI)
        # Do not close pipe this way: os.close(sys.stdout.fileno())
        sys.stdout.close()
        sys.exit(0)
    # -----
    else:
        os.close(detr2vfyr_rd)
        os.close(vfyr2detr_wrt)
        os.close(tc_wrt)

        signal.signal(signal.SIGINT, hdlr)
        signal.signal(signal.SIGALRM, recnct)

        # Dictionary of devices that have been detected
        # Key: MAC address
        # Value: [Type, Manufacturer, Model]
        devs = dict()
        devs[MAC] = ['Laptop', 'CJSCOPE', 'mars_15g']

        fds = select.epoll()
        fds.register(vfyr2detr_rd, select.EPOLLIN)
        fds.register(tc_rd, select.EPOLLIN)

        while stop == False:
            evnts = fds.poll()
            for fd, evnt in evnts:
                if fd == tc_rd:
                    # TODO: how to make sure os.read() always reads specified bytes of data before returning?
                    n = os.read(tc_rd, 4)
                    raw = os.read(tc_rd, int.from_bytes(n, 'big'))
                    # ----- Check if new device is connecting to Wi-Fi network. -----
                    pkt = Ether(raw)
                    if pkt.haslayer(DHCP) and pkt[Ether].src not in devs:
                    #if pkt[Ether].src not in devs:
                        new_dev(pkt[Ether].src, fds, devs)
                    # ----- Forward packet from Trace Collector to all Device Workers on Cloud. -----
                    for wkr in wkrs:
                        wkr.send(n)
                        wkr.send(raw)
                    # -----
                elif fd == vfyr2detr_rd:
                    mac = os.read(vfyr2detr_rd, 17).decode()
                    dev = devs[mac]
                    for wkr in wkrs:
                        if wkrs[wkr][0] == mac:
                            wkr.send(CMD_VFY)
                            # ----- Forward verification result from Verifier to Device Worker. -----
                            for i in range(len(dev)):
                                n = os.read(vfyr2detr_rd, 1)
                                wkr.send(n)
                                if n != b'\x00': # Prediction is wrong.
                                    dev[i] = os.read(vfyr2detr_rd, int.from_bytes(n, 'big')).decode()
                                    wkr.send(dev[i].encode())
                            # -----
                            break
                else:
                    for wkr in wkrs:
                        if wkr.fileno() == fd:
                            # Must specify option MSG_WAITALL, otherwise # of received bytes might be less than expected.
                            cmd = wkr.recv(1, socket.MSG_WAITALL)
                            if cmd == CMD_RECNCT:
                                discnct(wkr)
                            elif cmd == CMD_STOP:
                                end_dev(wkr, fds)
                            elif cmd == CMD_PRED:
                                mac = wkrs[wkr][0]
                                dev = devs[mac]
                                os.write(detr2vfyr_wrt, mac.encode())
                                # ----- Forward predicted labels of device from Device Worker to Verifier. -----
                                for i in range(len(dev)):
                                    n = wkr.recv(1, socket.MSG_WAITALL)
                                    dev[i] = wkr.recv(int.from_bytes(n, 'big'), socket.MSG_WAITALL).decode()
                                    os.write(detr2vfyr_wrt, n)
                                    os.write(detr2vfyr_wrt, dev[i].encode())
                                # -----
                            break
        # ----- Finalization -----
        # TODO: all file descriptors to Device Workers should be unregistered.
        fds.unregister(vfyr2detr_rd)
        fds.unregister(tc_rd)
        fds.close()

        # TODO: all socket connections should be closed.

        # (Ctrl + C) sends SIGINT to both parent and child processes, so no need to send another signal to terminate child process.
        os.waitpid(vfyr_pid, 0)
        os.close(detr2vfyr_wrt)
        os.close(vfyr2detr_rd)

        os.waitpid(tc_pid, 0)
        os.close(tc_rd)
        # -----
        sys.exit(0)

main()
