import os, socket, csv
from scapy.all import *
from feat import *

load_layer('tls')

THOLD_SU = 20
THOLD_DNS = 2
CNT = 3 # # of reconnection traces to collect (Not including first factory-reset trace.)

CMD_STOP = b'\x00'
CMD_RECNCT = b'\x01'
CMD_PRED = b'\x02'
CMD_CLS = b'\x00\x00\x00\x00'
CMD_VFY = b'\x00\x00\x00\x01'

PTH_TMP = './tmp' # Path of directory for temporary pcap files

PROXY_ADDR = '127.0.0.1'
PROXY_PORT = 2001

def pred(proxy, lbls, cli):
    proxy.send(CMD_PRED)
    proxy.send(os.getpid().to_bytes(3, 'big'))

    cli.send(CMD_PRED)

    for i in range(len(lbls)):
        # ----- Receive predicted labels from Classification Proxy. -----
        n = proxy.recv(1, socket.MSG_WAITALL)
        lbls[i] = proxy.recv(int.from_bytes(n, 'big'), socket.MSG_WAITALL).decode()
        # ----- Send predicted labels to Device Detector for user verification. -----
        cli.send(n)
        cli.send(lbls[i].encode())
        # -----

def vfy(cli, lbls, mac):
    err = 0 # Indicate which layer of predictions is erroneous.

    for i in range(len(lbls)):
        n = cli.recv(1, socket.MSG_WAITALL)
        if n != b'\x00': # Prediction is wrong.
            lbls[i] = cli.recv(int.from_bytes(n, 'big'), socket.MSG_WAITALL).decode()
            if err == 0:
                err = i + 1
    if err == 0:
        print('<Device Worker> Predicted labels of device [{}] are correct!'.format(mac))
    else:
        print('<Device Worker> Predicted labels of device [{}] are wrong.\n-> Correct labels: {}'.format(mac, lbls))
    return err

def run(cli):
    rec = False
    cnt = 0
    err = int()
    strt = float()
    dns = float() # Time of last DNS packet
    lbls = [None, None, None]
    wrtr_pcap = None
    # ----- Feature-related variables -----
    oths = 0 # # of packets from device but not of interest
    protos = [0]*len(Proto)
    feat_cnts = [0]*len(Feat)
    feats = [0]*NUM_FEAT
    # -----
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    feats_f = open('{}/{}.csv'.format(PTH_TMP, os.getpid()), 'w')
    wrtr_csv = csv.writer(feats_f)

    mac = cli.recv(17, socket.MSG_WAITALL).decode()
    print('<Device Worker> Ready to analyze network traffic of device [{}] ...'.format(mac))

    while True:
        # First 4 bytes of data may indicate # of bytes of packet or commands.
        tmp = cli.recv(4, socket.MSG_WAITALL)
        if tmp == CMD_CLS:
            break
        elif tmp == CMD_VFY:
            err = vfy(cli, lbls, mac)
            if err == 0: # Predicted labels are correct.
                cli.send(CMD_STOP)
                # Do not immediately close connection, because client keeps forwarding packets before receiving STOP command.
            else: # Predicted labels are incorrect.
                # ----- Open same csv file again to append more feature vectors for training. -----
                feats_f = open('{}/{}.csv'.format(PTH_TMP, os.getpid()), 'a')
                wrtr_csv = csv.writer(feats_f)
                # -----
                cli.send(CMD_RECNCT)
            continue
        n = int.from_bytes(tmp, 'big')
        pkt = Ether(cli.recv(n, socket.MSG_WAITALL))

        if rec:
            if pkt.time - strt > THOLD_SU and pkt.time - dns > THOLD_DNS: # Set-up is considered as finished.
                wrtr_pcap.close()
                rec = False
                print('<Device Worker> Set-up of device [{}] is finished. Duration < {} sec.'.format(mac, pkt.time - strt))
                # ----- Store features extracted from all but factory-reset traces. -----
                if cnt != 0:
                    smrz_feats(feats, protos, feat_cnts, oths)
                    wrtr_csv.writerow(feats)
                # -----
                if cnt != CNT:
                    if cnt == 1:
                        # Close csv file so that Classification Proxy can open it for reading.
                        feats_f.close()
                        proxy.connect((PROXY_ADDR, PROXY_PORT))
                        print('<Device Worker> Connect to Classification Proxy [{}:{}] to predict labels of device [{}].'.format(PROXY_ADDR, PROXY_PORT, mac))
                        pred(proxy, lbls, cli)
                        proxy.close()
                    else:
                        cli.send(CMD_RECNCT)
                    # ----- Reset statistics for next iteration. -----
                    cnt += 1
                    oths = 0
                    for i in range(len(protos)):
                        protos[i] = 0
                    for i in range(len(feat_cnts)):
                        feat_cnts[i] = 0
                    for i in range(len(feats)):
                        feats[i] = 0
                    # -----
                else:
                    feats_f.close()
                    cli.send(CMD_STOP)
                    # Do not immediately close connection, because client keeps forwarding packets before receiving STOP command.
                continue
            if pkt.haslayer(DNS) and pkt[Ether].src == mac:
                dns = pkt.time
            wrtr_pcap.write(pkt)
            # ----- Extract features once packets arrive. -----
            if pkt[Ether].src == mac:
                oths += 1
                prs_pkt(pkt, protos, feat_cnts, feats)
            # -----
        elif pkt.haslayer(DHCP) and pkt[Ether].src == mac:
            print('<Device Worker> Device [{}] is online.'.format(mac))
            rec = True
            strt = pkt.time
            # TODO: use pcapng file format instead of pcap.
            wrtr_pcap = PcapWriter('{}/{}-{}.pcap'.format(PTH_TMP, os.getpid(), cnt))
            print('<Device Worker> Writing network trace of device [{}] to file [{}/{}-{}.pcap] ...'.format(mac, PTH_TMP, os.getpid(), cnt))
            wrtr_pcap.write(pkt)
            # ----- Extract features once packets arrive. -----
            if pkt[Ether].src == mac:
                oths += 1
                prs_pkt(pkt, protos, feat_cnts, feats)
            # -----
