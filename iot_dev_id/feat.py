import sys, os, csv, re
from enum import Enum
from scapy.all import *
from scapy.contrib.mqtt import *

# Load Scapy TLS package.
load_layer('tls')

# TODO: find a better way to handle non-standard port parsing.
bind_layers(TCP, TLS, dport=853) # DNS over TLS (DoT): Facebook display
bind_layers(TCP, TLS, dport=2686) # SpotCam camera, SpotCam doorbell
bind_layers(TCP, TLS, dport=5223) # BAZZ siren, Philips socket, S-Butler socket, Emerson thermostat, TP-Link camera, Apple smartphone
bind_layers(TCP, TLS, dport=5228) # Google speaker
bind_layers(TCP, TLS, dport=5429) # SpotCam doorbell
bind_layers(TCP, TLS, dport=8091) # Emerson thermostat
bind_layers(TCP, TLS, dport=8443) # Belkin socket, Belkin sensor, Wyze camera, ASUS speaker
bind_layers(TCP, TLS, dport=8883) # Wyze lock, Philips socket, Wyze camera, ASUS speaker
bind_layers(TCP, TLS, dport=8886) # S-Butler socket, Atomi Smart coffee machine
bind_layers(TCP, TLS, dport=56700) # LIFX light bulb

class Tgt(Enum):
    TYPE = 0
    MFR = 1
    MDL = 2

class Proto(Enum):
    DHCP = 0
    TCP = 1
    HTTP_REQ = 2
    HTTP_RESP = 3
    TLS_CLI_HI = 4
    WS = 5
    MQTT = 6
    OTHS = 7

# Header fields which are optional
class Feat(Enum):
    MAX_DHCP_MSG_SIZE = 0
    MSS = 1
    HTTP_ACPT = 2
    HTTP_CT_REQ = 3 # Content-Type in HTTP request
    HTTP_CT_RESP = 4 # Content-Type in HTTP response
    HTTP_AUTH = 5
    TLS_SUP_GRP = 6
    TLS_EC_PT_FMT = 7
    TLS_SIG_ALGO = 8

CSV_FLD_TYPE = 'Type'
CSV_FLD_MFR = 'Manufacturer'
CSV_FLD_MDL = 'Model'
CSV_FLD_MAC = 'MAC Address'

TLS_CPHR_CNT_1 = 0x001b - 0x0000 + 1
TLS_CPHR_CNT_2 = (0x0046 - 0x001e + 1) + TLS_CPHR_CNT_1
TLS_CPHR_CNT_3 = (0x006d - 0x0067 + 1) + TLS_CPHR_CNT_2
TLS_CPHR_CNT_4 = (0x00c7 - 0x0084 + 1) + TLS_CPHR_CNT_3
TLS_CPHR_CNT_5 = 1 + TLS_CPHR_CNT_4
TLS_CPHR_CNT_6 = (0x1305 - 0x1301 + 1) + TLS_CPHR_CNT_5
TLS_CPHR_CNT_7 = 1 + TLS_CPHR_CNT_6
TLS_CPHR_CNT_8 = (0xc0b5 - 0xc001 + 1) + TLS_CPHR_CNT_7
TLS_CPHR_CNT_9 = (0xc106 - 0xc100 + 1) + TLS_CPHR_CNT_8
TLS_CPHR_CNT_10 = (0xccae - 0xcca8 + 1) + TLS_CPHR_CNT_9
TLS_CPHR_CNT_11 = (0xd003 - 0xd001 + 1) + TLS_CPHR_CNT_10
TLS_CPHR_CNT_12 = 1 + TLS_CPHR_CNT_11

TLS_SUP_GRP_CNT_1 = 41 - 1 + 1
TLS_SUP_GRP_CNT_2 = (260 - 256 + 1) + TLS_SUP_GRP_CNT_1
TLS_SUP_GRP_CNT_3 = (65282 - 65281 + 1) + TLS_SUP_GRP_CNT_2

TLS_SIG_ALGO_CNT_1 = 0x0203 - 0x0201 + 1
TLS_SIG_ALGO_CNT_2 = (0x0303 - 0x0301 + 1) + TLS_SIG_ALGO_CNT_1
TLS_SIG_ALGO_CNT_3 = (0x0403 - 0x0401 + 1) + TLS_SIG_ALGO_CNT_2
TLS_SIG_ALGO_CNT_4 = 1 + TLS_SIG_ALGO_CNT_3
TLS_SIG_ALGO_CNT_5 = (0x0503 - 0x0501 + 1) + TLS_SIG_ALGO_CNT_4
TLS_SIG_ALGO_CNT_6 = 1 + TLS_SIG_ALGO_CNT_5
TLS_SIG_ALGO_CNT_7 = (0x0603 - 0x0601 + 1) + TLS_SIG_ALGO_CNT_6
TLS_SIG_ALGO_CNT_8 = 1 + TLS_SIG_ALGO_CNT_7
TLS_SIG_ALGO_CNT_9 = (0x070f - 0x0704 + 1) + TLS_SIG_ALGO_CNT_8
TLS_SIG_ALGO_CNT_10 = (0x080b - 0x0804 + 1) + TLS_SIG_ALGO_CNT_9
TLS_SIG_ALGO_CNT_11 = (0x081c - 0x081a + 1) + TLS_SIG_ALGO_CNT_10

NUM_FEAT_DHCP = 1
NUM_FEAT_TCP = 2
NUM_FEAT_MIME = 49
NUM_FEAT_HTTP_REQ = NUM_FEAT_MIME*2
NUM_FEAT_HTTP_AUTH = 11
NUM_FEAT_HTTP_RESP = NUM_FEAT_MIME +\
                     NUM_FEAT_HTTP_AUTH
NUM_FEAT_TLS_VER = 5
NUM_FEAT_TLS_CPHR = TLS_CPHR_CNT_12 + 1 # Including unknown cipher suites.
NUM_FEAT_TLS_COMP = 4
NUM_FEAT_TLS_SUP_GRP = TLS_SUP_GRP_CNT_3 + 1 # Including unknown supported groups.
NUM_FEAT_TLS_EC_PT_FMT = 4
NUM_FEAT_TLS_SIG_ALGO = TLS_SIG_ALGO_CNT_11 + 1 # Including unknown signature algorithms.
NUM_FEAT_TLS_EXT_MSTR_SCRT = 1
NUM_FEAT_TLS_CLI_HI = NUM_FEAT_TLS_VER +\
                      NUM_FEAT_TLS_CPHR +\
                      NUM_FEAT_TLS_COMP +\
                      NUM_FEAT_TLS_SUP_GRP +\
                      NUM_FEAT_TLS_EC_PT_FMT +\
                      NUM_FEAT_TLS_SIG_ALGO +\
                      NUM_FEAT_TLS_EXT_MSTR_SCRT
# TODO: BitTorrent, UDT, ADwin Config
NUM_FEAT_APP = 3 # HTTP, WebSocket, MQTT
NUM_FEAT = NUM_FEAT_DHCP +\
           NUM_FEAT_TCP +\
           NUM_FEAT_HTTP_REQ +\
           NUM_FEAT_HTTP_RESP +\
           NUM_FEAT_TLS_CLI_HI +\
           NUM_FEAT_APP

KW_HTTP = b'HTTP/1.'

# FIXME: write a function to obtain feature names.
hdrs = list()

def prs_dhcp(lyr, protos, feat_cnts, feats):
    idx = 0 # Starting index for DHCP in feature vector
    protos[Proto.DHCP.value] += 1
    for opt in lyr.options:
        if opt[0] == 'max_dhcp_size':
            feat_cnts[Feat.MAX_DHCP_MSG_SIZE.value] += 1
            feats[idx] += opt[1]

def prs_tcp(lyr, protos, feat_cnts, feats):
    idx = NUM_FEAT_DHCP # Starting index for TCP in feature vector
    protos[Proto.TCP.value] += 1
    win = lyr.window
    for opt in lyr.options:
        if opt[0] == 'WScale':
            win *= pow(2, opt[1])
        elif opt[0] == 'MSS':
            feat_cnts[Feat.MSS.value] += 1
            feats[idx + 1] += opt[1]
    # Window size is added to feature vector after multiplied by scaling factor, if any.
    feats[idx] += win

# Parameter "mimes" may contain multiple MIME types, separated by commas.
def prs_mime(mimes, feats, idx):
    # Each MIME type may be weighted with a quality value.
    for mime in mimes.split(b','):
        if b'*/*' in mime:
            feats[idx] += 1
        # ----- Text -----
        elif b'text/*' in mime:
            feats[idx + 1] += 1
        elif b'text/css' in mime: # .css
            feats[idx + 2] += 1
        elif b'text/csv' in mime: # .csv
            feats[idx + 3] += 1
        elif b'text/html' in mime: # .html
            feats[idx + 4] += 1
        elif b'text/javascript' in mime: # .js
            feats[idx + 5] += 1
        elif b'text/plain' in mime: # .txt
            feats[idx + 6] += 1
        elif b'text/xml' in mime: # .xml
            feats[idx + 7] += 1
        # ----- Image -----
        elif b'image/*' in mime:
            feats[idx + 8] += 1
        elif b'image/bmp' in mime: # .bmp
            feats[idx + 9] += 1
        elif b'image/gif' in mime: # .gif
            feats[idx + 10] += 1
        elif b'image/jpeg' in mime: # .jpeg
            feats[idx + 11] += 1
        elif b'image/png' in mime: # .png
            feats[idx + 12] += 1
        elif b'image/svg+xml' in mime: # .svg
            feats[idx + 13] += 1
        # ----- Audio -----
        elif b'audio/*' in mime:
            feats[idx + 14] += 1
        elif b'audio/aac' in mime: # .aac
            feats[idx + 15] += 1
        elif b'audio/mpeg' in mime: # .mp3
            feats[idx + 16] += 1
        elif b'audio/wav' in mime: # .wav
            feats[idx + 17] += 1
        # ----- Video -----
        elif b'video/*' in mime:
            feats[idx + 18] += 1
        elif b'video/x-msvideo' in mime: # .avi
            feats[idx + 19] += 1
        elif b'video/mp4' in mime: # .mp4
            feats[idx + 20] += 1
        elif b'video/mpeg' in mime: # .mpeg
            feats[idx + 21] += 1
        # ----- Application -----
        elif b'application/*' in mime:
            feats[idx + 22] += 1
        elif b'application/x-freearc' in mime: # .arc
            feats[idx + 23] += 1
        elif b'application/octet-stream' in mime: # .bin
            feats[idx + 24] += 1
        elif b'application/x-bzip' in mime: # .bz
            feats[idx + 25] += 1
        elif b'application/x-bzip2' in mime: # .bz2
            feats[idx + 26] += 1
        elif b'application/x-csh' in mime: # .csh
            feats[idx + 27] += 1
        elif b'application/msword' in mime: # .doc
            feats[idx + 28] += 1
        elif b'application/vnd.openxmlformats-officedocument.wordprocessingml.document' in mime: # .docx
            feats[idx + 29] += 1
        elif b'application/gzip' in mime: # .gz
            feats[idx + 30] += 1
        elif b'application/java-archive' in mime: # .jar
            feats[idx + 31] += 1
        elif b'application/json' in mime: # .json
            feats[idx + 32] += 1
        elif b'application/vnd.oasis.opendocument.presentation' in mime: # .odp
            feats[idx + 33] += 1
        elif b'application/vnd.oasis.opendocument.spreadsheet' in mime: # .ods
            feats[idx + 34] += 1
        elif b'application/vnd.oasis.opendocument.text' in mime: # .odt
            feats[idx + 35] += 1
        elif b'application/pdf' in mime: # .pdf
            feats[idx + 36] += 1
        elif b'application/x-httpd-php' in mime: # .php
            feats[idx + 37] += 1
        elif b'application/vnd.ms-powerpoint' in mime: # .ppt
            feats[idx + 38] += 1
        elif b'application/vnd.openxmlformats-officedocument.presentationml.presentation' in mime: # .pptx
            feats[idx + 39] += 1
        elif b'application/vnd.rar' in mime: # .rar
            feats[idx + 40] += 1
        elif b'application/x-sh' in mime: # .sh
            feats[idx + 41] += 1
        elif b'application/x-tar' in mime: # .tar
            feats[idx + 42] += 1
        elif b'application/vnd.ms-excel' in mime: # .xls
            feats[idx + 43] += 1
        elif b'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' in mime: # .xlsx
            feats[idx + 44] += 1
        elif b'application/xml' in mime: # .xml
            feats[idx + 45] += 1
        elif b'application/zip' in mime: # .zip
            feats[idx + 46] += 1
        elif b'application/x-7z-compressed' in mime: # .7z
            feats[idx + 47] += 1
        # -----
        else:
            feats[idx + 48] += 1
            print('Unknown MIME type: {}'.format(mime.split(b';', 1)[0].decode()))

def prs_http_req(pl, protos, feat_cnts, feats):
    idx = NUM_FEAT_DHCP + NUM_FEAT_TCP # Starting index for HTTP request in feature vector
    protos[Proto.HTTP_REQ.value] += 1

    pos = pl.find(b'Accept: ')
    if pos >= 0:
        feat_cnts[Feat.HTTP_ACPT.value] += 1
        mimes = pl[pos + len(b'Accept: '):].split(b'\r', 1)[0]
        prs_mime(mimes, feats, idx)
    # ----- HTTP POST request contains header [Content-Type]. -----
    idx += NUM_FEAT_MIME
    pos = pl.find(b'Content-Type: ')
    if pos >= 0:
        feat_cnts[Feat.HTTP_CT_REQ.value] += 1
        mimes = pl[pos + len(b'Content-Type: '):].split(b'\r', 1)[0]
        prs_mime(mimes, feats, idx)
    # -----
    if pl.find(b'Upgrade: websocket') >= 0: # WebSocket is used.
        protos[Proto.WS.value] += 1

def prs_http_resp(pl, protos, feat_cnts, feats):
    idx = NUM_FEAT_DHCP + NUM_FEAT_TCP + NUM_FEAT_HTTP_REQ # Starting index for HTTP response in feature vector
    protos[Proto.HTTP_RESP.value] += 1

    pos = pl.find(b'Content-Type: ')
    if pos >= 0:
        feat_cnts[Feat.HTTP_CT_RESP.value] += 1
        mimes = pl[pos + len(b'Content-Type: '):].split(b'\r', 1)[0]
        prs_mime(mimes, feats, idx)

    idx += NUM_FEAT_MIME
    pos = pl.find(b'WWW-Authenticate: ')
    if pos >= 0:
        feat_cnts[Feat.HTTP_AUTH.value] += 1
        schm = re.split(b' |\r', pl[pos + len(b'WWW-Authenticate: '):], 1)[0]
        if schm == b'Basic':
            feats[idx] += 1
        elif schm == b'Bearer':
            feats[idx + 1] += 1
        elif schm == b'Digest':
            feats[idx + 2] += 1
        elif schm == b'HOBA':
            feats[idx + 3] += 1
        elif schm == b'Mutual':
            feats[idx + 4] += 1
        elif schm == b'Negotiate':
            feats[idx + 5] += 1
        elif schm == b'OAuth':
            feats[idx + 6] += 1
        elif schm == b'SCRAM-SHA-1':
            feats[idx + 7] += 1
        elif schm == b'SCRAM-SHA-256':
            feats[idx + 8] += 1
        elif schm == b'vapid':
            feats[idx + 9] += 1
        else:
            feats[idx + 10] += 1
            print('Unknown HTTP authentication scheme: {}'.format(schm))

def prs_sup_grp(grps, feats, idx):
    for grp in grps:
        if 1 <= grp and grp <= 41:
            feats[idx + (grp - 1)] += 1
        elif 256 <= grp and grp <= 260:
            feats[idx + TLS_SUP_GRP_CNT_1 + (grp - 256)] += 1
        elif 65281 <= grp and grp <= 65282:
            feats[idx + TLS_SUP_GRP_CNT_2 + (grp - 65281)] += 1
        else:
            feats[idx + TLS_SUP_GRP_CNT_3] += 1
            print('Unknown TLS supported group: {}'.format(grp))

def prs_sig_algo(algos, feats, idx):
    for algo in algos:
        if 0x0201 <= algo and algo <= 0x0203:
            feats[idx + (algo - 0x0201)] += 1
        elif 0x0301 <= algo and algo <= 0x0303:
            feats[idx + TLS_SIG_ALGO_CNT_1 + (algo - 0x0301)] += 1
        elif 0x0401 <= algo and algo <= 0x0403:
            feats[idx + TLS_SIG_ALGO_CNT_2 + (algo - 0x0401)] += 1
        elif algo == 0x0420:
            feats[idx + TLS_SIG_ALGO_CNT_3] += 1
        elif 0x0501 <= algo and algo <= 0x0503:
            feats[idx + TLS_SIG_ALGO_CNT_4 + (algo - 0x0501)] += 1
        elif algo == 0x0520:
            feats[idx + TLS_SIG_ALGO_CNT_5] += 1
        elif 0x0601 <= algo and algo <= 0x0603:
            feats[idx + TLS_SIG_ALGO_CNT_6 + (algo - 0x0601)] += 1
        elif algo == 0x0620:
            feats[idx + TLS_SIG_ALGO_CNT_7] += 1
        elif 0x0704 <= algo and algo <= 0x070f:
            feats[idx + TLS_SIG_ALGO_CNT_8 + (algo - 0x0704)] += 1
        elif 0x0804 <= algo and algo <= 0x080b:
            feats[idx + TLS_SIG_ALGO_CNT_9 + (algo - 0x0804)] += 1
        elif 0x081a <= algo and algo <= 0x081c:
            feats[idx + TLS_SIG_ALGO_CNT_10 + (algo - 0x081a)] += 1
        else:
            feats[idx + TLS_SIG_ALGO_CNT_11] += 1
            print('Unknown TLS signature algorithm: {}'.format(algo))

def prs_tls_cli_hi(lyr, protos, feat_cnts, feats):
    # TLS package from Scapy may interpret other handshake types as Client Hello.
    if lyr.cipherslen == None:
        return

    idx = NUM_FEAT_DHCP + NUM_FEAT_TCP + NUM_FEAT_HTTP_REQ + NUM_FEAT_HTTP_RESP # Starting index for TLS Client Hello in feature vector
    protos[Proto.TLS_CLI_HI.value] += 1
    # ----- TLS version -----
    # ver = lyr.version
    # if ver == 0x0301: # TLS 1.0
    #     feats[idx] += 1
    # elif ver == 0x0303: # TLS 1.2
    #     feats[idx + 1] += 1
    # else:
    #     feats[idx + 2] += 1
    #     print('Unknown TLS version: {}'.format(ver))

    feats[idx + (lyr.version - 0x0300)] += 1
    # ----- Cipher suites -----
    idx += NUM_FEAT_TLS_VER
    for cphr in lyr.ciphers:
        if 0x0000 <= cphr and cphr <= 0x001b:
            feats[idx + cphr] += 1
        elif 0x001e <= cphr and cphr <= 0x0046:
            feats[idx + TLS_CPHR_CNT_1 + (cphr - 0x001e)] += 1
        elif 0x0067 <= cphr and cphr <= 0x006d:
            feats[idx + TLS_CPHR_CNT_2 + (cphr - 0x0067)] += 1
        elif 0x0084 <= cphr and cphr <= 0x00c7:
            feats[idx + TLS_CPHR_CNT_3 + (cphr - 0x0084)] += 1
        elif cphr == 0x00ff:
            feats[idx + TLS_CPHR_CNT_4] += 1
        elif 0x1301 <= cphr and cphr <= 0x1305:
            feats[idx + TLS_CPHR_CNT_5 + (cphr - 0x1301)] += 1
        elif cphr == 0x5600:
            feats[idx + TLS_CPHR_CNT_6] += 1
        elif 0xc001 <= cphr and cphr <= 0xc0b5:
            feats[idx + TLS_CPHR_CNT_7 + (cphr - 0xc001)] += 1
        elif 0xc100 <= cphr and cphr <= 0xc106:
            feats[idx + TLS_CPHR_CNT_8 + (cphr - 0xc100)] += 1
        elif 0xcca8 <= cphr and cphr <= 0xccae:
            feats[idx + TLS_CPHR_CNT_9 + (cphr - 0xcca8)] += 1
        elif 0xd001 <= cphr and cphr <= 0xd003:
            feats[idx + TLS_CPHR_CNT_10 + (cphr - 0xd001)] += 1
        elif cphr == 0xd005:
            feats[idx + TLS_CPHR_CNT_11] += 1
        else:
            feats[idx + TLS_CPHR_CNT_12] += 1
            print('Unknown TLS cipher suite: {}'.format(cphr))
    # ----- Compression methods -----
    idx += NUM_FEAT_TLS_CPHR
    for comp in lyr.comp:
        if comp == 0:
            feats[idx] += 1
        elif comp == 1:
            feats[idx + 1] += 1
        elif comp == 64:
            feats[idx + 2] += 1
        else:
            feats[idx + 3] += 1
            print('Unknown TLS compression method: {}'.format(comp))
    # -----
    if lyr.ext != None:
        idx += NUM_FEAT_TLS_COMP
        for ext in lyr.ext:
            ext_type = ext.type
            if ext_type == 10: # Supported groups
                feat_cnts[Feat.TLS_SUP_GRP.value] += 1
                prs_sup_grp(ext.groups, feats, idx)
            elif ext_type == 11: # EC point formats
                feat_cnts[Feat.TLS_EC_PT_FMT.value] += 1
                for fmt in ext.ecpl:
                    if 0 <= fmt and fmt <= 2:
                        feats[idx + NUM_FEAT_TLS_SUP_GRP + fmt] += 1
                    else:
                        feats[idx + NUM_FEAT_TLS_SUP_GRP + 3] += 1
                        print('Unknown TLS EC point format: {}'.format(fmt))
            elif ext_type == 13: # Signature algorithms
                feat_cnts[Feat.TLS_SIG_ALGO.value] += 1
                prs_sig_algo(ext.sig_algs, feats, idx + NUM_FEAT_TLS_SUP_GRP + NUM_FEAT_TLS_EC_PT_FMT)
            elif ext_type == 23: # Extended master secret
                # To signal both client and server to use extended master secret computation. -> Data field of extension is empty.
                feats[idx + NUM_FEAT_TLS_SUP_GRP + NUM_FEAT_TLS_EC_PT_FMT + NUM_FEAT_TLS_SIG_ALGO] += 1
            elif ext_type == 43: # Supported versions
                # TLS 1.3 Client Hello is identified as version being 0x0303 and highest version in extension "supported versions" being 0x0304.
                for v in ext.versions:
                    if v == 0x0304: # TLS 1.3
                        feats[NUM_FEAT_DHCP + NUM_FEAT_TCP + NUM_FEAT_HTTP_REQ + NUM_FEAT_HTTP_RESP + (lyr.version - 0x0300)] -= 1
                        feats[NUM_FEAT_DHCP + NUM_FEAT_TCP + NUM_FEAT_HTTP_REQ + NUM_FEAT_HTTP_RESP + (v - 0x0300)] += 1
                        break

def prs_pkt(pkt, protos, feat_cnts, feats):
    if pkt.haslayer(DHCP):
        prs_dhcp(pkt[DHCP], protos, feat_cnts, feats)
    elif pkt.haslayer(TCP):
        if pkt[TCP].flags.value == 0x002 or pkt[TCP].flags.value == 0x012: # TCP [SYN] or [SYN, ACK]
            prs_tcp(pkt[TCP], protos, feat_cnts, feats)
        elif pkt.haslayer(TLSClientHello): # TLS Client Hello
            prs_tls_cli_hi(pkt[TLSClientHello], protos, feat_cnts, feats)
        elif pkt.haslayer(MQTT): # MQTT
            protos[Proto.MQTT.value] += 1
        else:
            # HTTP package from Scapy fails to detect HTTP packets that do not use port 80.
            # Therefore, detect HTTP packets manually.
            idx = bytes(pkt[TCP].payload).find(KW_HTTP)
            if idx > 0: # HTTP request
                prs_http_req(bytes(pkt[TCP].payload), protos, feat_cnts, feats)
            elif idx == 0: # HTTP response
                prs_http_resp(bytes(pkt[TCP].payload), protos, feat_cnts, feats)

def smrz_feats(feats, protos, feat_cnts, oths):
    # ----- Check whether application-layer protocols are used. -----
    # Starting index for application-layer protocols in feature vector
    idx = NUM_FEAT_DHCP +\
          NUM_FEAT_TCP +\
          NUM_FEAT_HTTP_REQ +\
          NUM_FEAT_HTTP_RESP +\
          NUM_FEAT_TLS_CLI_HI
    if protos[Proto.HTTP_REQ.value] > 0 or protos[Proto.HTTP_RESP.value] > 0: # HTTP
        feats[idx] = 1
    if protos[Proto.WS.value] > 0: # WebSocket
        feats[idx + 1] = 1
        oths -= protos[Proto.WS.value]
    if protos[Proto.MQTT.value] > 0: # MQTT
        feats[idx + 2] = 1
        oths -= protos[Proto.MQTT.value]
    # -----

    # ----- Calculate averages of feature values. -----
    strt = 0
    end = NUM_FEAT_DHCP
    # cnt = protos[Proto.DHCP.value]
    cnt = feat_cnts[Feat.MAX_DHCP_MSG_SIZE.value]
    if cnt > 0:
        # oths -= cnt
        for i in range(strt, end):
            feats[i] /= cnt
    oths -= protos[Proto.DHCP.value]

    strt = end
    end += NUM_FEAT_TCP
    cnt = protos[Proto.TCP.value]
    if cnt > 0:
        oths -= cnt
        # for i in range(strt, end):
        #     feats[i] /= cnt
        feats[strt] /= cnt
        # ----- TCP maximum segment size -----
        cnt = feat_cnts[Feat.MSS.value]
        if cnt > 0:
            feats[strt + 1] /= cnt
        # -----

    # ----- HTTP Accept -----
    strt = end
    # end += NUM_FEAT_HTTP_REQ
    end += NUM_FEAT_MIME
    # cnt = protos[Proto.HTTP_REQ.value]
    cnt = feat_cnts[Feat.HTTP_ACPT.value]
    if cnt > 0:
        # oths -= cnt
        for i in range(strt, end):
            feats[i] /= cnt
    # ----- HTTP Content-Type (Request) -----
    strt = end
    end += NUM_FEAT_MIME
    cnt = feat_cnts[Feat.HTTP_CT_REQ.value]
    if cnt > 0:
        for i in range(strt, end):
            feats[i] /= cnt
    # -----
    oths -= protos[Proto.HTTP_REQ.value]

    # ----- HTTP Content-Type (Response) -----
    strt = end
    # end += NUM_FEAT_HTTP_RESP
    end += NUM_FEAT_MIME
    # cnt = protos[Proto.HTTP_RESP.value]
    cnt = feat_cnts[Feat.HTTP_CT_RESP.value]
    if cnt > 0:
        # oths -= cnt
        for i in range(strt, end):
            feats[i] /= cnt
    # ----- HTTP WWW-Authenticate -----
    strt = end
    end += NUM_FEAT_HTTP_AUTH
    cnt = feat_cnts[Feat.HTTP_AUTH.value]
    if cnt > 0:
        for i in range(strt, end):
            feats[i] /= cnt
    # -----
    oths -= protos[Proto.HTTP_RESP.value]

    strt = end
    # end += NUM_FEAT_TLS_CLI_HI
    end += NUM_FEAT_TLS_VER +\
           NUM_FEAT_TLS_CPHR +\
           NUM_FEAT_TLS_COMP
    cnt = protos[Proto.TLS_CLI_HI.value]
    if cnt > 0:
        oths -= cnt
        for i in range(strt, end):
            feats[i] /= cnt
        # ----- TLS supported groups -----
        strt = end
        end += NUM_FEAT_TLS_SUP_GRP
        cnt = feat_cnts[Feat.TLS_SUP_GRP.value]
        if cnt > 0:
            for i in range(strt, end):
                feats[i] /= cnt
        # ----- TLS EC point formats -----
        strt = end
        end += NUM_FEAT_TLS_EC_PT_FMT
        cnt = feat_cnts[Feat.TLS_EC_PT_FMT.value]
        if cnt > 0:
            for i in range(strt, end):
                feats[i] /= cnt
        # ----- TLS signature algorithms -----
        strt = end
        end += NUM_FEAT_TLS_SIG_ALGO
        cnt = feat_cnts[Feat.TLS_SIG_ALGO.value]
        if cnt > 0:
            for i in range(strt, end):
                feats[i] /= cnt
        # ----- TLS extended master secret -----
        strt = end
        end += NUM_FEAT_TLS_EXT_MSTR_SCRT
        cnt = protos[Proto.TLS_CLI_HI.value]
        for i in range(strt, end):
            feats[i] /= cnt
        # -----
    # -----
    protos[Proto.OTHS.value] = oths
    print('# of packets for [DHCP, TCP, HTTP Request, HTTP Response, TLS, WebSocket, MQTT, Others] = {}'.format(protos))

def prs_pcap(pth, mac):
    oths = 0 # # of packets from device but not of interest
    protos = [0]*len(Proto)
    # Count # of appearances of optional header fields to calculate their average values.
    feat_cnts = [0]*len(Feat)
    feats = [0]*NUM_FEAT

    for pkt in PcapReader(pth):
        if not pkt.haslayer(Ether):
            continue
        if pkt[Ether].src != mac:
            continue
        oths += 1
        prs_pkt(pkt, protos, feat_cnts, feats)

    smrz_feats(feats, protos, feat_cnts, oths)
    return feats

def wrt_csv(feats, lbls, out):
    if out == None:
        return

    out_f = open(out, 'w')
    wrtr = csv.writer(out_f)
    # ----- Write CSV headers -----
    # hdrs = list()
    # FIXME: remove this line when not needed.
    hdrs.clear()

    hdrs.append('Type')
    hdrs.append('Manufacturer')
    hdrs.append('Model')
    hdrs.append('File')

    hdrs.append('Maximum DHCP message size')
    hdrs.append('TCP window size')
    hdrs.append('TCP maximum segment size')

    # hdrs.append('HTTP Accept')
    # for i in range(NUM_FEAT_MIME - 1):
    for i in range(NUM_FEAT_MIME):
        # hdrs.append('')
        hdrs.append('Acpt[{}]'.format(i))

    # hdrs.append('HTTP Content-Type (Request)')
    # for i in range(NUM_FEAT_MIME - 1):
    for i in range(NUM_FEAT_MIME):
        # hdrs.append('')
        hdrs.append('CT(Req)[{}]'.format(i))

    # hdrs.append('HTTP Content-Type (Response)')
    # for i in range(NUM_FEAT_MIME - 1):
    for i in range(NUM_FEAT_MIME):
        # hdrs.append('')
        hdrs.append('CT(Resp)[{}]'.format(i))

    # hdrs.append('HTTP WWW-Authenticate')
    # for i in range(NUM_FEAT_HTTP_AUTH - 1):
    for i in range(NUM_FEAT_HTTP_AUTH):
        # hdrs.append('')
        hdrs.append('Auth[{}]'.format(i))

    hdrs.append('SSL3.0')
    hdrs.append('TLS1.0')
    hdrs.append('TLS1.1')
    hdrs.append('TLS1.2')
    hdrs.append('TLS1.3')

    # hdrs.append('TLS cipher suites')
    # for i in range(NUM_FEAT_TLS_CPHR - 1):
    for i in range(NUM_FEAT_TLS_CPHR):
        # hdrs.append('')
        hdrs.append('Cphr[{}]'.format(i))

    # hdrs.append('TLS compression methods')
    # for i in range(NUM_FEAT_TLS_COMP - 1):
    for i in range(NUM_FEAT_TLS_COMP):
        # hdrs.append('')
        hdrs.append('Comp[{}]'.format(i))

    # hdrs.append('TLS supported groups')
    # for i in range(NUM_FEAT_TLS_SUP_GRP - 1):
    for i in range(NUM_FEAT_TLS_SUP_GRP):
        # hdrs.append('')
        hdrs.append('SupGrp[{}]'.format(i))

    # hdrs.append('TLS EC point formats')
    # for i in range(NUM_FEAT_TLS_EC_PT_FMT - 1):
    for i in range(NUM_FEAT_TLS_EC_PT_FMT):
        # hdrs.append('')
        hdrs.append('ECPtFmt[{}]'.format(i))

    # hdrs.append('TLS signature algorithms')
    # for i in range(NUM_FEAT_TLS_SIG_ALGO - 1):
    for i in range(NUM_FEAT_TLS_SIG_ALGO):
        # hdrs.append('')
        hdrs.append('SigAlgo[{}]'.format(i))

    hdrs.append('TLS extended master secret')
    for i in range(NUM_FEAT_TLS_EXT_MSTR_SCRT - 1):
        hdrs.append('')

    hdrs.append('HTTP')
    hdrs.append('WebSocket')
    hdrs.append('MQTT')

    wrtr.writerow(hdrs)
    # ----- Write CSV data -----
    for i in range(len(lbls)):
        wrtr.writerow(lbls[i] + feats[i])
    # -----
    out_f.close()

def prs_dir(pth, devs, tgt, out=None):
    lbls = list() # List of [Type, Manufacturer, Model]
    feats = list()
    dev_info = dict()

    # ----- Load device information into dictionary -----
    devs_f = open(devs, 'r')
    for row in csv.DictReader(devs_f):
        # Use list, instead of tuple, as dictionary value to prevent later conversion.
        dev_info[row[CSV_FLD_MDL]] = [row[CSV_FLD_TYPE], row[CSV_FLD_MFR], row[CSV_FLD_MAC]]
    devs_f.close()
    # -----
    for root, dirs, fs in os.walk(pth):
        if(len(fs) == 0):
            continue
        for f in fs:
            mdl = f.split('-', 1)[0]
            if mdl not in dev_info:
                print('Information of device [{}] is not found in device file [{}], so skip parsing file [{}].'.format(mdl, devs, root + '/' + f), file=sys.stderr)
                continue
            print('Parsing file [{}] ...'.format(root + '/' + f))
            lbls.append(dev_info[mdl][0:2] + [mdl] + [f])
            feats.append(prs_pcap(root + '/' + f, dev_info[mdl][2]))
    # Write extracted features to output file.
    wrt_csv(feats, lbls, out)
    return feats, [row[tgt.value] for row in lbls]

def ld_csv(pth, tgt):
    idx = tgt.value
    lbls = list()
    feats = list()
    feats_f = open(pth, 'r')
    rdr = csv.reader(feats_f)

    # Skip CSV headers.
    next(rdr)
    for row in rdr:
        lbls.append(row[idx])
        feats.append(row[4:])
    feats_f.close()
    return feats, lbls
