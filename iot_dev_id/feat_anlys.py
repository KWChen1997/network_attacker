import csv
from feat import *

def idx2code_cphr(idx):
    code = 0x0000

    if idx >= TLS_CPHR_CNT_11:
        code = 0xd005 + (idx - TLS_CPHR_CNT_11)
    elif idx >= TLS_CPHR_CNT_10:
        code = 0xd001 + (idx - TLS_CPHR_CNT_10)
    elif idx >= TLS_CPHR_CNT_9:
        code = 0xcca8 + (idx - TLS_CPHR_CNT_9)
    elif idx >= TLS_CPHR_CNT_8:
        code = 0xc100 + (idx - TLS_CPHR_CNT_8)
    elif idx >= TLS_CPHR_CNT_7:
        code = 0xc001 + (idx - TLS_CPHR_CNT_7)
    elif idx >= TLS_CPHR_CNT_6:
        code = 0x5600 + (idx - TLS_CPHR_CNT_6)
    elif idx >= TLS_CPHR_CNT_5:
        code = 0x1301 + (idx - TLS_CPHR_CNT_5)
    elif idx >= TLS_CPHR_CNT_4:
        code = 0x00ff + (idx - TLS_CPHR_CNT_4)
    elif idx >= TLS_CPHR_CNT_3:
        code = 0x0084 + (idx - TLS_CPHR_CNT_3)
    elif idx >= TLS_CPHR_CNT_2:
        code = 0x0067 + (idx - TLS_CPHR_CNT_2)
    elif idx >= TLS_CPHR_CNT_1:
        code = 0x001e + (idx - TLS_CPHR_CNT_1)
    else:
        code = idx

    print(hex(code))

def idx2code_sup_grp(idx):
    code = 0x0000

    if idx >= TLS_SUP_GRP_CNT_2:
        code = 65281 + (idx - TLS_SUP_GRP_CNT_2)
    elif idx >= TLS_SUP_GRP_CNT_1:
        code = 256 + (idx - TLS_SUP_GRP_CNT_1)
    else:
        code = 1 + idx

    print(code)

def cphr_stats(pth):
    feats_f = open(pth, 'r')
    rdr = csv.reader(feats_f)

    next(rdr)
    print('---------- Statistics of TLS cipher suites ----------')
    for row in rdr:
        sec = 0
        weak = 0
        insec = 0
        na = 0

        strt = 4 + NUM_FEAT_DHCP + NUM_FEAT_TCP + NUM_FEAT_HTTP_REQ + NUM_FEAT_HTTP_RESP + NUM_FEAT_TLS_VER
        end = strt + NUM_FEAT_TLS_CPHR - 1
        for i in range(strt, end):
            if float(row[i]) > 0:
                idx = i - strt
                if 3 <= idx and idx <= 10:
                    insec += 1
                elif 12 <= idx and idx <= 13:
                    insec += 1
                elif 15 <= idx and idx <= 22:
                    insec += 1
                elif 45 <= idx and idx <= 49:
                    insec += 1
                elif 51 <= idx and idx <= 55:
                    insec += 1
                elif 58 <= idx and idx <= 62:
                    weak += 1
                elif 63 <= idx and idx <= 67:
                    insec += 1
                elif 69 <= idx and idx <= 73:
                    weak += 1
                elif 76 <= idx and idx <= 80:
                    insec += 1
                elif 82 <= idx and idx <= 85:
                    insec += 1
                elif 87 <= idx and idx <= 89:
                    insec += 1
                elif 91 <= idx and idx <= 98:
                    insec += 1
                elif 100 <= idx and idx <= 101:
                    weak += 1
                elif 102 <= idx and idx <= 103:
                    sec += 1
                elif 104 <= idx and idx <= 105:
                    weak += 1
                elif 106 <= idx and idx <= 107:
                    sec += 1
                elif 108 <= idx and idx <= 109:
                    weak += 1
                elif 112 <= idx and idx <= 113:
                    weak += 1
                elif 114 <= idx and idx <= 115:
                    sec += 1
                elif 116 <= idx and idx <= 119:
                    weak += 1
                elif 122 <= idx and idx <= 123:
                    weak += 1
                elif 126 <= idx and idx <= 127:
                    weak += 1
                elif 130 == idx:
                    weak += 1
                elif 133 <= idx and idx <= 134:
                    weak += 1
                elif 136 == idx:
                    weak += 1
                elif 139 <= idx and idx <= 140:
                    weak += 1
                elif 144 == idx:
                    na += 1
                elif 145 <= idx and idx <= 147:
                    sec += 1
                elif 152 <= idx and idx <= 155:
                    insec += 1
                elif 157 <= idx and idx <= 160:
                    insec += 1
                elif 162 <= idx and idx <= 165:
                    insec += 1
                elif 167 <= idx and idx <= 170:
                    insec += 1
                elif 185 <= idx and idx <= 192:
                    weak += 1
                elif 193 <= idx and idx <= 194:
                    sec += 1
                elif 195 <= idx and idx <= 196:
                    weak += 1
                elif 197 <= idx and idx <= 198:
                    sec += 1
                elif 199 <= idx and idx <= 200:
                    weak += 1
                elif 202 <= idx and idx <= 204:
                    insec += 1
                elif 205 <= idx and idx <= 206:
                    weak += 1
                elif 230 <= idx and idx <= 231:
                    weak += 1
                elif 232 <= idx and idx <= 233:
                    sec += 1
                elif 236 <= idx and idx <= 237:
                    sec += 1
                elif 242 <= idx and idx <= 243:
                    sec += 1
                elif 246 <= idx and idx <= 247:
                    sec += 1
                elif 264 <= idx and idx <= 273:
                    weak += 1
                elif 274 <= idx and idx <= 275:
                    sec += 1
                elif 284 <= idx and idx <= 285:
                    sec += 1
                elif 286 <= idx and idx <= 287:
                    weak += 1
                elif 288 <= idx and idx <= 289:
                    sec += 1
                elif 290 <= idx and idx <= 293:
                    weak += 1
                elif 294 <= idx and idx <= 295:
                    sec += 1
                elif 296 <= idx and idx <= 307:
                    weak += 1
                elif 308 <= idx and idx <= 309:
                    sec += 1
                elif 310 <= idx and idx <= 311:
                    weak += 1
                elif 312 <= idx and idx <= 313:
                    sec += 1
                elif 314 <= idx and idx <= 315:
                    weak += 1
                elif 316 <= idx and idx <= 317:
                    sec += 1
                elif 318 <= idx and idx <= 319:
                    weak += 1
                elif 320 <= idx and idx <= 325:
                    sec += 1
                elif 339 <= idx and idx <= 341:
                    sec += 1
                else:
                    print('Unknown TLS cipher suite, whose index = {}.'.format(idx))

        print('{} / {} / {} / {} -> Secure: {}, Weak: {}, Insecure: {}'.format(row[0], row[1], row[2], row[3], sec, weak, insec))

    feats_f.close()

def sup_grp_stats(pth):
    feats_f = open(pth, 'r')
    rdr = csv.reader(feats_f)

    next(rdr)
    print('---------- Statistics of TLS supported groups ----------')
    for row in rdr:
        rcmd = 0
        not_rcmd = 0

        strt = 4 + NUM_FEAT_DHCP + NUM_FEAT_TCP + NUM_FEAT_HTTP_REQ + NUM_FEAT_HTTP_RESP + NUM_FEAT_TLS_VER + NUM_FEAT_TLS_CPHR + NUM_FEAT_TLS_COMP
        end = strt + NUM_FEAT_TLS_SUP_GRP - 1
        for i in range(strt, end):
            if float(row[i]) > 0:
                idx = i - strt
                if 0 <= idx and idx <= 21:
                    not_rcmd += 1
                elif 22 <= idx and idx <= 23:
                    rcmd += 1
                elif 24 <= idx and idx <= 27:
                    not_rcmd += 1
                elif 28 <= idx and idx <= 29:
                    rcmd += 1
                elif 41 <= idx and idx <= 42:
                    not_rcmd += 1
                else:
                    print('Unknown TLS supported group, whose index = {}.'.format(idx))

        print('{} / {} / {} / {} -> Recommended: {}, Not recommended: {}'.format(row[0], row[1], row[2], row[3], rcmd, not_rcmd))

    feats_f.close()
