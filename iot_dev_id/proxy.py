import os, socket, csv, sys
import logging as _logging

# ML model persistence
from joblib import dump, load

_logger = _logging.getLogger(__name__)
_s_formatter = _logging.Formatter('[%(name)s][%(levelname)s]: %(message)s')
_f_formatter = _logging.Formatter('[%(levelname)s]: %(message)s')
_hdlr = _logging.StreamHandler(sys.stdout)
_file_hdlr = _logging.FileHandler(__name__+'.log')
_hdlr.setFormatter(_s_formatter)
_file_hdlr.setFormatter(_f_formatter)
_logger.setLevel(_logging.DEBUG)
_logger.addHandler(_hdlr)
_logger.addHandler(_file_hdlr)

PROXY_ADDR = '' # Empty represents INADDR_ANY, which binds to all interfaces.
PROXY_PORT = 2001

CMD_PRED = b'\x02'

PTH_TMP = './iot_dev_id/tmp'
PTH_CLFS = './iot_dev_id/clfs'

def ld_clfs(pth, node):
    for name in os.listdir(pth):
        if os.path.isfile(pth + '/' + name):
            node[0] = load(pth + '/' + name)
        else:
            node[1][name] = [None, dict()]
            ld_clfs(pth + '/' + name, node[1][name])

def pred(node, feats, lbls, idx):
    lbl = node[0].predict([feats])[0]
    lbls[idx] = lbl
    if lbl == 'Non-IoT' or idx == 2:
        return
    else:
        pred(node[1][lbl], feats, lbls, idx + 1)

def run(cli, root):
    lbls = [None, 'N/A', 'N/A']

    cmd = cli.recv(1, socket.MSG_WAITALL)
    pid = int.from_bytes(cli.recv(3, socket.MSG_WAITALL), 'big')

    if cmd == CMD_PRED:
        feats_f = open('{}/{}.csv'.format(PTH_TMP, pid, 'r'))
        rdr = csv.reader(feats_f)
        feats = next(rdr)
        pred(root, feats, lbls, 0)
        feats_f.close()
        _logger.debug('Prediction result:\n-> Type: {}\n-> Manufacturer: {}\n-> Model: {}'.format(lbls[0], lbls[1], lbls[2]))
        # ----- Send predicted labels of device back to Device Worker. -----
        for i in range(len(lbls)):
            cli.send(len(lbls[i]).to_bytes(1, 'big'))
            cli.send(lbls[i].encode())
        # -----

def strt():
    # Tree node of Multi-Layer Classifier (List is used because tuple is immutable.)
    # 1st element: multi-class classifier
    # 2nd element: dictionary of child nodes
    # - Key: label name
    # - Value: tree node
    root = [None, dict()]
    _logger.debug('Loading Multi-Layer Classifier from directory [{}] ...'.format(PTH_CLFS))
    ld_clfs(PTH_CLFS, root)

    svr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    svr.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    svr.bind((PROXY_ADDR, PROXY_PORT))
    svr.listen()
    _logger.debug('Listening on socket [{}:{}] ...'.format(PROXY_ADDR, PROXY_PORT))

    while True:
        cli, addr = svr.accept()
        _logger.debug('Connected by client [{}:{}].'.format(addr[0], addr[1]))
        run(cli, root)
        cli.close()
        _logger.debug('Disconnect from client [{}:{}].'.format(addr[0], addr[1]))
