import os, socket, csv
# ML model persistence
from joblib import dump, load

PROXY_ADDR = '' # Empty represents INADDR_ANY, which binds to all interfaces.
PROXY_PORT = 2001

CMD_PRED = b'\x02'

PTH_TMP = './tmp'
PTH_CLFS = './clfs'

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
        print('<Classification Proxy> Prediction result:\n-> Type: {}\n-> Manufacturer: {}\n-> Model: {}'.format(lbls[0], lbls[1], lbls[2]))
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
    print('<Classification Proxy> Loading Multi-Layer Classifier from directory [{}] ...'.format(PTH_CLFS))
    ld_clfs(PTH_CLFS, root)

    svr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    svr.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    svr.bind((PROXY_ADDR, PROXY_PORT))
    svr.listen()
    print('<Classification Proxy> Listening on socket [{}:{}] ...'.format(PROXY_ADDR, PROXY_PORT))

    while True:
        cli, addr = svr.accept()
        print('<Classification Proxy> Connected by client [{}:{}].'.format(addr[0], addr[1]))
        run(cli, root)
        cli.close()
        print('<Classification Proxy> Disconnect from client [{}:{}].'.format(addr[0], addr[1]))
