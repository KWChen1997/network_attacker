#!/usr/bin/env python3

import sys, os, signal, socket
import wkr, proxy

CLD_ADDR = '' # Empty represents INADDR_ANY, which binds to all interfaces.
CLD_PORT = 2000

def hdlr(sig, frm):
    while True:
        try:
            pid, stat = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError: # No child process to wait for
            break

def main():
    signal.signal(signal.SIGCHLD, hdlr)
    # ----- Initiate Classification Proxy -----
    pid = os.fork()
    if pid == 0:
        proxy.strt()
        sys.exit(0)
    # -----
    svr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    svr.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    svr.bind((CLD_ADDR, CLD_PORT))
    svr.listen()
    print('<Cloud> Listening on socket [{}:{}] ...'.format(CLD_ADDR, CLD_PORT))

    while True:
        cli, addr = svr.accept()
        print('<Cloud> Connected by client [{}:{}].'.format(addr[0], addr[1]))

        pid = os.fork()
        if pid == 0:
            svr.close()
            wkr.run(cli)
            cli.close()
            print('<Cloud> Disconnect from client [{}:{}].'.format(addr[0], addr[1]))
            sys.exit(0)
        else:
            cli.close()

main()
