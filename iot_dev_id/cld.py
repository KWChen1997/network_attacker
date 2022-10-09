#!/usr/bin/env python3

import sys, os, signal, socket
import logging as _logging
import wkr, proxy

_logger = _logging.getLogger('Cloud')
_s_formatter = _logging.Formatter('[%(name)s][%(levelname)s]: %(message)s')
_f_formatter = _logging.Formatter('[%(levelname)s]: %(message)s')
_hdlr = _logging.StreamHandler(sys.stdout)
_file_hdlr = _logging.FileHandler('Cloud.log')
_hdlr.setFormatter(_s_formatter)
_file_hdlr.setFormatter(_f_formatter)
_logger.setLevel(_logging.DEBUG)
_logger.addHandler(_hdlr)
_logger.addHandler(_file_hdlr)



CLD_ADDR = '' # Empty represents INADDR_ANY, which binds to all interfaces.
CLD_PORT = 2000

pid_list = {}

def hdlr(sig, frm):
    while True:
        try:
            pid, stat = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError: # No child process to wait for
            break

def exit_hdlr(sig, frm):
    _logger.debug('enter exit handler')
    for pid in pid_list:
        os.kill(pid, signal.SIGKILL)

    sys.exit(0)

def cld():
    signal.signal(signal.SIGCHLD, hdlr)
    signal.signal(signal.SIGTERM, exit_hdlr)
    # ----- Initiate Classification Proxy -----
    pid = os.fork()
    if pid == 0:
        proxy.strt()
        sys.exit(0)

    _logger.debug(f'{pid} child process created')
    pid_list[pid] = 1
    # -----
    svr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    svr.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    svr.bind((CLD_ADDR, CLD_PORT))
    svr.listen()
    _logger.debug('Listening on socket [{}:{}] ...'.format(CLD_ADDR, CLD_PORT))

    while True:
        cli, addr = svr.accept()
        _logger.debug('Connected by client [{}:{}].'.format(addr[0], addr[1]))

        pid = os.fork()
        if pid == 0:
            svr.close()
            wkr.run(cli)
            cli.close()
            _logger.debug('Disconnect from client [{}:{}].'.format(addr[0], addr[1]))
            sys.exit(0)
        else:
            pid_list[pid] = 1
            cli.close()

cld()
