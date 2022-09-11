import netifaces as _netifaces
import subprocess as _sp
import shlex as _shlex
import logging as _logging
import sys as _sys
import re as _re
import time as _time
import threading as _threading

_logger = _logging.getLogger(__name__)
_s_formatter = _logging.Formatter('[%(name)s][%(levelname)s]: %(message)s')
_f_formatter = _logging.Formatter('[%(levelname)s]: %(message)s')
_hdlr = _logging.StreamHandler(_sys.stdout)
_file_hdlr = _logging.FileHandler(__name__+'.log')
_hdlr.setFormatter(_s_formatter)
_file_hdlr.setFormatter(_f_formatter)
_logger.setLevel(_logging.DEBUG)
_logger.addHandler(_hdlr)
_logger.addHandler(_file_hdlr)

_gw = None
_netmask = None
_iface = None
ip2mac = {}
ip2mac_flag = _threading.Event()

def nm2num(nm):
    tmp = nm.split('.')
    mask = 0
    for m in tmp:
        mask = mask << 8
        mask += int(m)

    mask = 0xffffffff - mask
    count = 0
    while mask != 0:
        count += 1
        mask = mask >> 1

    return 32 - count

def get_route():
    global _gw
    global _netmask
    global _iface

    if _gw != None and _netmask != None and _iface != None:
        return _gw, _netmask, _iface

    gw, iface = _netifaces.gateways()['default'][2]
    nm = _netifaces.ifaddresses(iface)[2][0]['netmask']
    _logger.debug(f'Gateway is at {gw} with netmask {nm}.')

    _gw, _netmask, _iface = gw, nm, iface

    return gw,nm,iface

def probe(iface = None, gw = None, nm = None):
    global ip2mac
    if gw == None or nm == None or iface == None:
        gw, nm, iface = get_route()
        nm = nm2num(nm)

    p = _sp.Popen(['arp-scan', '-I', iface, '-x', gw+'/'+str(nm)],
                         stdout = _sp.PIPE,
                         stderr = _sp.DEVNULL
                         )

    p.wait()
    prompts, _ = p.communicate()
    prompts = prompts.decode().split('\n')[:-1]

    for prompt in prompts:
        m = prompt.split('\t')[:2]
        if m[0] not in ip2mac or m[1] != ip2mac[m[0]]:
            _logger.info(f'{m[0]} is at {m[1]}')
        ip2mac[m[0]] = m[1]
    

def probes(gw = None, nm = None, count = 0):
    if count == 0:
        while True:
            probe(gw, nm)
            _time.sleep(1)
            if ip2mac_flag.is_set():
                break
            
        _logger.debug('Stop probing')
        return
    
    _logger.debug(f'Looping for {count} times')
    for _ in range(count):
        probe(gw, nm)
        _time.sleep(1)
