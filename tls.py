import OpenSSL.crypto
import pyshark as _pyshark
import codecs as _codecs
from cs_dict import cs_dict
import logging as _logging
import sys as _sys
import asyncio as _asyncio
import multiprocessing as _mp
import threading as _threading

_logger = _logging.getLogger(__name__)
_formatter = _logging.Formatter('[%(name)s][%(levelname)s]: %(message)s')
_hdlr = _logging.StreamHandler(_sys.stdout)
_hdlr.setFormatter(_formatter)
_logger.setLevel(_logging.DEBUG)
_logger.addHandler(_hdlr)

def get_version_ciphersuite(pkt):
    version_map = {
            0x0300: 'SSL 3.0',
            0x0301: 'TLS 1.0',
            0x0302: 'TLS 1.1',
            0x0303: 'TLS 1.2',
            0x0304: 'TLS 1.3',
            }

    if type(pkt.tls.record) == list:
        vnum = int(pkt.tls.record[0].handshake.extension.supported_version, 16)
        csnum = int(pkt.tls.record[0].handshake.ciphersuite, 16)
    else:
        vnum = int(pkt.tls.record.version, 16)
        csnum = int(pkt.tls.record.handshake.ciphersuite, 16)
    
    csname = cs_dict[csnum]
    _logger.info(f'{pkt.ip.src}:{pkt.tcp.srcport} -> {pkt.ip.dst}:{pkt.tcp.dstport} uses {version_map[vnum]}')
    _logger.info(f'{pkt.ip.src}:{pkt.tcp.srcport} -> {pkt.ip.dst}:{pkt.tcp.dstport} uses {csname}')

    return version_map[vnum], csname

def check_alert(pkt):
    if 'TLS' not in pkt:
        return False

    am_desc = int(pkt.tls.record.alert_message.desc)
    if am_desc == 48:
        return True

    else:
        return False

def get_certs(pkt):
    cert_bin = pkt.tls.record.handshake.certificates.certificate
    binary_pem = map(lambda x:x.replace(':',''),cert_bin)
    b64 = map(lambda x:\
                "-----BEGIN CERTIFICATE-----\n" + \
                _codecs.encode(_codecs.decode(x,'hex'),'base64').decode() + \
                "-----END CERTIFICATE-----\n",\
                binary_pem)
    cert_list = map(lambda x:OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, x), b64)
    return cert_list 

def verify(cert_list):
    x509store = OpenSSL.crypto.X509Store()
    x509store.load_locations(None, capath="/etc/ssl/certs")
    
    for cert in cert_list[1:]:
        x509store.add_cert(cert)

    store_ctx = OpenSSL.crypto.X509StoreContext(x509store, cert_list[0])

    try:
        store_ctx.verify_certificate()
    except:
        return False
    else:
        return True

def verify_cert_pkt(pkt):
    cert_list = list(get_certs(pkt))
    if cert_list[0].has_expired():
        _logger.info(f'{cert_list[0].get_subject()} has expired')
    
    if verify(cert_list):
        res = 'valid'
    else:
        res = 'invalid'

    _logger.info(f'{pkt.ip.src}:{pkt.tcp.srcport} -> {pkt.ip.dst}:{pkt.tcp.dstport} has {res} certificates')

    return



def sniffer(iface, flag, callback, display_filter = ''):
    _logger.debug(f'Start {callback.__name__} sniffer at {_threading.get_native_id()}')
    cap = _pyshark.LiveCapture( interface = iface,
                               display_filter = display_filter,
                               use_json = True
                             )
    p = _mp.Process(target = cap.apply_on_packets,
                args = (callback,)
                )

    p.start()

    if flag.wait():
        cap.close()
        p.kill()
        p.join()
        _logger.debug(f'{callback.__name__} sniffer at {_threading.get_native_id()} ended')
        flag.clear()
        return


