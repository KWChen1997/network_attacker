import os, sys
import logging as _logging

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

def run(rd, wrt):
    dev = [None, None, None]

    _logger.debug('Ready for user verification.')
    while True:
        # ----- Receive predicted labels of device from Device Detector. -----
        mac = os.read(rd, 17).decode()
        for i in range(len(dev)):
            n = int.from_bytes(os.read(rd, 1), 'big')
            dev[i] = os.read(rd, n).decode()
        # ----- Ask for user verification. -----
        _logger.debug('Identity of device [{}]:\n-> Type: {}\n-> Manufacturer: {}\n-> Model: {}'.format(mac, dev[0], dev[1], dev[2]))
        '''
        cqt = input('Is predicted identity correct? (yes/no) ')

        if cqt == 'no':
            ans = input('Please provide correct labels of device [{}].\n-> Type: '.format(mac))
            if ans != dev[0]:
                dev[0] = ans
            else:
                dev[0] = None

            ans = input('-> Manufacturer: ')
            if ans != dev[1]:
                dev[1] = ans
            else:
                dev[1] = None

            ans = input('-> Model: ')
            if ans != dev[2]:
                dev[2] = ans
            else:
                dev[2] = None
        else:
            for i in range(len(dev)):
                dev[i] = None
        '''
        # ----- Forward verification result to Device Detector. -----
        os.write(wrt, mac.encode())
        for i in range(len(dev)):
            if dev[i] == None:
                os.write(wrt, int(0).to_bytes(1, 'big'))
            else:
                os.write(wrt, len(dev[i]).to_bytes(1, 'big'))
                os.write(wrt, dev[i].encode())
        # -----
