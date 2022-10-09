import os

def run(rd, wrt):
    dev = [None, None, None]

    print('<Verifier> Ready for user verification.')
    while True:
        # ----- Receive predicted labels of device from Device Detector. -----
        mac = os.read(rd, 17).decode()
        for i in range(len(dev)):
            n = int.from_bytes(os.read(rd, 1), 'big')
            dev[i] = os.read(rd, n).decode()
        # ----- Ask for user verification. -----
        print('<Verifier> Identity of device [{}]:\n-> Type: {}\n-> Manufacturer: {}\n-> Model: {}'.format(mac, dev[0], dev[1], dev[2]))
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
        # ----- Forward verification result to Device Detector. -----
        os.write(wrt, mac.encode())
        for i in range(len(dev)):
            if dev[i] == None:
                os.write(wrt, int(0).to_bytes(1, 'big'))
            else:
                os.write(wrt, len(dev[i]).to_bytes(1, 'big'))
                os.write(wrt, dev[i].encode())
        # -----
