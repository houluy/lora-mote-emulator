import pytest
import struct

from motes.mac import Mote
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

def test_parse_byte():
    byte = (0b11010010).to_bytes(1, 'big')
    name = ('a', 'b', 'c')
    offset = (5, 2, 0)
    bitlength = (3, 3, 2)
    res = Mote.parse_byte(byte, name, offset, bitlength)
    a, b, c = res['a'], res['b'], res['c']
    assert a == 0b110
    assert b == 0b100
    assert c == 0b10

def test_rejoin():
    joineui = b'\xAA' * 8
    deveui = b'\x00' * 8
    appkey = b'\x11' * 16
    nwkkey = b'\x22' * 16
    device_file = 'test.pkl'
    mote = Mote(joineui, deveui, appkey, nwkkey, device_file)
    print(mote.form_rejoin(0))

def test_calcmic():
    joinreqtype = b'\x00'
    joineui = b'\xa0\x00\x00\x00\x00\x00\x00\x00'
    deveui = b'\xd0\x00\x00\x00\x00\x00\x00\x00'
    # 0c00000000005bdfb3018001184f84e85684b85e84886684586e84004cc63b75
    # 4cc63b75
    nwkKey = bytes.fromhex('ee000000000000000000000000000000')
    jsintkeymsg = b'\x06' + deveui[::-1] + b'\x00\x00\x00\x00\x00\x00\x00'
    assert len(jsintkeymsg) == 16
    cryptor = AES.new(nwkKey, AES.MODE_ECB)
    jsintkey = cryptor.encrypt(jsintkeymsg)
    devnonce = struct.pack('<H', 14)
    mhdr = b'\x20'
    joinnonce = b'\x00\x00\x0c'
    netid = b'\x00\x00\x00'
    #devaddr = b'\x01\x87\x34\x23'
    devaddr = b'\x01\xb3\xdf\x5b'
    dlsettings = b'\x80'
    rxdelay = b'\x01'
    cflist = bytes.fromhex('184f84e85684b85e84886684586e8400')
    msg = joinreqtype +\
        joineui[::-1] +\
        devnonce[::-1]+\
        mhdr+\
        joinnonce[::-1]+\
        netid[::-1]+\
        devaddr[::-1]+\
        dlsettings+\
        rxdelay+\
        cflist
    print(msg.hex())
    cobj = CMAC.new(jsintkey, ciphermod=AES)
    cobj.update(msg)
    rmic = bytes.fromhex('4cc63b75')
    print(rmic.hex(), cobj.digest()[:4].hex())


