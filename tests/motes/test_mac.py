import pytest

from motes.mac import Mote

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
