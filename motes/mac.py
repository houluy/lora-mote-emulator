import math
import time
import base64
import json
import logging
import secrets
import struct
from pprint import pprint
from colorline import cprint
from functools import partial
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
# from Crypto.Util import Padding

nprint = partial(cprint, color='g', bcolor='k')
eprint = partial(cprint, color='c', bcolor='r')


GMTformat = "%Y-%m-%d %H:%M:%S GMT"


logger = logging.getLogger('main')


class BytesOperation:
    @staticmethod
    def str_rev(obj_str):
        return ''.join([
            obj_str[x:x+2] for x in range(len(obj_str))
        ][-2::-2])

    @staticmethod
    def bytes_xor(bytea, byteb):
        return [bytearray.fromhex(
            '{:0>2x}'.format(x ^ y)) for (x, y) in zip(bytea, byteb)
        ]

    @staticmethod
    def int2hexstring(number):
        return '{:0>2x}'.format(number)


class GatewayOp(BytesOperation):
    '''
    Gateway from Semtech
    '''
    def __init__(self, gateway_id):
        self.gateway_id = bytes.fromhex(gateway_id)
        self.version = b'\x02'
        self.pull_id = b'\x02'
        self.token_length = 2
        self._call = {
            'pull': self.pull_data,
            'push': self.push_data,
        }
        self._gateway_attributes = [
            'version',
            'token',
            'identifier',
        ]
        self._stat_attributes = [
            'time',
            'lati',
            'long',
            'alti',
            'rxnb',
            'rxok',
            'rwfw',
            'ackr',
            'dwnb',
            'txnb',
        ]

        self._rxpk_attributes = [
            'time',
            'tmst',
            'freq',
            'chan',
            'rfch',
            'stat',
            'modu',
            'datr',
            'codr',
            'rssi',
            'lsnr',
            'size',
            'data',
        ]

        self._default_rxpk = {
            'rxpk': [{
                "tmst": 854980284,
                "chan": 7,
                "rfch": 0,
                "freq": 435.9,
                "stat": 1,
                "modu": 'LORA',
                "datr": 'SF12BW125',
                "codr": '4/5',
                "lsnr": 2,
                "rssi": -119,
                "size": 17,
                "data": '',
            }]
        }

        self._default_stat = {
            "stat": {
                "time": time.strftime(GMTformat, time.localtime()),
                "rxnb": 1,
                "rxok": 0,
                "rxfw": 0,
                "ackr": 100,
                "dwnb": 0,
                "txnb": 0,
            }
        }
        self._default_data = 'gIh3ZlWEIhEiIiIiEwhl92tzPc8CNUC0'

    @property
    def gateway_attributes(self):
        return self._gateway_attributes

    @property
    def rxpk_attributes(self):
        return self._rxpk_attributes

    @property
    def stat_attributes(self):
        return self._stat_attributes

    def _add_data_to_rxpk(self, rxpk, data, data_size=17):
        rxpk['rxpk'][0]['size'] = data_size
        rxpk['rxpk'][0]['data'] = data
        return rxpk

    def form_gateway_data(self, data=None, enc=False, rxpk=None, stat=None):
        data_size = len(data) // 2
        if data is None:
            data = self._default_data
        else:
            if enc:
                data = self._b64data(data)
        if rxpk is None:
            rxpk = self._add_data_to_rxpk(self._default_rxpk, data, data_size)
        if stat is None:
            stat = self._default_stat
        rxpk.update(stat)
        return json.dumps(
            rxpk
        ).encode('ascii')

    def _b64data(self, data):
        return base64.b64encode(bytearray.fromhex(data)).decode()

    @property
    def pull_data(self):
        token = secrets.token_bytes(self.token_length)
        return b''.join([
            self.version,
            token,
            self.pull_id,
            self.gateway_id
        ])

    def pull(self, transmitter):
        try:
            transmitter.send(self.pull_data)
        except Exception:
            return False
        while True:
            try:
                res = transmitter.recv()
            except Exception:
                return False
            else:
                print(res)
                return True

    def parse_pullack(self, pullack):
        pullack = memoryview(pullack)
        pass

    def push_data(
        self,
        data=None,
        json_obj=None,
        version='02',
        token='83ec',
        identifier='00'
    ):
        if data:
            json_bytes = self.form_gateway_data(data=data, enc=True)
        elif json_obj:
            json_bytes = json_obj
        self.data_dict = {
            'version': version,
            'token': token,
            'identifier': identifier,
            'gateway_id': self.gateway_id,
            'json_obj': json_bytes.hex(),
        }
        self.bytes_str = (
            '{version}'
            '{token}'
            '{identifier}'
            '{gateway_id}'
            '{json_obj}'.format(**self.data_dict)
        )
        return bytearray.fromhex(self.bytes_str)

    def form_json(self, attribute, typ='stat', **params):
        data = {
            k: params.get(k, '') for k in attribute
        }
        return {
            'stat': data
        } if typ == 'stat' else {'rxpk': [data]}

    def form_default_rxpk_data(self):
        raw_data = 'gIh3ZlWEIhEiIiIijn/FXA=='
        # rxpk = self.form_json(self._rxpk_attributes, typ='rxpk', **params)
        rxpk = self._add_data_to_rxpk(rxpk=self._default_rxpk, data=raw_data)
        return rxpk

    def get_txpk_data(self, keys, txpk):
        macpayload = base64.b64decode(txpk.get('data'))
        nprint('RAW Dlk MAC Payload in hex:')
        print(macpayload.hex())
        MHDR = macpayload[0:1]
        macpayload = macpayload[1:]
        if (int.from_bytes(MHDR, 'big') >> 5) == 1:
            AppKey = keys.get('AppKey')
            macpayload = DeviceOp.join_acpt_decrypt(
                key=AppKey,
                join_acpt=macpayload
            )
            AppNonce = macpayload[0:3]
            NetID = macpayload[3:6]
            DevAddr = macpayload[6:10]
            DLSettings = macpayload[10:11]
            RxDelay = macpayload[11:12]
            CFList = macpayload[12:-4]
            MIC = macpayload[-4:]
            MIC_obj = {
                'MHDR': MHDR.hex(),
                'AppNonce': AppNonce.hex(),
                'NetID': NetID.hex(),
                'DevAddr': DevAddr.hex(),
                'DLSettings': DLSettings.hex(),
                'RxDelay': RxDelay.hex(),
                'CFList': '',
            }
            if CFList:
                MIC_obj['CFList'] = CFList.hex()
            mic = DeviceOp.cal_mic(
                key=AppKey,
                typ='acpt',
                **MIC_obj
            )
            if (MIC.hex() == mic):
                print('MIC matched')
                return MIC_obj
            else:
                raise ValueError('MIC mismatch')
        else:
            NwkSKey = keys.get('NwkSKey')
            AppSKey = keys.get('AppSKey')
            DevAddr = macpayload[3::-1]
            FCtrl = macpayload[4:5]
            FOptsLen = (ord(FCtrl) & 0b1111)
            FCnt = macpayload[5:7]
            FCnt += b'\x00\x00'
            FCnt = bytes(reversed(FCnt))
            FOptsOffset = 7 + FOptsLen
            FOpts = macpayload[7:FOptsOffset]
            FHDR = macpayload[:7+FOptsLen]
            msg = macpayload[FOptsOffset:]
            FPort = msg[:1]
            FRMPayload = msg[1:-4]
            MIC = macpayload[-4:]
            mic_fields = {
                'MHDR': MHDR.hex(),
                'FHDR': FHDR.hex(),
                'FPort': FPort.hex(),
                'FRMPayload': FRMPayload.hex(),
                'DevAddr': DevAddr.hex(),
                'FCnt': FCnt.hex(),
                'direction': '01',
            }
            nprint('---Original fields---')
            pprint(mic_fields)
            caled_mic = DeviceOp.cal_mic(key=NwkSKey, **mic_fields)
            if caled_mic == MIC.hex():
                nprint('---MIC matched---')
                # Decrypt
                decrypt_fields = {
                    'DevAddr': DevAddr.hex(),
                    'FCnt': FCnt.hex(),
                    'direction': '01',
                }
                if FPort == b'\x00':
                    key = NwkSKey
                else:
                    key = AppSKey
                FRMPayload = DeviceOp.encrypt(
                    key=key,
                    payload=FRMPayload,
                    **decrypt_fields
                )
                log_json = {
                    'MHDR': MHDR.hex(),
                    'DevAddr': DevAddr.hex(),
                    'FCtrl': FCtrl.hex(),
                    'FOptsLen': FOptsLen,
                    'FCnt': FCnt.hex(),
                    'FOpts': FOpts.hex(),
                    'FPort': FPort.hex(),
                    'FRMPayload': FRMPayload.hex(),
                    'MIC': MIC.hex(),
                }
                return log_json
            else:
                raise ValueError('Dlk MIC MISMATCH!!!')

    def parse_dlk(self, downlink):
        if downlink[3] in (1, 4):
            return None
        else:
            txpk = downlink[4:]
            nprint('---TXPK---')
            print(txpk)
            txpk_json = json.loads(txpk.decode('ascii'))
            return txpk_json.get('txpk')


class DeviceOp(BytesOperation):
    def __init__(self):
        self._attributes = [
            'DevAddr',
            'MHDR',
            'FCnt',
            'FPort',
            'FRMPayload',
            'FCtrl',
            'direction',
            'FOpts',
        ]
        self._join_attributes = [
            'AppEUI',
            'DevEUI',
            'DevNonce',
            'MHDR',
        ]
        self.FHDR_list = [
            'DevAddr',
            'FCtrl',
            'FCnt',
            'FOpts',
        ]

    @property
    def attributes(self):
        return self._attributes

    @property
    def join_attributes(self):
        return self._join_attributes

    @staticmethod
    def form_FCtrl(
        direction='up',
        ADR=0,
        ADRACKReq=0,
        ACK=0,
        ClassB=0,
        FOptsLen=0,
        FPending=0
    ):
        if direction == 'up':
            FCtrl = (ADR << 7) + (ADRACKReq << 6) + (ACK << 5) + (ClassB << 4)
            FCtrl += (FOptsLen & 0b1111)
        else:
            FCtrl = (ADR << 7) + (0 << 6) + (ACK << 5) + (FPending << 4)
            FCtrl += (FOptsLen & 0b1111)
        return DeviceOp.int2hexstring(FCtrl)

    @staticmethod
    def form_FHDR(DevAddr, FCtrl, FCnt, FOpts=''):
        DevAddr = DeviceOp.str_rev(DevAddr)
        if len(FCnt) == 8:
            FCnt = FCnt[:4]
        # FCnt = DeviceOp.str_rev(FCnt)
        FCtrl['FOptsLen'] = len(FOpts) // 2
        FCtrl = DeviceOp.form_FCtrl(**FCtrl)
        return '{}{}{}{}'.format(DevAddr, FCtrl, FCnt, FOpts)

    @staticmethod
    def _base_block(**kwargs):
        kwargs['DevAddr'] = DeviceOp.str_rev(kwargs.get('DevAddr'))
        kwargs['FCnt'] = DeviceOp.str_rev(kwargs.get('FCnt'))
        return '00000000{direction}{DevAddr}{FCnt}00'.format(**kwargs)

    @staticmethod
    def _B0(**kwargs):
        base_block = DeviceOp._base_block(**kwargs)
        return '49{base_block}{msg_length}'.format(
            base_block=base_block,
            msg_length=kwargs.get('msg_length')
        )

    @staticmethod
    def _A(**kwargs):
        base_block = DeviceOp._base_block(**kwargs)
        return '01{base_block}{i}'.format(
            base_block=base_block,
            i=kwargs.get('i')
        )

    @staticmethod
    def cal_mic(key, typ='normal', **kwargs):
        if typ == 'normal':
            # pdb.set_trace()
            msg = '{MHDR}{FHDR}{FPort}{FRMPayload}'.format(**kwargs)
            msg_bytes = bytearray.fromhex(msg)
            msg_length = '{:0>2x}'.format(len(msg_bytes) % 0xFF)
            B0 = DeviceOp._B0(msg_length=msg_length, **kwargs)
            obj_msg = B0 + msg
            obj_msg = bytearray.fromhex(obj_msg)
        elif typ == 'join':
            msg = '{MHDR}{AppEUI}{DevEUI}{DevNonce}'.format(**kwargs)
            obj_msg = bytearray.fromhex(msg)
        else:
            msg = '{MHDR}{AppNonce}{NetID}{DevAddr}\
                {DLSettings}{RxDelay}{CFList}'.format(**kwargs)
            obj_msg = bytearray.fromhex(msg)
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(obj_msg)
        return cobj.hexdigest()[:8]

    @staticmethod
    def join_acpt_decrypt(key, join_acpt):
        cryptor = AES.new(key, AES.MODE_ECB)
        return cryptor.encrypt(join_acpt)

    @staticmethod
    def encrypt(key, payload, **kwargs):
        pld_len = len(payload)
        eprint('---FRMPayload Length---')
        k = math.ceil(pld_len / 16)
        payload += b'\x00'*(16*k - pld_len)
        cryptor = AES.new(key, AES.MODE_ECB)
        S = b''
        for i in range(1, k + 1):
            kwargs['i'] = '{:0>2x}'.format(i)
            _A_each = DeviceOp._A(**kwargs)
            Ai = bytearray.fromhex(_A_each)
            Si = cryptor.encrypt(Ai)
            S += Si
        return b''.join(DeviceOp.bytes_xor(S, payload))[:pld_len]

    @staticmethod
    def gen_keys(AppKey, NetID, AppNonce, DevNonce):
        cryptor = AES.new(AppKey, AES.MODE_ECB)
        pad = '00000000000000'
        NwkSKeybytes = '01' + AppNonce + NetID + DevNonce + pad
        AppSKeybytes = '02' + AppNonce + NetID + DevNonce + pad
        NwkSKeybytes = bytes.fromhex(NwkSKeybytes)
        AppSKeybytes = bytes.fromhex(AppSKeybytes)
        # NwkSKeybytes = Padding.pad(NwkSKeybytes, 16)
        # AppSKeybytes = Padding.pad(AppSKeybytes, 16)
        NwkSKey = cryptor.encrypt(NwkSKeybytes)
        AppSKey = cryptor.encrypt(AppSKeybytes)
        return {
            'NwkSKey': NwkSKey.hex(),
            'AppSKey': AppSKey.hex(),
        }

    def form_join(self, key, **kwargs):
        AppEUI = DeviceOp.str_rev(kwargs.get('AppEUI'))
        DevEUI = DeviceOp.str_rev(kwargs.get('DevEUI'))
        DevNonce = DeviceOp.str_rev(kwargs.get('DevNonce'))
        MIC = DeviceOp.cal_mic(
            key=key,
            typ='join',
            AppEUI=AppEUI,
            DevEUI=DevEUI,
            DevNonce=DevNonce,
            MHDR=kwargs.get('MHDR')
        )
        return ''.join([
            kwargs.get('MHDR'),
            AppEUI,
            DevEUI,
            DevNonce,
            MIC
        ])

    def form_payload(self, NwkSKey, AppSKey, **kwargs):
        FRMPayload = kwargs.pop('FRMPayload')
        FPort = kwargs.get('FPort')
        if FPort == '00':
            enc_key = NwkSKey
            FRMPayload = bytes.fromhex(FRMPayload)
        else:
            enc_key = AppSKey
        if FRMPayload:
            if isinstance(FRMPayload, str):
                FRMPayload = FRMPayload.encode()
            FRMPayload = DeviceOp.encrypt(
                key=enc_key,
                payload=FRMPayload,
                **kwargs
            ).hex()
        else:
            FRMPayload = ''
        if not kwargs.get('FHDR'):
            FHDR = DeviceOp.form_FHDR(
                **{k: kwargs.get(k) for k in self.FHDR_list}
            )
        else:
            FHDR = kwargs.get('FHDR')
        kwargs['FRMPayload'] = FRMPayload
        kwargs['FHDR'] = FHDR
        MIC = DeviceOp.cal_mic(key=NwkSKey, **kwargs)
        return ''.join([
            kwargs.get('MHDR'),
            kwargs.get('FHDR'),
            kwargs.get('FPort'),
            FRMPayload,
            MIC
        ])

    def parse(self):
        pass
