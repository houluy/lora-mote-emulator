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
from Crypto.Util import Padding

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
    pullack_f = '<s2ss8s'
    pushack_f = '<s2ss'
    pullresp_f = '<s2ss'

    def __init__(self, gateway_id):
        self.gateway_id = bytes.fromhex(gateway_id)
        self.version = b'\x02'
        self.pull_id = b'\x02'
        self.push_id = b'\x00'
        self.token_length = 2
        self.gateway_attributes = [
            'version',
            'token',
            'identifier',
        ]
        self.stat_attributes = [
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

        self.rxpk_attributes = [
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

    def add_data(self, rxpk, data):
        rxpk['rxpk'][0].update({
            'size': len(data),
            'data': data,
        })
        return rxpk

    @property
    def stat(self):
        return {
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

    @property
    def rxpk(self):
        return {
            'rxpk': [{
                "tmst": int(time.time()),
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

    def form_push_data(self, data):
        data = self.b64data(data)
        rxpk = self.add_data(self.rxpk, data)
        stat = self.stat
        rxpk.update(stat)
        return json.dumps(
            rxpk
        ).encode('ascii')

    def b64data(self, data):
        return base64.b64encode(data).decode()

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
        transmitter.send(self.pull_data)
        while True:
            res = transmitter.recv()
            self.parse_pullack(res[0])
            return True

    def parse_pullack(self, pullack):
        pullack = memoryview(pullack)
        version, token, identifier, gateway_eui =\
            struct.unpack(self.pullack_f, pullack)
        logger.info(
            ('PULL ACK -\n Version: {}, '
                'Token: {}, '
                'Identifier:{}, '
                'GatewayEUI: {}').format(
                version.hex(), token.hex(), identifier.hex(),
                gateway_eui.hex()))

    def push_data(self, data):
        json_obj = self.form_push_data(data=data)
        token = secrets.token_bytes(self.token_length)
        return b''.join([
            self.version,
            token,
            self.push_id,
            self.gateway_id,
            json_obj,
        ])

    def push(self, data, transmitter, mote):
        transmitter.send(self.push_data(data))
        while True:
            pushack = transmitter.recv()
            self.parse_pushack(pushack[0])
            pullresp = transmitter.recv()
            self.parse_pullresp(pullresp[0], mote)
            return True

    def parse_pushack(self, pushack):
        pushack = memoryview(pushack)
        version, token, identifier = struct.unpack(
            self.pushack_f,
            pushack
        )
        logger.info(
            ('PUSH ACK -\n'
                'Version: {}, '
                'Token: {}, '
                'Identifier: {}').format(
                    version.hex(),
                    token.hex(),
                    identifier.hex(),
                ))

    def parse_pullresp(self, pullresp, mote):
        pullresplen = len(pullresp)
        pullresp_f = self.pullresp_f + '{}s'.format(pullresplen - 4)
        version, token, identifier, txpk = struct.unpack(
            pullresp_f,
            pullresp,
        )
        txpk = json.loads(txpk.decode('ascii'))['txpk']
        logger.info(
            ('PULL RESP - \n'
                'Version: {}, '
                'Token: {}, '
                'Identifier: {},\n').format(
                    version.hex(),
                    token.hex(),
                    identifier.hex(),
                ))
        self.parse_txpk(txpk, mote)

    def form_json(self, attribute, typ='stat', **params):
        data = {
            k: params.get(k, '') for k in attribute
        }
        return {
            'stat': data
        } if typ == 'stat' else {'rxpk': [data]}

    def form_default_rxpk_data(self):
        raw_data = 'gIh3ZlWEIhEiIiIijn/FXA=='
        rxpk = self._add_data_to_rxpk(rxpk=self._default_rxpk, data=raw_data)
        return rxpk

    def parse_txpk(self, txpk, mote):
        data = memoryview(base64.b64decode(txpk.get('data')))
        data = mote.joinacpt_decrypt(data)
        msglen = len(data)
        pldlen = msglen - 1 - 4  # MHDR 1 byte, MIC 4 bytes
        pullresp_f = '<s{}s4s'.format(pldlen)
        mhdr, macpayload, mic = struct.unpack(pullresp_f, data)
        logger.info('Downlink MHDR: {}, MAC payload: {}, MIC: {}'.format(
                    mhdr.hex(), macpayload.hex(), mic.hex()))
        if (int.from_bytes(mhdr, 'big') >> 5) == 1:
            appnonce, netid, devaddr, dlsettings, rxdelay, cflist =\
                mote.parse_joinacpt(macpayload, mic)
            cflist = cflist if cflist else b''
            vmic = mote.cal_mic(
                mhdr,
                key=mote.appkey,
                typ='acpt',
                appnonce=appnonce,
                netid=netid,
                devaddr=devaddr,
                dlsettings=dlsettings,
                rxdelay=rxdelay,
                cflist=cflist,
            )
            if (vmic == mic):
                logger.info(
                    ('Join Accept (MIC verified) -\n'
                        'AppNonce: {}'
                        'NetID: {}'
                        'DevAddr: {}'
                        'DLSettings: {}'
                        'RxDelay: {}\n').format(
                            appnonce,
                            netid,
                            devaddr,
                            dlsettings,
                            rxdelay
                        ))
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
            caled_mic = Mote.cal_mic(key=NwkSKey, **mic_fields)
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
                FRMPayload = Mote.encrypt(
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


class Mote(BytesOperation):
    devnoncelen = 2
    miclen = 4
    joinreq_f = '<s8s8s2s4s'
    joinacpt_f = '<3s3s4sss'

    def __init__(self, appeui, deveui, appkey):
        self.appeui = appeui[::-1]
        self.deveui = deveui[::-1]
        self.appkey = appkey
        self.attributes = [
            'DevAddr',
            'MHDR',
            'FCnt',
            'FPort',
            'FRMPayload',
            'FCtrl',
            'direction',
            'FOpts',
        ]
        self.join_attributes = [
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

    @classmethod
    def from_file(cls, file):
        pass

    def join(self, gateway, transmitter):
        join_data = self.form_join()
        gateway.push(join_data, transmitter, self)

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
        return Mote.int2hexstring(FCtrl)

    @staticmethod
    def form_FHDR(DevAddr, FCtrl, FCnt, FOpts=''):
        DevAddr = Mote.str_rev(DevAddr)
        if len(FCnt) == 8:
            FCnt = FCnt[:4]
        # FCnt = Mote.str_rev(FCnt)
        FCtrl['FOptsLen'] = len(FOpts) // 2
        FCtrl = Mote.form_FCtrl(**FCtrl)
        return '{}{}{}{}'.format(DevAddr, FCtrl, FCnt, FOpts)

    @staticmethod
    def _base_block(**kwargs):
        kwargs['DevAddr'] = Mote.str_rev(kwargs.get('DevAddr'))
        kwargs['FCnt'] = Mote.str_rev(kwargs.get('FCnt'))
        return '00000000{direction}{DevAddr}{FCnt}00'.format(**kwargs)

    @staticmethod
    def _B0(**kwargs):
        base_block = Mote._base_block(**kwargs)
        return '49{base_block}{msg_length}'.format(
            base_block=base_block,
            msg_length=kwargs.get('msg_length')
        )

    @staticmethod
    def _A(**kwargs):
        base_block = Mote._base_block(**kwargs)
        return '01{base_block}{i}'.format(
            base_block=base_block,
            i=kwargs.get('i')
        )

    @staticmethod
    def cal_mic(mhdr, key, typ='normal', **kwargs):
        if typ == 'normal':
            msg = '{MHDR}{FHDR}{FPort}{FRMPayload}'.format(**kwargs)
            msg_bytes = bytearray.fromhex(msg)
            msg_length = '{:0>2x}'.format(len(msg_bytes) % 0xFF)
            B0 = Mote._B0(msg_length=msg_length, **kwargs)
            obj_msg = B0 + msg
            obj_msg = bytearray.fromhex(obj_msg)
        elif typ == 'join':
            msg = b''.join([
                mhdr,
                kwargs.get('appeui'),
                kwargs.get('deveui'),
                kwargs.get('devnonce'),
            ])
        else:
            msg = b''.join([
               mhdr,
               kwargs.get('appnonce'),
               kwargs.get('netid'),
               kwargs.get('devaddr'),
               kwargs.get('dlsettings'),
               kwargs.get('rxdelay'),
               kwargs.get('cflist'),
            ])
            print('msg: {}'.format(msg.hex()))
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(msg)
        return cobj.digest()[:Mote.miclen]

    def joinacpt_decrypt(self, macpayload):
        macpayloadlen = len(macpayload)
        print(macpayloadlen)
        macpayload = bytes(macpayload) + b''.join([
            b'\x00' for _ in range(16 - macpayloadlen)
        ])
        cryptor = AES.new(self.appkey, AES.MODE_ECB)
        print('Decrypt: {}'.format(macpayload.hex()))
        decrypt = cryptor.decrypt(macpayload)
        return decrypt[:macpayloadlen - 4]

    @staticmethod
    def encrypt(key, payload, **kwargs):
        pld_len = len(payload)
        k = math.ceil(pld_len / 16)
        payload += b'\x00'*(16*k - pld_len)
        cryptor = AES.new(key, AES.MODE_ECB)
        S = b''
        for i in range(1, k + 1):
            kwargs['i'] = '{:0>2x}'.format(i)
            _A_each = Mote._A(**kwargs)
            Ai = bytearray.fromhex(_A_each)
            Si = cryptor.encrypt(Ai)
            S += Si
        return b''.join(Mote.bytes_xor(S, payload))[:pld_len]

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

    def form_join(self):
        devnonce = secrets.token_bytes(self.devnoncelen)[::-1]
        mhdr = b'\x00'
        mic = self.cal_mic(
            key=self.appkey,
            typ='join',
            appeui=self.appeui,
            deveui=self.deveui,
            devnonce=devnonce,
            mhdr=mhdr
        )
        return struct.pack(
            self.joinreq_f,
            mhdr,
            self.appeui,
            self.deveui,
            devnonce,
            mic
        )

    def parse_joinacpt(self, joinacpt, mic):
        joinacptlen = len(joinacpt)
        self.joinacpt_f += '{}s'.format(joinacptlen - 12)
        return struct.unpack(
            self.joinacpt_f,
            joinacpt
        )

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
            FRMPayload = Mote.encrypt(
                key=enc_key,
                payload=FRMPayload,
                **kwargs
            ).hex()
        else:
            FRMPayload = ''
        if not kwargs.get('FHDR'):
            FHDR = Mote.form_FHDR(
                **{k: kwargs.get(k) for k in self.FHDR_list}
            )
        else:
            FHDR = kwargs.get('FHDR')
        kwargs['FRMPayload'] = FRMPayload
        kwargs['FHDR'] = FHDR
        MIC = Mote.cal_mic(key=NwkSKey, **kwargs)
        return ''.join([
            kwargs.get('MHDR'),
            kwargs.get('FHDR'),
            kwargs.get('FPort'),
            FRMPayload,
            MIC
        ])

    def parse(self):
        pass
