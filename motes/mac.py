import base64
import json
import logging
import math
import pdb
import pickle
import secrets
import struct
import time
import random
from functools import partial
from pprint import pprint

from colorline import cprint
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util import Padding

nprint = partial(cprint, color='g', bcolor='k')
eprint = partial(cprint, color='c', bcolor='r')


GMTformat = "%Y-%m-%d %H:%M:%S GMT"


logger = logging.getLogger('main')


class GatewayOp:
    pullack_f = '<s2ss8s'
    pushack_f = '<s2ss'
    pullresp_f = '<s2ss'

    def __init__(self, gateway_id):
        self.gateway_id = bytes.fromhex(gateway_id)
        self.version = b'\x02'
        self.pull_id = b'\x02'
        self.push_id = b'\x00'
        self.token_length = 2

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

    def parse_txpk(self, txpk, mote):
        data = memoryview(base64.b64decode(txpk.get('data')))
        mhdr = data[:1]
        encrypted_data = data[1:]
        macpayloadmic = mote.joinacpt_decrypt(encrypted_data)
        msglen = len(data)
        pldlen = msglen - 1 - 4  # MHDR 1 byte, MIC 4 bytes
        pullresp_f = '<{}s4s'.format(pldlen)
        macpayload, mic = struct.unpack(pullresp_f, macpayloadmic)
        if (int.from_bytes(mhdr, 'big') >> 5) == 1:
            mote.parse_joinacpt(mhdr, macpayload, mic)
        else:  # PULL RESP for app data
            mote.parse_macpld(mhdr, macpayload, mic)

    def parse_dlk(self, downlink):
        if downlink[3] in (1, 4):
            return None
        else:
            txpk = downlink[4:]
            nprint('---TXPK---')
            print(txpk)
            txpk_json = json.loads(txpk.decode('ascii'))
            return txpk_json.get('txpk')


class Mote:
    devnoncelen = 2
    miclen = 4
    joinreq_f = '<s8s8s2s4s'
    joinacpt_f = '<3s3s4sss'
    fhdr_f = '<4ssH'

    def __init__(self, appeui, deveui, appkey, conffile):
        self.appeui = appeui[::-1]
        self.deveui = deveui[::-1]
        self.appkey = appkey
        self.conffile = conffile
        self.FHDR_list = [
            'DevAddr',
            'FCtrl',
            'FCnt',
            'FOpts',
        ]

    @classmethod
    def load(cls, file):
        with open(file, 'rb') as f:
            obj = pickle.load(f)
        obj.conffile = file
        return obj

    def save(self):
        with open(self.conffile, 'wb') as f:
            pickle.dump(self, f)

    def join(self, gateway, transmitter):
        join_data = self.form_join()
        gateway.push(join_data, transmitter, self)

    def app(self, gateway, transmitter):
        app_data = self.form_app()
        gateway.push(app_data, transmitter, self)

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

    def form_fctrl(self, foptslen):
        FCtrl = (ADR << 7) + (ADRACKReq << 6) + (ACK << 5) + (ClassB << 4)
        FCtrl += (FOptsLen & 0b1111)
    else:
        FCtrl = (ADR << 7) + (0 << 6) + (ACK << 5) + (FPending << 4)
        FCtrl += (FOptsLen & 0b1111)
        return Mote.int2hexstring(FCtrl)

    def form_fhdr(self, fopts=b''):
        foptslen = len(fopts)
        self.fhdr_f += '{}s'.format(foptslen)
        fctrl = self.form_fctrl(foptslen)
        return struct.pack(self.fhdr_f, self.devaddr, fctrl, self.fcnt, fopts)

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
            msg = b''.join([
                mhdr,
                kwargs.get('fhdr'),
                kwargs.get('fport'),
                kwargs.get('msg'),
            ])
            msglen = len(msg)
            #msg_length = '{:0>2x}'.format(len(msg_bytes) % 0xFF)
            B0 = Mote._B0(msglen=msglen, **kwargs)
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
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(msg)
        return cobj.digest()[:Mote.miclen]

    def joinacpt_decrypt(self, macpayload):
        macpayloadlen = len(macpayload)
        macpayload = bytes(macpayload) + b''.join([
            b'\x00' for _ in range(16 - macpayloadlen)
        ])
        cryptor = AES.new(self.appkey, AES.MODE_ECB)
        return cryptor.encrypt(macpayload)

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

    def gen_keys(self):
        cryptor = AES.new(self.appkey, AES.MODE_ECB)
        pad = b'\x00\x00\x00\x00\x00\x00\x00'
        nwkskeymsg = b'\01' + self.appnonce + self.netid + self.devnonce + pad
        appskeymsg = b'\02' + self.appnonce + self.netid + self.devnonce + pad
        nwkskey = cryptor.encrypt(nwkskeymsg)
        appskey = cryptor.encrypt(appskeymsg)
        return nwkskey, appskey

    def form_join(self):
        self.devnonce = secrets.token_bytes(self.devnoncelen)[::-1]
        mhdr = b'\x00'
        mic = self.cal_mic(
            key=self.appkey,
            typ='join',
            appeui=self.appeui,
            deveui=self.deveui,
            devnonce=self.devnonce,
            mhdr=mhdr
        )
        return struct.pack(
            self.joinreq_f,
            mhdr,
            self.appeui,
            self.deveui,
            self.devnonce,
            mic
        )

    def parse_joinacpt(self, mhdr, joinacpt, mic):
        self.cflist = joinacpt[12:] if joinacpt[12:] else b''
        self.appnonce, self.netid, self.devaddr, self.dlsettings, self.rxdelay = struct.unpack(
                self.joinacpt_f,
                joinacpt[:12]
            )
        self.cflist = self.cflist if self.cflist else b''
        vmic = self.cal_mic(
            mhdr,
            key=self.appkey,
            typ='acpt',
            appnonce=self.appnonce,
            netid=self.netid,
            devaddr=self.devaddr,
            dlsettings=self.dlsettings,
            rxdelay=self.rxdelay,
            cflist=self.cflist,
        )
        if (vmic == mic):
            logger.info(
                ('Join Accept (MIC verified) -\n'
                    'AppNonce: {}, '
                    'NetID: {}, '
                    'DevAddr: {}, '
                    'DLSettings: {}, '
                    'RxDelay: {}\n').format(
                        self.appnonce.hex(),
                        self.netid.hex(),
                        self.devaddr.hex(),
                        self.dlsettings.hex(),
                        self.rxdelay.hex()
                    ))
            self.nwkskey, self.appskey = self.gen_keys()
            self.fcnt = 0
            self.save()
        else:
            raise ValueError('MIC mismatch')

    def form_app(self, msg, fopts):
        mhdr = b'\x80'
        fhdr = self.form_fhdr(fopts)
        fhdrlen = len(fhdr)
        fport = random.randint(2, 255)
        msglen = len(msg)
        app_f = '<s{fhdrlen}sB{msglen}s4s'.format(
            fhdrlen=fhdrlen,
            msglen=msglen,
        )
        mic = self.cal_mic(
            mhdr,
            self.nwkskey,
            fhdr=fhdr,
            fport=fport,
            msg=msg,
        )
        return struct.pack(
            mhdr,
            fhdr,
            fport,
            msg,
            mic,
        )
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
