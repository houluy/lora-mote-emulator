import base64
import json
import logging
import math
import pickle
import random
import secrets
import struct
import time
import pdb

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

GMTformat = "%Y-%m-%d %H:%M:%S GMT"

logger = logging.getLogger('main')

MHDR_LEN = 1
MTYPE_OFFSET = 5
JOINACPT_CFLIST_OFFSET = 12
AES_BLOCK = 16


class MICError(ValueError):
    pass


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
        logger.info(
            ('PULL DATA -\nVersion: {}, '
                'Token: {}, '
                'Identifier: {}, '
                'GatewayEUI: {}').format(
                    self.version.hex(),
                    token.hex(),
                    self.pull_id.hex(),
                    self.gateway_id.hex()
                ))

        return b''.join([
            self.version,
            token,
            self.pull_id,
            self.gateway_id
        ])

    def pull(self, transmitter):
        transmitter.send(self.pull_data)
        res = transmitter.recv()
        self.parse_pullack(res[0])

    def parse_pullack(self, pullack):
        pullack = memoryview(pullack)
        version, token, identifier, gateway_eui =\
            struct.unpack(self.pullack_f, pullack)
        logger.info(
            ('PULL ACK -\nVersion: {}, '
                'Token: {}, '
                'Identifier: {}, '
                'GatewayEUI: {}').format(
                    version.hex(),
                    token.hex(),
                    identifier.hex(),
                    gateway_eui.hex()
                ))

    def push_data(self, data):
        json_obj = self.form_push_data(data=data)
        token = secrets.token_bytes(self.token_length)
        logger.info(
            ('PUSH DATA -\nVerson: {}, '
                'Token: {}, '
                'Identifier: {}, '
                'GatewayEUI: {}').format(
                    self.version.hex(),
                    token.hex(),
                    self.push_id.hex(),
                    self.gateway_id.hex(),
                ))

        return b''.join([
            self.version,
            token,
            self.push_id,
            self.gateway_id,
            json_obj,
        ])

    def push(self, data, transmitter, mote):
        transmitter.send(self.push_data(data))
        pushack = transmitter.recv()
        self.parse_pushack(pushack[0])
        pullresp = transmitter.recv()
        self.parse_pullresp(pullresp[0], mote)

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
                'Identifier: {} --').format(
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
        mhdr = data[:MHDR_LEN]
        if (int.from_bytes(mhdr, 'big') >> 5) == 1:
            encrypted_data = data[MHDR_LEN:]
            macpayloadmic = mote.joinacpt_decrypt(encrypted_data)
            msglen = len(data)
            pldlen = msglen - 1 - 4  # MHDR 1 byte, MIC 4 bytes
            pullresp_f = '<{}s4s'.format(pldlen)
            macpayload, mic = struct.unpack(pullresp_f, macpayloadmic)
            mote.parse_joinacpt(mhdr, macpayload, mic)
        else:  # PULL RESP for app data
            macpayload = data[MHDR_LEN:-4]
            mic = data[-4:]
            mote.parse_macpld(mhdr, macpayload, mic)


class Mote:
    devnoncelen = 2
    miclen = 4
    joinreq_f = '<s8s8s2s4s'
    joinacpt_f = '<3s3s4sss'
    fhdr_f = '<4ssH'
    mic_msg_tpl = {
        'join': [
            'mhdr',
            'joineui',
            'deveui',
            'devnonce',
        ],
        'acpt': [
            'joinreqtyp',
            'joineui',
            'devnonce',
            'mhdr',
            'joinnonce',
            'netid',
            'devaddr',
            'dlsettings',
            'rxdelay',
            'cflist'
        ],
    }

    def __init__(self, joineui, deveui, appkey, nwkkey, conffile, version='1.0.2'):
        self.joineui = joineui[::-1]
        self.deveui = deveui[::-1]
        self.appkey, self.nwkkey = appkey, nwkkey
        self.conffile = conffile
        self.version = version

        self._initialization_by_ver()

    def _initialize(self, optneg):
        if optneg:
            # Server supports LoRaWAN 1.1 and later
            # Generate FNwkSIntKey, SNwkSIntKey, NwkSEncKey and AppSKey
            nwkskey_prefix = b''.join([
                self.joinnonce,
                self.joineui,
                self.devnonce,
            ])
            fnwksint_msg, snwksint_msg, nwksenc_msg = [
                (prefix + nwkskey_prefix).ljust(AES_BLOCK, b'\x00')
                for prefix in (b'\x01', b'\x03', b'\x04')
            ]
            self.fnwksintkey, self.snwksintkey, self.nwksenckey = self.gen_keys(
                self.nwkkey, (fnwksint_msg, snwksint_msg, nwksenc_msg)
            )
            appsmsg = b''.join([
                b'\x02',
                self.joinnonce,
                self.joineui,
                self.devnonce,
            ]).ljust(AES_BLOCK, b'\x00')
            self.appskey, = self.gen_keys(self.appkey, (appsmsg,))
        else:
            # Server only supports LoRaWAN 1.0
            sesskey_prefix = b''.join([
                self.joinnonce,
                self.netid,
                self.devnonce,
            ])
            apps_msg, fnwksint_msg = [
                (prefix + sesskey_prefix).ljust(AES_BLOCK, b'\x00')
                for prefix in (b'\x02', b'\x01')
            ]
            self.appskey, self.fnwksintkey = self.gen_keys(self.nwkkey, (apps_msg, fnwksint_msg))
            self.snwksintkey = self.nwksenckey = self.fnwksintkey
        self.fcnt = 0
        self.save()

    def _initialization_by_ver(self):
        if self.version == '1.0.2':
            self.join_mic_key = self.nwkkey
            self.joinacpt_dec_key = self.nwkkey
        elif self.version == '1.1':
            self.join_mic_key = self.nwkkey
            self.joinacpt_dec_key = self.nwkkey
            # Generate JS Int & Enc keys
            # 0x06 \ 0x05 | DevEUI | pad 
            jsintkeymsg, jsenckeymsg = [
                (prefix + self.deveui).ljust(AES_BLOCK, b'\x00') 
                for prefix in (b'\x06', b'\x05')
            ]
            self.jsintkey, self.jsenckey = self.gen_keys(self.nwkkey, (jsintkeymsg, jsenckeymsg))

    @staticmethod
    def bytes_xor(b1, b2):
        result = bytearray()
        for b1, b2 in zip(b1, b2):
            result.append(b1 ^ b2)
        return bytes(result)

    @staticmethod
    def parse_byte(data: bytes, name: list, offset: list, bitlength: list):
        '''
        Parse one-byte data into several fields by bits
        @ data: Original byte data
        @ name: List of names for each field
        @ offset: Offset number of each field
        @ bitlength: Bit length of each field

        % dict: field name - field value in integer
        '''
        assert len(name) == len(offset) == len(length)
        data = int.from_bytes(data)
        res = {}
        for ind, value in enumerate(name):
            off, leng = offset[ind], length[ind]
            binmask = '1'*leng + '0'*off
            mask = int(binmask, base=2)
            res[name] = (data & mask) >> off
        return res

    @classmethod
    def load(cls, filename):
        with open(filename, 'rb') as f:
            obj = pickle.load(f)
        obj.conffile = filename
        return obj

    def save(self):
        with open(self.conffile, 'wb') as f:
            pickle.dump(self, f)

    def join(self, gateway, transmitter):
        join_data = self.form_join()
        gateway.push(join_data, transmitter, self)

    def app(self, gateway, transmitter, msg, fopts):
        app_data = self.form_app(msg, self.app_preproc, fopts)
        gateway.push(app_data, transmitter, self)

    def cmd(self, gateway, transmitter, cmd):
        cmd_data = self.form_app(cmd, self.cmd_preproc, b'')
        gateway.push(cmd_data, transmitter, self)

    def form_fctrl(self, foptslen):
        return (0x2f & (foptslen | 0xF0)).to_bytes(1, 'big')

    def form_fhdr(self, fopts):
        foptslen = len(fopts)
        if foptslen:
            fopts = fopts
            # fOpts encryption is only required in LoRaWAN 1.1.
            # fopts = self.encrypt(
            #     self.nwkskey,
            #     fopts,
            #     direction=0,
            #     devaddr=self.devaddr,
            #     fcnt=self.fcnt,
            # )
        fhdr_f = self.fhdr_f + '{}s'.format(foptslen)
        fctrl = self.form_fctrl(foptslen)
        return struct.pack(fhdr_f, self.devaddr, fctrl, self.fcnt, fopts)

    def cal_mic(self, key, typ='app', **kwargs):
        if typ == 'app':
            B0_f = '<cHHB4sIBB'
            msg = b''.join([
                kwargs.get('mhdr'),
                kwargs.get('fhdr'),
                kwargs.get('fport').to_bytes(1, 'big'),
                kwargs.get('frmpld'),
            ])
            msglen = len(msg)
            conffcnt = 0
            B0 = struct.pack(
                B0_f,
                b'\x49',
                conffcnt,
                0,
                kwargs.get('direction'),
                kwargs.get('devaddr'),
                kwargs.get('fcnt'),
                0,
                msglen
            )
            msg = B0 + msg
        else:
            msgname = self.mic_msg_tpl[typ]
            def attr_by_name(attr):
                try:
                    return getattr(self, attr)
                except AttributeError:
                    return kwargs.get(attr)
            msg = b''.join(map(attr_by_name, msgname))
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(msg)
        return cobj.digest()[:Mote.miclen]

    def joinacpt_decrypt(self, macpayload):
        macpayloadlen = len(macpayload)
        macpayload = bytes(macpayload) + b''.join([
            b'\x00' for _ in range(16 - macpayloadlen)
        ])
        cryptor = AES.new(self.joinacpt_dec_key, AES.MODE_ECB)
        return cryptor.encrypt(macpayload)

    @staticmethod
    def encrypt(key, payload, direction=0, **kwargs):
        pldlen = len(payload)
        k = math.ceil(pldlen / 16)
        payload += b'\x00'*(16*k - pldlen)
        cryptor = AES.new(key, AES.MODE_ECB)
        S = b''
        a_f = '<c4sB4sIBB'
        for i in range(1, k + 1):
            Ai = struct.pack(
                a_f,
                b'\x01',
                b'\x00'*4,
                direction,
                kwargs.get('devaddr'),
                kwargs.get('fcnt'),
                0,
                i
            )
            Si = cryptor.encrypt(Ai)
            S += Si
        return Mote.bytes_xor(S, payload)[:pldlen]

    def gen_keys(self, root, keymsgs: tuple, mode=AES.MODE_ECB):
        cryptor = AES.new(root, mode)
        return [cryptor.encrypt(msg) for msg in keymsgs]

    def gen_sess_keys(self):
        pad = b'\x00\x00\x00\x00\x00\x00\x00'
        nwkskeymsg = b'\01' + self.joinnonce + self.netid + self.devnonce + pad
        appskeymsg = b'\02' + self.joinnonce + self.netid + self.devnonce + pad
        return self.gen_keys(self.appkey, (nwkskeymsg, appskeymsg))

    def form_join(self):
        '''
        @ joinreqtyp: 
            0xFF: Join Request
            0x00: Rejoin type 0
            0x01: Rejoin type 1
            0x02: Rejoin type 2
        '''
        self.joinreqtyp = b'\xFF'
        self.devnonce = secrets.token_bytes(self.devnoncelen)[::-1]
        mhdr = b'\x00'
        mic = self.cal_mic(
            key=self.join_mic_key,
            typ='join',
            mhdr=mhdr
        )
        logger.info(
            ('Join Request - \n'
                'AppEUI: {}, '
                'DevEUI: {}, '
                'DevNonce: {}, '
                'MIC: {} --').format(
                    self.joineui.hex(),
                    self.deveui.hex(),
                    self.devnonce.hex(),
                    mic.hex(),
                ))

        return struct.pack(
            self.joinreq_f,
            mhdr,
            self.joineui,
            self.deveui,
            self.devnonce,
            mic
        )

    def parse_mhdr(self, mhdr):
        '''
        MHDR
        -----------------------
        | MType | RFU | Major |
        -----------------------
        |  000  | 000 |  00   |
        -----------------------
        '''

        msgtyp = (mhdr >> MTYPE_OFFSET)

    def parse_joinacpt(self, mhdr, joinacpt, mic):
        self.
        self.cflist = joinacpt[JOINACPT_CFLIST_OFFSET:] or b''
        self.joinnonce, self.netid, self.devaddr, self.dlsettings, self.rxdelay = struct.unpack(
            self.joinacpt_f,
            joinacpt[:JOINACPT_CFLIST_OFFSET]
        )
        # Check OptNeg flag in DLSettings
        optneg, _ = self.parse_dlsettings(self.dlsettings)
        if optneg:
            joinacpt_mic_key = self.jsintkey
        else:
            joinacpt_mic_key = self.nwkkey
        vmic = self.cal_mic(
            key=joinacpt_mic_key,
            typ='acpt',
            mhdr=mhdr,
        )
        if (vmic == mic):
            logger.info(
                ('Join Accept (MIC verified) -\n'
                    'DevAddr: {}, '
                    'DLSettings: {}, '
                    'RxDelay: {}').format(
                        self.devaddr.hex(),
                        self.dlsettings.hex(),
                        self.rxdelay.hex()
                    ))
            self._initialize(optneg)
        else:
            raise ValueError('MIC mismatch')

    def parse_dlsettings(self, dlsettings):
        '''
        DLSettings
        ----------------------------------------
        | OptNeg | RX1DRoffset | RX2 Data Rate |
        ----------------------------------------
        |   0    |    000      |     0000      |
        ----------------------------------------
        '''
        dlsettings = int.from_bytes(dlsettings)
        optnegoffset = 7
        rx1droffset = 4
        optneg = dlsettings >> optnegoffset
        rx1droffset = (dlsettings & 0x70) >> rx1droffset
        rx2datarate = dlsettings & 0x0F
        return optneg, rx1droffset, rx2datarate

    def parse_macpld(self, mhdr, macpldmv, mic):
        prefhdr = macpldmv[:7]
        beforefopts_f = '<4sBH'
        devaddr, fctrl, fcnt = struct.unpack(
            beforefopts_f,
            prefhdr
        )
        foptslen = fctrl & 0b1111
        fhdrlen = 7 + foptslen
        fhdr = macpldmv[:fhdrlen]
        fopts = fhdr[7:].tobytes()
        fport = macpldmv[fhdrlen]
        frmpld = macpldmv[fhdrlen + 1:].tobytes()
        if fport == 0:
            key = self.nwkskey
        else:
            key = self.appskey
        frmpld = self.encrypt(
            key,
            frmpld,
            direction=1,
            devaddr=devaddr,
            fcnt=fcnt
        )
        vmic = self.cal_mic(
            mhdr,
            self.nwkskey,
            direction=1,
            devaddr=self.devaddr,
            fcnt=fcnt,
            fhdr=fhdr,
            fport=fport,
            frmpld=frmpld,
        )
        if (vmic == mic):
            logger.info(
                ('Downlink data (MIC verified) - \n'
                    'DevAddr: {}, '
                    'FCnt: {}, '
                    'FOpts: {}, '
                    'FPort: {}, '
                    'Payload: {}').format(
                        devaddr.hex(),
                        fcnt,
                        fopts.hex(),
                        fport,
                        frmpld.hex(),
                    ))
        else:
            raise MICError()

    def app_preproc(self, frmpld):
        fport = random.randint(2, 255)
        frmpld = self.encrypt(
            self.appskey,
            frmpld,
            devaddr=self.devaddr,
            fcnt=self.fcnt,
        )
        return fport, frmpld

    def cmd_preproc(self, cmd):
        fport = 0
        frmpld = self.encrypt(
            self.nwkskey,
            cmd,
            devaddr=self.devaddr,
            fcnt=self.fcnt,
        )
        return fport, frmpld

    def form_app(self, frmpld, preproc, fopts=b''):
        '@preproc: different process for frmpld and fport'
        mhdr = b'\x80'
        fhdr = self.form_fhdr(fopts)
        fhdrlen = len(fhdr)
        frmpldlen = len(frmpld)
        app_f = '<s{fhdrlen}sB{frmpldlen}s4s'.format(
            fhdrlen=fhdrlen,
            frmpldlen=frmpldlen,
        )
        fport, frmpld = preproc(frmpld)
        mic = self.cal_mic(
            mhdr,
            self.nwkskey,
            direction=0,
            devaddr=self.devaddr,
            fcnt=self.fcnt,
            fhdr=fhdr,
            fport=fport,
            frmpld=frmpld,
        )
        self.fcnt += 1
        self.save()
        logger.info(
            ('Application Data -\n'
                'FHDR: {}, '
                'FPort: {}, '
                'FRMPayload (after encryption): {}, '
                'MIC: {} --').format(
                    fhdr.hex(),
                    fport,
                    frmpld,
                    mic.hex()
                ))

        return struct.pack(
            app_f,
            mhdr,
            fhdr,
            fport,
            frmpld,
            mic,
        )

    def form_rejoin(self, typ=0):
        '''
        rejoin request(typ 0 or 2):
        |1 byte      | 3 bytes | 8 bytes | 2 bytes |
        |rejoin type | NetID   |  DevEUI | RJcount0|
        rejoin request(typ 1):
        |1 byte      | 8 bytes | 8 bytes | 2 bytes |
        |rejoin type | JoinEUI |  DevEUI | RJcount1|
        @typ: type of rejoin request, 0, 1 or 2.
        '''
        rejoin_f = '<s{}s8sh'
        typ_field = {
            0: (self.netid, self.rjcount0),
            1: (self.joineui, self.rjcount1),
            2: (self.netid, self.rjcount0)
        }
        field, rjcount = typ_field[typ]
        return struct.pack(
            rejoin_f.format(len(field)),
            typ,
            field,
            self.deveui,
            rjcount,
        )

