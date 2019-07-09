import base64
import json
import logging
import math
import pickle
import random
import secrets
import struct
import time

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

GMTformat = "%Y-%m-%d %H:%M:%S GMT"

logger = logging.getLogger('main')

MHDR_LEN = 1
MTYPE_OFFSET = 5
JOINACPT_CFLIST_OFFSET = 12
AES_BLOCK = 16
MIC_LEN = 4


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
        mote.parse_data(data)
        

class Mote:
    devnoncelen = 2
    joinreq_f = '<s8s8s2s4s'
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
            'homenetid',
            'devaddr',
            'dlsettings',
            'rxdelay',
            'cflist'
        ],
    }

    def __init__(self, joineui, deveui, appkey, nwkkey, conffile):
        self.joineui = joineui[::-1]
        self.deveui = deveui[::-1]
        self.appkey, self.nwkkey = appkey, nwkkey
        self.conffile = conffile

        self._initialization()

    def _initialize_session(self, optneg):
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
                self.homenetid,
                self.devnonce,
            ])
            apps_msg, fnwksint_msg = [
                (prefix + sesskey_prefix).ljust(AES_BLOCK, b'\x00')
                for prefix in (b'\x02', b'\x01')
            ]
            self.appskey, self.fnwksintkey = self.gen_keys(self.nwkkey, (apps_msg, fnwksint_msg))
            self.snwksintkey = self.nwksenckey = self.fnwksintkey
        self.fcntup = 0
        self.txdr = 5 # Uplink data rate index
        self.txch = 7 # Channel index
        self.save()

    def _initialization(self):
        """
        Generate JS Int & Enc keys
        ------------------------------
        | 0x06 \ 0x05 | DevEUI | pad |
        ------------------------------
        |    1 byte   | 8 bytes|  -  |
        ------------------------------
        """
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
        """
        Parse one-byte data into several fields by bits
        Args:
            data: Original byte data
            name: List of names for each field
            offset: Offset number of each field
            bitlength: Bit length of each field

        Returns:
            A list of field values in integer
        """
        assert len(name) == len(offset) == len(bitlength)
        data = int.from_bytes(data, byteorder='little')
        res = [0 for _ in range(len(name))]
        for ind, value in enumerate(name):
            off, leng = offset[ind], bitlength[ind]
            binmask = '1'*leng + '0'*off
            mask = int(binmask, base=2)
            res[ind] = (data & mask) >> off
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

    def app(self, gateway, transmitter, msg, fopts, unconfirmed=False):
        app_data = self.form_app(msg, self.app_preproc, fopts, unconfirmed)
        gateway.push(app_data, transmitter, self)

    def cmd(self, gateway, transmitter, cmd):
        cmd_data = self.form_app(cmd, self.cmd_preproc, b'')
        gateway.push(cmd_data, transmitter, self)

    def form_fctrl(self, foptslen: int, unconfirmed: bool) -> bytes:
        '''
        Form FCtrl byte in FHDR
        Args:
            foptslen: Indicate the real length of FOpts field
            unconfirmed: Whether this is an UNconfirmed data up
        Returns:
            A bytes of FCtrl field

        ---------------------------------------
        | ADR | RFU | ACK | ClassB | FOptsLen |
        ---------------------------------------
        |  0  |  0  |  0  |    0   |   0000   |
        ---------------------------------------
        '''
        mask = 0x0F if unconfirmed else 0x2F
        return (mask & (foptslen | 0xF0)).to_bytes(1, 'big')

    def form_fhdr(self, fopts, unconfirmed=False, version='1.1'):
        '''
        Form FHDR field
        Args:
            fopts: FOpts values, could be empty bytes
            unconfirmed: Whether this is an UNconfirmed data up
            version: LoRaWAN version, if 1.1, then FOpts MUST be encrypted
        Returns:
            bytes of FHDR field

        ----------------------------------
        | DevAddr | FCtrl | FCnt | FOpts |
        ----------------------------------
        |  0000   |   0   |  00  | 0 ~ 15|
        ----------------------------------
        '''
        foptslen = len(fopts)
        if foptslen:
            if version == '1.1':
            # fOpts encryption is only required in LoRaWAN 1.1.
                fopts = self.encrypt(
                    self.nwksenckey,
                    fopts,
                    direction=0,
                )
        fhdr_f = self.fhdr_f + '{}s'.format(foptslen)
        fctrl = self.form_fctrl(foptslen, unconfirmed)
        return struct.calcsize(fhdr_f), struct.pack(fhdr_f, self.devaddr, fctrl, self.fcnt, fopts)

    def calcmic_app(self, key, mhdr, fhdr, fport, frmpld, direction, version='1.1'):
        '''
        Calculate the MIC field for uplink and downlink application data
        Args:
            key: Key used to CMAC
            mhdr, fhdr, fport, frmpld: Necessary fields to compute
            direction: int object, 0 for uplink and 1 for downlink
            typ: Type of data
        Returns:
            A 4-byte length bytes object of MIC field
        '''
        msg = b''.join([
            mhdr,
            fhdr,
            fport.to_bytes(1, 'big'),
            frmpld,
        ])
        msglen = len(msg)
        if direction == 0: # Uplink
            B0_varfield = self.conffcnt
        elif direction == 1: # Downlink
            B0_varfield = 0
        B_f = '<cH{}B4sIBB'
        B0_elements = [
            b'\x49',
            B0_varfield,
            0,
            0,
            direction,
            self.devaddr,
            self.fcntup,
            0,
            msglen
        ]
        B0 = struct.pack(
            B_f.format('H'),
            *B0_elements,
        )
        
        fmsg = B0 + msg
        fcmacobj = CMAC.new(self.fnwksintkey, ciphermod=AES)
        fcmac = fcmacobj.update(fmsg)
        if version == '1.1':
            B1_elements = B0_elements[:]
            B1_elements[1] = self.txdr
            B1_elements.insert(2, self.txch)
            B1 = struct.pack(
                B_f.format('BB'),
                *B1_elements,
            )
            smsg = B1 + msg
            scmacobj = CMAC.new(self.snwksintkey, ciphermod=AES)
            scmac = scmacobj.update(smsg)
            return fcmac.digest()[:MIC_LEN//2] + scmac.digest()[:MIC_LEN//2]
        else:
            return fcmac.digest()[:MIC_LEN]

    def calcmic_join(self, key, typ='join', **kwargs):
        '''
        Calculate the MIC field for join-related data (join request, accept and rejoin)
        Args:
            key: Key used to CMAC
            typ: The type of message (join, acpt, rejn)
            kwargs: Extra parameters
        Returns:
            A 4-byte length bytes object of MIC field
        '''
        msgname = self.mic_msg_tpl[typ]
        def attr_by_name(attr):
            try:
                return getattr(self, attr)
            except AttributeError:
                return kwargs.get(attr)
        msg = b''.join(map(attr_by_name, msgname))
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(msg)
        return cobj.digest()[:MIC_LEN]

    def joinacpt_decrypt(self, macpld):
        '''
        Decrypt join accept message
        Args:
            macpld: Encrypted macpayload
        Returns:
            bytes of decrypted join accept message

        ----------------------
        | ReqType |   Key    |
        ----------------------
        |  Join   |  NwkKey  |
        ----------------------
        | Rejoin  | JSEncKey |
        ----------------------
        '''
        macpldlen = len(macpld)
        macpld = macpld.ljust(AES_BLOCK, b'\x00')
        cryptor = AES.new(self.joinenckey, AES.MODE_ECB)
        return cryptor.encrypt(macpld)

    def encrypt(self, key, payload, direction=0):
        pldlen = len(payload)
        k = math.ceil(pldlen / 16)
        payload = payload.ljust(16*k, b'\x00')
        cryptor = AES.new(key, AES.MODE_ECB)
        S = b''
        a_f = '<c4sB4sIBB'
        for i in range(1, k + 1):
            Ai = struct.pack(
                a_f,
                b'\x01',
                b'\x00'*4,
                direction,
                self.devaddr,
                self.fnctup,
                0,
                i
            )
            Si = cryptor.encrypt(Ai)
            S += Si
        return Mote.bytes_xor(S, payload)[:pldlen]

    def gen_keys(self, root, keymsgs: tuple, mode=AES.MODE_ECB):
        """
        Generate necessary keys
        Args:
            root: Root key, could be appkey or nwkkey
            keymsgs: Messages used to generate keys
            mode: AES mode, no need to change
        Returns:
            A list(even one key) of keys
        """
        cryptor = AES.new(root, mode)
        return [cryptor.encrypt(msg) for msg in keymsgs]

    @property
    def joinmickey(self):
        return self.jsintkey if self.optneg else self.nwkkey

    @property
    def joinenckey(self):
        return self.nwkkey if self.joinreqtyp == b'\xFF' else self.jsenckey

    def form_join(self):
        '''
        Form join request

        ---------------------
        |0xFF| Join Request |
        ---------------------
        |0x00| Rejoin type 0|
        ---------------------
        |0x01| Rejoin type 1|
        ---------------------
        |0x02| Rejoin type 2|
        ---------------------
        '''
        self.joinreqtyp = b'\xFF'
        self.devnonce = secrets.token_bytes(self.devnoncelen)[::-1]
        mhdr = b'\x00'
        mic = self.calcmic(
            key=self.joinmickey,
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
        Parse MHDR byte
        Args:
            mhdr: MHDR field
        Returns:
            A proxy of dict values, the field order sticks to the protocol

        -----------------------
        | MType | RFU | Major |
        -----------------------
        |  000  | 000 |  00   |
        -----------------------
        '''
        name = ('mtype', 'rfu', 'major')
        bitlength = (3, 3, 2)
        offset = (5, 2, 0)
        return self.parse_byte(mhdr, name=name, bitlength=bitlength, offset=offset)

    def parse_joinacpt(self, mhdr, joinacpt, mic):
        """
        Parse the join accept message
        Args:
            mhdr: MHDR field
            joinacpt: Decrypted join accept message
            mic: MIC field
        Returns:
            None

        Exceptions:
            MICError: MIC mismatches

        --------------------------------------------------------------------
        | JoinNonce | Home_NetID | DevAddr | DLSettings | RxDelay | CFList |
        --------------------------------------------------------------------
        |  3 bytes  |   3 bytes  | 4 bytes |   1 byte   | 1 byte  |  (16)  |
        --------------------------------------------------------------------
        """
        joinacpt_f = '<3s3s4sss'
        joinacpt = memoryview(joinacpt)
        self.cflist = joinacpt[JOINACPT_CFLIST_OFFSET:] or b''
        self.joinnonce, self.homenetid, self.devaddr, self.dlsettings, self.rxdelay = struct.unpack(
            self.joinacpt_f,
            joinacpt[:JOINACPT_CFLIST_OFFSET]
        )
        # Check OptNeg flag in DLSettings
        optneg, _ = self.parse_dlsettings(self.dlsettings)
        if optneg:
            joinacpt_mic_key = self.jsintkey
        else:
            joinacpt_mic_key = self.nwkkey
        vmic = self.calcmic(
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
            self._initialize_session(optneg)
        else:
            raise MICError('MIC mismatches')

    def parse_dlsettings(self, dlsettings):
        '''
        DLSettings
        ----------------------------------------
        | OptNeg | RX1DRoffset | RX2 Data Rate |
        ----------------------------------------
        |   0    |    000      |     0000      |
        ----------------------------------------
        '''
        name = ('optneg', 'rx1droffset', 'rx2dr')
        bitlength = (1, 3, 4)
        offset = (7, 4, 0)
        return self.parse_byte(dlsettings, name=name, bitlength=bitlength, offset=offset)

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
        vmic = self.calcmic(
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
            raise MICError('MIC mismatches')

    def app_preproc(self, frmpld):
        fport = random.randint(2, 255)
        frmpld = self.encrypt(
            self.appskey,
            frmpld,
            devaddr=self.devaddr,
            fcntup=self.fcntup,
        )
        return fport, frmpld

    def cmd_preproc(self, cmd):
        fport = 0
        frmpld = self.encrypt(
            self.nwkencskey,
            cmd,
            devaddr=self.devaddr,
            fcntup=self.fcntup,
        )
        return fport, frmpld

    def form_app(self, fport, frmpld, fopts=b'', unconfirmed=True, version='1.1'):
        '''
        Form the application data
        Args:
            frmpld: Application message
            encrypt: Encryption of MACPayload (APP or CMD)
            fopts: MAC Command in FOpts field, < 15 bytes
            confirmed: Confirmed data up or unconfirmed data up
        Returns:
            bytes of final application data
        '''
        if confirmed:
            mhdr = b'\x80'
        else:
            mhdr = b'\x40'
        fhdrlen, fhdr = self.form_fhdr(fopts, unconfirmed, version)
        frmpldlen = len(frmpld)
        app_f = '<s{fhdrlen}sB{frmpldlen}s4s'.format(
            fhdrlen=fhdrlen,
            frmpldlen=frmpldlen,
        )
        if fport == 0:
            enckey = self.nwksenckey
        else:
            enckey = self.appskey
        frmpld = self.encrypt(
            enckey,
            frmpld,
            direction=0
        )
        mic = self.calcmic(
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
        |  1 byte    | 3 bytes | 8 bytes | 2 bytes  |
        |rejoin type |  NetID  |  DevEUI | RJcount0 |
        rejoin request(typ 1):
        |  1 byte    | 8 bytes | 8 bytes | 2 bytes  |
        |rejoin type | JoinEUI |  DevEUI | RJcount1 |
        @typ: type of rejoin request, 0, 1 or 2.
        '''
        self.joinreqtyp = typ.to_bytes(1, 'big')
        rejoin_f = '<s{}s8sh'
        typ_field = {
            0: (self.homenetid, self.rjcount0),
            1: (self.joineui, self.rjcount1),
            2: (self.homenetid, self.rjcount0)
        }
        field, rjcount = typ_field[typ]
        return struct.pack(
            rejoin_f.format(len(field)),
            typ,
            field,
            self.deveui,
            rjcount,
        )

    def parse_data(self, data: bytes):
        '''
        Parse the data inside txpk field
        Args:
            data: data in txpk
        Returns:
            None

        Message Type:
        -------------------------------
        | 000 |      Join request     |
        -------------------------------
        | 001 |      Join accept      |
        -------------------------------
        | 010 |  Unconfirmed data up  |
        -------------------------------
        | 011 | Unconfirmed data down |
        -------------------------------
        | 100 |   Confirmed data up   |
        -------------------------------
        | 101 |  Confirmed data down  |
        -------------------------------
        | 110 |     Rejoin request    |
        -------------------------------
        | 111 |       Proprietary     |
        -------------------------------
        '''
        data = memoryview(data)
        mhdr = data[:MHDR_LEN]
        mtype, _, major = self.parse_mhdr(mhdr).values()
        if mtype == 1:
            encrypted_data = data[MHDR_LEN:]
            macpldmic = self.joinacpt_decrypt(encrypted_data)
            msglen = len(data)
            pldlen = msglen - MHDR_LEN - MIC_LEN  # MHDR 1 byte, MIC 4 bytes
            pullresp_f = '<{}s{}s'.format(pldlen, MIC_LEN)
            macpld, mic = struct.unpack(pullresp_f, macpldmic)
            self.parse_joinacpt(mhdr, macpld, mic)
        else:  # PULL RESP for app data
            macpld = data[MHDR_LEN:-MIC_LEN]
            mic = data[-MIC_LEN:]
            self.parse_macpld(mhdr, macpld, mic)

