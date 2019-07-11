"""
Main programs of this emulator.
Author: Houlu
Email: houlu8674@bupt.edu.cn

Class:
    Gateway: Emulation of LoRaWAN gateway behaviors.
        According to Gateway to Server Interface from Semtech. 
    Mote: Emulation of LoRaWAN end devices
"""

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
DEVNONCE_LEN = 2
DEVADDR_LEN = 4
FCTRL_LEN = 1
FCNT_LEN = 2
FPORT_LEN = 1


class MICError(ValueError):
    pass


class Gateway:
    """
    Gateway class

    Attributes:
        pullack_f: pull ACK struct format 
        pushack_f: push ACK struct format
        pullresp_f: pullresp struct format
        txdr2datr: TxDr in mote converts to datr in txpk
    """
    pullack_f = '<s2ss8s'
    pushack_f = '<s2ss'
    pullresp_f = '<s2ss'
    txdr2datr = {
        0: 'SF12BW125',
        1: 'SF11BW125',
        2: 'SF10BW125',
        3: 'SF9BW125',
        4: 'SF8BW125',
        5: 'SF7BW125',
        6: 'SF7BW250',
        7: 50000, # FSK modulation
    }

    def __init__(self, gweui):
        self.gweui = bytes.fromhex(gweui)
        self.version = b'\x02'
        self.token_length = 2

    def add_data(self, rxpk, data):
        """
        Add data and data size to rxpk
        Args:
            rxpk: Dict of rxpk lists
            data: Target data
        Returns:
            A dict of complete rxpk data
        """
        rxpk['rxpk'][0].update({
            'size': len(data),
            'data': data,
        })
        return rxpk

    @property
    def stat(self):
        """
        property of stat field in PUSH_DATA payload
        Returns:
            A dict contains stat key-value
        """
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

    def form_rxpk(self, mote):
        """
        Form rxpk field
        Args:
            mote: Object of Mote class to get "chan" and "datr" field
        Returns:
            A dict contains rxpk key-value
        """
        return {
            'rxpk': [{
                "tmst": int(time.time()),
                "chan": mote.txch,
                "rfch": 0,
                "freq": 435.9,
                "stat": 1,
                "modu": 'LORA',
                "datr": self.txdr2datr[mote.txdr],
                "codr": '4/5',
                "lsnr": 2,
                "rssi": -119,
                "size": 17,
                "data": '',
            }]
        }

    def form_push_pld(self, data, mote):
        """
        Form payload field of PUSH_DATA
        Args:
            data: data field in rxpk
            mote: Object of Mote class
        Returns:
            Payload of the PUSH_DATA after ASCII encoding
        """
        data = self.b64data(data)
        payload = self.add_data(self.form_rxpk(mote), data)
        stat = self.stat
        payload.update(stat)
        return json.dumps(
            payload
        ).encode('ascii')

    def b64data(self, data):
        """
        base64 encode data, then decode to string by UTF-8
        Args:
            data: bytes data
        Returns:
            A string of base64 encoded data
        """
        return base64.b64encode(data).decode()

    @property
    def pull_data(self):
        """
        Property of PULL_DATA
        """
        plldat_f = 's2ss8s'
        token = secrets.token_bytes(self.token_length)
        pull_id = b'\x02'
        logger.info(
            ('PULL DATA -\nVersion: {}, '
                'Token: {}, '
                'Identifier: {}, '
                'GatewayEUI: {}').format(
                    self.version.hex(),
                    token.hex(),
                    pull_id.hex(),
                    self.gweui.hex()
                ))

        return struct.pack(
            plldat_f,
            self.version,
            token,
            pull_id,
            self.gweui,
        )

    def pull(self, transmitter):
        """
        Sending PULL_DATA from gateway
        Args:
            transmitter: Transmitter between gateway to server, MUST have send() and recv() method.
        Returns:
            None

        PULL_DATA:
        --------------------------------------------------
        |   Version    | Token | Identifier | GatewayEUI |
        --------------------------------------------------
        | 0x00 or 0x01 |2 bytes|    0x02    |   8 bytes  |
        --------------------------------------------------
        """
        transmitter.send(self.pull_data)
        res = transmitter.recv()
        self.parse_pullack(res[0])

    def parse_pullack(self, pullack):
        """
        Parse PULL_ACK message
        Args:
            pullack: bytes of PULL_ACK message
        returns:
            None

        PULL_ACK:
        --------------------------------------------------
        |   Version    | Token | Identifier | GatewayEUI |
        --------------------------------------------------
        | 0x00 or 0x01 |2 bytes|    0x04    |   8 bytes  |
        --------------------------------------------------
        """
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

    def form_pshdat(self, data, mote):
        """
        Form the complete PUSH_DATA
        Args:
            data: PHYPayload from mote
            mote: Object of Mote class
        Returns:
            A bytes of complete PUSH_DATA, ready to be sent

        PUSH_DATA
        ------------------------------------------------------------
        |   Version    | Token | Identifier | GatewayEUI | Payload |
        ------------------------------------------------------------
        | 0x00 or 0x01 |2 bytes|    0x00    |   8 bytes  |    -    |
        ------------------------------------------------------------
        """
        payload = self.form_push_pld(data=data, mote=mote)
        token = secrets.token_bytes(self.token_length)
        push_id = b'\x00'
        logger.info(
            ('PUSH DATA -\nVerson: {}, '
                'Token: {}, '
                'Identifier: {}, '
                'GatewayEUI: {}').format(
                    self.version.hex(),
                    token.hex(),
                    push_id.hex(),
                    self.gweui.hex(),
                ))

        return b''.join([
            self.version,
            token,
            push_id,
            self.gweui,
            payload,
        ])

    def push(self, transmitter, data, mote):
        """
        Sending PUSH_DATA from gateway to server.
        Args:
            transmitter: Transmitter between gateway to server, MUST have send() and recv() method.
            data: PHYPayload from mote
            mote: Object of Mote class, for extra usage
        Returns:
            A bytes of the data field in PULL_RESP txpk field, or an empty bytes if unconfirmed
        """
        transmitter.send(self.form_pshdat(data, mote))
        pushack = transmitter.recv()
        self.parse_pushack(pushack[0])
        pullresp = transmitter.recv()
        self.parse_pullresp(pullresp[0], mote)

    def parse_pushack(self, pushack):
        """
        Parse PUSH_ACK message
        Args:
            pushack: bytes of PUSH_ACK message
        Returns:
            None
        
        PUSH_ACK:
        -----------------------------------
        |  Version   | Token | Identifier |
        -----------------------------------
        |0x00 or 0x01|2 bytes|    0x01    |
        -----------------------------------
        """
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
        """
        Parse the PULL RESP from LoRa Server
        Args:
            pullresp: PULL RESP bytes
            mote: Object of Mote
        Returns:
            None

        ---------------------------------------------------------------
        | Protocol Version | PULL RESP Token | Identifier |  Payload  |
        ---------------------------------------------------------------
        |   0x01 or 0x02   |     2 bytes     |    0x03    |< 996 bytes|
        ---------------------------------------------------------------
        """
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

    def parse_txpk(self, txpk, mote):
        """
        Parse the txpk (downlink) data
        Args:
            txpk: a dict of txpk data (converted from JSON)
            mote: Object of Mote
        Returns:
            None

        ------------------------------
        |       Required Fields      |
        ------------------------------
        | time |       UTC time      |
        ------------------------------
        | rfch |    Antenna index    |
        ------------------------------
        | codr |    ECC code rate    |
        ------------------------------
        | ipol |         True        |
        ------------------------------
        |       Optional Fields      |
        ------------------------------
        | imme |      Immediately    |
        ------------------------------
        | tmst |     When to send    |
        ------------------------------
        | freq |         MHz         |
        ------------------------------
        | powe |     Output power    |
        ------------------------------
        | modu |    "FSK" or "LORA"  |
        ------------------------------
        | datr |    SFnBWm or k Hz   |
        ------------------------------
        | size |     Size of data    |
        ------------------------------
        | data |  base64 phypayload  |
        ------------------------------
        | ncrc |  Physical layer CRC |
        ------------------------------
        """
        phypld = memoryview(base64.b64decode(txpk.get('data')))
        mote.parse_phypld(phypld)
        

class Mote:
    """
    This is the main class of LoRa end device
    Attributes:
        joinreq_f: Join request struct format
        fhdr_f: FHDR field struct format
        mic_msg_tpl: Required fields to calculate MIC of join message
    """

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
        self.txdr = 5 # Uplink data rate index
        self.txch = 7 # Channel index

        self.gen_jskeys()

    def _initialize_session(self, optneg):
        """
        Initialize session context according to optneg flag
        Args:
            optneg: 0 or 1
        Returns:
            None
        """
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
        self.save()

    def gen_jskeys(self):
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
        """
        Calculate the XOR of two multiple bytes
        Args:
            b1: bytes
            b2: bytes
        Returns:
            bytes of XOR results 
        """
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

    def form_fctrl(self, foptslen: int, unconfirmed: bool) -> bytes:
        """
        Form FCtrl byte in FHDR
        Args:
            foptslen: Indicate the real length of FOpts field
            unconfirmed: Whether this is an UNconfirmed data up
        Returns:
            A bytes of FCtrl field

        Uplink FCtrl:
        ---------------------------------------
        | ADR | RFU | ACK | ClassB | FOptsLen |
        ---------------------------------------
        |  0  |  0  |  0  |    0   |   0000   |
        ---------------------------------------
        """
        mask = 0x0F if unconfirmed else 0x2F
        return (mask & (foptslen | 0xF0)).to_bytes(1, 'big')

    def parse_fctrl(self, fctrl):
        """
        Parse the FCtrl byte
        Args:
            fctrl: FCtrl byte
        Returns:
            A proxy of FCtrl values

        Downlink FCtrl:
        ---------------------------------------
        | ADR | RFU | ACK |FPending| FOptsLen |
        ---------------------------------------
        |  0  |  0  |  0  |    0   |   0000   |
        ---------------------------------------
        """
        name = ('adr', 'rfu', 'ack', 'fpending', 'foptslen')
        bitlength = (1, 1, 1, 1, 4)
        offset = (7, 6, 5, 4, 0)
        return self.parse_byte(name=name, bitlength=bitlength, offset=offset)

    def form_fhdr(self, fopts, unconfirmed=False, version='1.1'):
        """
        Form FHDR field
        Args:
            fopts: FOpts values, could be empty bytes
            unconfirmed: Whether this is an UNconfirmed data up
            version: LoRaWAN version, if 1.1, then FOpts MUST be encrypted
        Returns:
            Length and bytes of FHDR field

        ----------------------------------
        | DevAddr | FCtrl | FCnt | FOpts |
        ----------------------------------
        |  0000   |   0   |  00  | 0 ~ 15|
        ----------------------------------
        """
        foptslen = len(fopts)
        if foptslen:
            if version == '1.1':
            # fOpts encryption is only required in LoRaWAN 1.1.
                fopts = self.encrypt(
                    self.nwksenckey,
                    fopts,
                    direction=0,
                    start=0,
                )
        fhdr_f = self.fhdr_f + '{}s'.format(foptslen)
        fctrl = self.form_fctrl(foptslen, unconfirmed)
        return struct.calcsize(fhdr_f), struct.pack(fhdr_f, self.devaddr, fctrl, self.fcnt, fopts)

    def parse_fhdr(self, macpld):
        """
        Parse variable-length FHDR from MACPayload
        Args:
            macpld: memoryview of MACPayload bytes
        Returns:
            Length of FHDR bytes and dict of the FHDR data

        The structure of FHDR field can be referred above
        """
        const_len = DEVADDR_LEN + FCTRL_LEN + FCNT_LEN
        beforefopts_f = '<4sBH'
        devaddr, fctrl, fcnt = struct.unpack(
            beforefopts_f,
            macpld[:const_len]
        )
        adr, _, ack, fpending, foptslen = self.parse_fctrl(fctrl)
        fhdrlen = const_len + foptslen
        fopts = self.encrypt(
            self.nwksenckey,
            macpld[const_len:fhdrlen],
            direction=1,
            fcnt=fcnt,
            start=0
        )
        fhdr = dict(
            devaddr=devaddr,
            adr=adr,
            ack=ack,
            fpending=fpending,
            foptslen=foptslen,
            fcnt=fcnt,
            fopts=fopts
        )
        return fhdrlen, fhdr

    def calcmic_app(self, key, mhdr, fhdr, fport, frmpld, direction, version='1.1'):
        """
        Calculate the MIC field for uplink and downlink application data
        Args:
            key: Key used to CMAC
            mhdr, fhdr, fport, frmpld: Necessary fields to compute
            direction: int object, 0 for uplink and 1 for downlink
            typ: Type of data
        Returns:
            A 4-byte length bytes object of MIC field
        """
        msg = b''.join([
            mhdr,
            fhdr,
            fport.to_bytes(1, 'big'),
            frmpld,
        ])
        msglen = len(msg)
        B0_varfield = self.fcntup if direction == 0 else 0
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
        """
        Calculate the MIC field for join-related data (join request, accept and rejoin)
        Args:
            key: Key used to CMAC
            typ: The type of message (join, acpt, rejn)
            kwargs: Extra parameters
        Returns:
            A 4-byte length bytes object of MIC field
        """
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
        """
        Decrypt join accept message
        Args:
            macpld: Encrypted macpayload
        Returns:
            bytes of decrypted join accept message

        Decryption keys:
        ----------------------
        | ReqType |   Key    |
        ----------------------
        |  Join   |  NwkKey  |
        ----------------------
        | Rejoin  | JSEncKey |
        ----------------------
        """
        macpldlen = len(macpld)
        macpld = macpld.ljust(AES_BLOCK, b'\x00')
        cryptor = AES.new(self.joinenckey, AES.MODE_ECB)
        return cryptor.encrypt(macpld)

    def encrypt(self, key, payload, direction=0, fcnt=0, start=1):
        """
        Encrypt and decrypt FRMPayload or FOpts
        Args:
            key: Corresponding key
            payload: Object payload
            direction: 0 for uplink and 1 for downlink
            fcnt: If direction is 1, this value MUST be provided
            start: This arg differentiates the payload type (FRMPayload or FOpts)
                by indicating the start value of block A. Default is 1 (FRMPayload).
        Returns:
            bytes that stands for the encrypted or decrypted FRMPayload

        Ai:
        -----------------------------------------------------------
        | 0x01 | 4 X 0x00 | Direction | DevAddr | FCnt | 0x00 | i |
        -----------------------------------------------------------
        """
        pldlen = len(payload)
        k = math.ceil(pldlen / AES_BLOCK)
        payload = payload.ljust(AES_BLOCK * k, b'\x00')
        cryptor = AES.new(key, AES.MODE_ECB)
        S = b''
        ai_f = '<cIB4sIBB'
        fcnt = self.fcntup if direction == 0 else fcnt
        for i in range(start, k + start):
            Ai = struct.pack(
                ai_f,
                b'\x01',
                0,
                direction,
                self.devaddr,
                fcnt,
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
    def joinenckey(self):
        return self.nwkkey if self.joinreqtyp == b'\xFF' else self.jsenckey

    def form_join(self):
        """
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
        """
        self.joinreqtyp = b'\xFF'
        self.devnonce = secrets.token_bytes(DEVNONCE_LEN)[::-1]
        mhdr = b'\x00'
        mic = self.calcmic_join(
            key=self.nwkkey,
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
        """
        Parse MHDR byte
        Args:
            mhdr: MHDR field
        Returns:
            A proxy of dict values, the field order sticks to the protocol

        MHDR:
        -----------------------
        | MType | RFU | Major |
        -----------------------
        |  000  | 000 |  00   |
        -----------------------
        """
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

        Join Accept:
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
        """
        Parse DLSettings field

        ----------------------------------------
        | OptNeg | RX1DRoffset | RX2 Data Rate |
        ----------------------------------------
        |   0    |    000      |     0000      |
        ----------------------------------------
        """
        name = ('optneg', 'rx1droffset', 'rx2dr')
        bitlength = (1, 3, 4)
        offset = (7, 4, 0)
        return self.parse_byte(dlsettings, name=name, bitlength=bitlength, offset=offset)

    def parse_phypld(self, phypld):
        """
        Parse phypayload inside txpk data
        Args:
            phypld: phypaylod in txpk
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
        """
        phypld = memoryview(phypld)
        mhdr = phypld[:MHDR_LEN]
        mtype, _, major = self.parse_mhdr(mhdr).values()
        if mtype == 1:
            encrypted_phypld = phypld[MHDR_LEN:]
            macpldmic = self.joinacpt_decrypt(encrypted_phypld)
            msglen = len(phypld)
            pldlen = msglen - MHDR_LEN - MIC_LEN  # MHDR 1 byte, MIC 4 bytes
            pullresp_f = '<{}s{}s'.format(pldlen, MIC_LEN)
            macpld, mic = struct.unpack(pullresp_f, macpldmic)
            self.parse_joinacpt(mhdr, macpld, mic)
        else:  # PULL RESP for app phypayload
            macpld = phypld[MHDR_LEN:-MIC_LEN]
            mic = phypld[-MIC_LEN:]
            self.parse_macpld(mhdr, macpld, mic)

    def parse_macpld(self, mhdr, macpld, mic):
        """
        Parse macpayload data (not join data)
        Args:
            mhdr: MHDR field
            macpld: MACPayload field
            mic: MIC
        Returns:
            None
        Exceptions:
            MICError: MIC mismatches

        ------------------------------------
        | MHDR | FHDR | FPort | FRMPayload |
        ------------------------------------
        |1 byte|  -   |1 byte |     -      |
        ------------------------------------
        """
        macpld = memoryview(macpld)
        fhdrlen, fhdr = self.parse_fhdr(macpld)
        fport = macpld[fhdrlen:fhdrlen + FPORT_LEN]
        frmpld = macpld[fhdrlen + FPORT_LEN:]
        if fport == 0:
            key = self.nwksenckey
        else:
            key = self.appskey
        #TODO: The LoRaWAN version
        vmic = self.calcmic_app(
            self.snwksintkey,
            mhdr,
            direction=1,
            fcnt=fcnt,
            fhdr=fhdr,
            fport=fport,
            frmpld=frmpld,
        )
        if (vmic == mic):
            frmpld = self.encrypt(
                key,
                frmpld,
                direction=1,
                devaddr=fhdr.get('devaddr'),
                fcnt=fhdr.get('fcnt') # This arg must be provided
            )
            logger.info(
                ('Downlink MACPayload, Important Info:\n'
                    '\tFHDR: {}, '
                    '\tFPort: {}, '
                    '\tPayload: {}').format(
                        fhdr,
                        fport,
                        frmpld.hex(),
                    ))
        else:
            raise MICError('MIC of MACPayload mismatches')
        
    def form_phypld(self, fport, frmpld, fopts=b'', unconfirmed=False, version='1.1'):
        """
        Form the MACPayload of normal application data
        Args:
            fport: int value of FPort field
            frmpld: Application message
            encrypt: Encryption of MACPayload (APP or CMD)
            fopts: MAC Command in FOpts field, < 15 bytes
            unconfirmed: Unconfirmed data up or confirmed data up
        Returns:
            bytes of final application data
        Exceptions:
            ValueError: FOpts MUST be empty if FPort is zero
        """
        if unconfirmed:
            mhdr = b'\x40'
        else:
            mhdr = b'\x80'
        if fport == 0 and fopts:
            raise ValueError('Cannot set FPort and FOpts in one same frame')
        fhdrlen, fhdr = self.form_fhdr(fopts, unconfirmed, version)
        frmpldlen = len(frmpld)
        phypld_f = '<s{fhdrlen}sB{frmpldlen}s4s'.format(
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
            ('Unlink application data -\n'
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
            phypld_f,
            mhdr,
            fhdr,
            fport,
            frmpld,
            mic,
        )

    def form_rejoin(self, typ=0):
        """
        rejoin request(typ 0 or 2):
        ---------------------------------------------
        |   1 byte    | 3 bytes | 8 bytes | 2 bytes  |
        ---------------------------------------------
        | rejoin type |  NetID  | DevEUI | RJcount0 |
        ---------------------------------------------
        rejoin request(typ 1):
        ---------------------------------------------
        |   1 byte    | 8 bytes | 8 bytes | 2 bytes  |
        ---------------------------------------------
        | rejoin type | JoinEUI | DevEUI  | RJcount1 |
        ---------------------------------------------
        @typ: type of rejoin request, 0, 1 or 2.
        """
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


