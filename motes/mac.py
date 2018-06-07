import math
import time
import base64
import json
from pprint import pprint
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util import Padding

from motes import db_connector as db

# import pdb
GMTformat = "%Y-%m-%d %H:%M:%S GMT"


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
        self.gateway_id = gateway_id
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

    def pull_data(self, version='02', token='83ec', identifier='02'):
        self.data_dict = {
            'version': version,
            'token': token,
            'identifier': identifier,
            'gateway_id': self.gateway_id,
        }
        self.bytes_str = (
            '{version}'
            '{token}'
            '{identifier}'
            '{gateway_id}'.format(**self.data_dict)
        )
        return bytearray.fromhex(self.bytes_str)

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

    def get_txpk_data(self, key, txpk):
        macpayload = base64.b64decode(txpk.get('data'))
        print('macpayload: {}'.format(macpayload.hex()))
        MHDR = macpayload[0:1]
        macpayload = macpayload[1:]
        if (int.from_bytes(MHDR, 'big') >> 5) == 1:
            macpayload = DeviceOp.join_acpt_decrypt(key, macpayload)
            AppNonce = macpayload[0:3]
            NetID = macpayload[3:6]
            DevAddr = macpayload[6:10]
            DLSettings = macpayload[10:11]
            RxDelay = macpayload[11:12]
            CFList = macpayload[12:]
            log_json = {
                'MHDR': GatewayOp.str_rev(MHDR.hex()),
                'AppNonce': GatewayOp.str_rev(AppNonce.hex()),
                'NetID': GatewayOp.str_rev(NetID.hex()),
                'DevAddr': GatewayOp.str_rev(DevAddr.hex()),
                'DLSettings': GatewayOp.str_rev(DLSettings.hex()),
                'RxDelay': GatewayOp.str_rev(RxDelay.hex()),
                'CFList': GatewayOp.str_rev(CFList.hex()),
            }
        else:
            DevAddr = macpayload[1:5]
            FCtrl = macpayload[5:6]
            FOptsLen = (ord(FCtrl) & 0b1111)
            FCnt = macpayload[6:8]
            FOpts = macpayload[8:8+FOptsLen]
            log_json = {
                'MHDR': MHDR.hex(),
                'DevAddr': DevAddr.hex(),
                'FCtrl': FCtrl.hex(),
                'FOptsLen': FOptsLen,
                'FCnt': FCnt.hex(),
                'FOpts': FOpts.hex(),
            }
        pprint(log_json)

    def parse_dlk(self, downlink):
        if downlink[3] in (1, 4):
            return None
        else:
            txpk = downlink[4:]
            txpk_json = json.loads(txpk.decode('ascii'))
            return txpk_json.get('txpk')


class DeviceOp(BytesOperation):
    def __init__(self, database_conf):
        self.database_conf = database_conf
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
            FCnt = FCnt[4:]
        FCnt = DeviceOp.str_rev(FCnt)
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
            msg_length = '{:0>2x}'.format(len(msg_bytes))
            B0 = DeviceOp._B0(msg_length=msg_length, **kwargs)
            obj_msg = B0 + msg
            obj_msg = bytearray.fromhex(obj_msg)
        else:
            msg = '{MHDR}{AppEUI}{DevEUI}{DevNonce}'.format(**kwargs)
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
        pld_len = len(payload) // 2
        payload = Padding.pad(payload, 16)
        k = math.ceil(pld_len / 16)
        cryptor = AES.new(key, AES.MODE_ECB)
        S = b''
        for i in range(1, k + 1):
            kwargs['i'] = '{:0>2x}'.format(i)
            _A_each = DeviceOp._A(**kwargs)
            Ai = bytearray.fromhex(_A_each)
            Si = cryptor.encrypt(Ai)
            S += Si
        return b''.join(DeviceOp.bytes_xor(S, payload))[:pld_len * 2 + 1]

    def get_keys(self, DevAddr, key_list=None):
        if not key_list:
            key_list = [
                'NwkSKey',
                'AppSKey',
                'AppKey',
            ]

        query_condition = {
            'DevAddr': DevAddr,
        }
        table_name = 'DeviceInfo'
        cli = db.Mycli(config=self.database_conf)
        row = cli.query_info(
            query_condition=query_condition,
            table_name=table_name, attributes=key_list
        )
        return row[0]

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
        if FPort == 0:
            enc_key = NwkSKey
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


if __name__ == '__main__':
    DevAddr = '55667788'
    direction = '00'
    FCnt = '000000FF'
    FCnt_low = FCnt[-4:]
    payload = b'hello'.hex()
    FPort = '02'
    MHDR = '80'
    F_ADR = 0
    F_ADRACKReq = 0
    F_ACK = 0
    F_ClassB = 0
    FCtrl = {
        'ADR': F_ADR,
        'ADRACKReq': F_ADRACKReq,
        'ACK': F_ACK,
        'ClassB': F_ClassB,
    }
    FOpts = '020203'
    device = DeviceOp()
    FHDR = device.form_FHDR(
            DevAddr=DevAddr,
            FCtrl=FCtrl,
            FCnt=FCnt_low,
            FOpts=FOpts
            )
    kwargs = {
        'DevAddr': DevAddr,
        'FCnt': FCnt,
        'FHDR': FHDR,
        'MHDR': MHDR,
        'FPort': FPort,
        'direction': direction,
        'FCtrl': FCtrl,
        'FRMPayload': payload,
    }
    pprint(kwargs)
    keys = device.get_keys(DevAddr)
    print(keys)
    NwkSKey, AppSKey = [bytearray.fromhex(x) for x in keys]
    mic = device.cal_mic(key=NwkSKey, **kwargs)
    enc_msg = device.encrypt(key=AppSKey, payload=payload, **kwargs)
    macpayload = device.form_payload(
            NwkSKey=NwkSKey,
            AppSKey=AppSKey,
            **kwargs
        )
    print(macpayload)
    gateway = GatewayOp('DDDDDDDDDDDDDDDD')
