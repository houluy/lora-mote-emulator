import argparse
# from functools import partial
from pprint import pprint

# from colorline import cprint

import yaml
from motes import network, mac

# import pdb

import threading

import time

import json
import os

parser = argparse.ArgumentParser(
    description='LoRa server test'
)
# parser.add_argument(
#     'target',
#     help='test simple/full server',
#     choices=['simple', 'full'],
#     default='simple'
# )
# parser.add_argument(
#     '-t',
#     '--data-type',
#     help='Specify which kind of packages',
#     choices=['pull', 'push', 'join', 'stat', 'rxpk'],
#     dest='data_type'
# )
# parser.add_argument(
#     '-i',
#     '--index',
#     type=int,
#     help='Specify which test case',
# )

parser.add_argument(
    'type',
    help='Data type of uplink',
    choices=['join', 'app']
)

parser.add_argument(
    '-i',
    help='Inteval of uplink',
    type=int,
    default=5,
    dest='interval'
)

parser.add_argument(
    '-s',
    help='Sign for single pack',
    default=False,
    dest='single',
    action='store_true'
)

args = parser.parse_args()

# nprint = partial(cprint, color='c', bcolor='k')
# iprint = partial(cprint, color='g', bcolor='k')
# nprint = print
# iprint = print

config_file = 'config.yml'
device_info_file = 'device.inf'

with open(config_file) as f:
    config = yaml.load(f)

with open(device_info_file) as f:
    device_info = json.load(f)
# basic_config = config.get('target').get(args.target)
# target = (config.get('host'), basic_config.get('port'))
target = ('10.3.242.235', 12234)
database_conf = config.get('database').get('mysql')
gateway_id = 'DDDDDDDDDDDDDDDD'
device_handler = mac.DeviceOp(database_conf)
gateway_handler = mac.GatewayOp(gateway_id)
AppEUI = '9816be466f467a17'
DevEUI = 'e97c762de97c762d'
# keys = basic_config.get('keys')
DevAddr = '55667788'
direction = '00'
FCnt = '000000FF'
FCnt_low = FCnt[-4:]
payload = b'\x02\x02\x02\x02'
FPort = '00'
MHDR = '80'
joinMHDR = '00'
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
FOpts = ''
FHDR = device_handler.form_FHDR(
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

if args.type == 'app':
    keys = device_handler.get_keys(DevAddr)
    NwkSKey, AppSKey, AppKey = [bytearray.fromhex(x) for x in keys]
    dlk_key = AppSKey
# mic = device_handler.cal_mic(key=NwkSKey, **kwargs)
# enc_msg = device_handler.encrypt(key=AppSKey, **kwargs)
else:
    dlk_key = AppKey = bytes.fromhex('1d01d94541d57b101d01d94541d57b10')
    # joinpayload = device_handler.form_join(
    #     key=AppKey,
    #     **join_kwargs
    # )
    # print('joinp: {}'.format(joinpayload))
    # data = gateway_handler.push_data(data=joinpayload)

udp_address = ('10.3.242.235', 12367)
pull_data = gateway_handler.pull_data()

udp_client = network.UDPClient(target, address=udp_address)
udp_client.send(pull_data)


def uplink(udp_client, typ='app'):
    while True:
        if typ == 'join':
            DevNonce = os.urandom(2).hex()
            join_kwargs = {
                'MHDR': joinMHDR,
                'AppEUI': AppEUI,
                'DevEUI': DevEUI,
                'DevNonce': DevNonce,
            }
            joinpayload = device_handler.form_join(
                    key=AppKey,
                    **join_kwargs
                )
            print('joinpayload: {}'.format(joinpayload))
            data = gateway_handler.push_data(data=joinpayload)
        else:
            macpayload = device_handler.form_payload(
                NwkSKey=NwkSKey,
                AppSKey=AppSKey,
                **kwargs
            )
            print('apppayload: {}'.format(joinpayload))
            data = gateway_handler.push_data(data=macpayload)

        udp_client.send(data)
        time.sleep(args.interval)
        if args.single:
            return


def downlink(udp_client):
    while True:
        res = udp_client.recv()
        txpk = gateway_handler.parse_dlk(res[0])
        if txpk:
            gateway_handler.get_txpk_data(key=dlk_key, txpk=txpk)


uplink_thread = threading.Thread(target=uplink, args=(udp_client, args.type))
downlink_thread = threading.Thread(target=downlink, args=(udp_client,))

uplink_thread.start()
downlink_thread.start()
uplink_thread.join()
downlink_thread.join()


# reader = data_reader.Test_data(config.get('test_file'))
# test_cases = config.get('test_cases')
# log = log_show.LogShow(config=config.get('log_config'), print_method=print)

# for test_type, test_conf in test_cases.items():
#     if args.data_type:
#         if args.data_type != test_type:
#             continue
#     start = test_conf.get('start')
#     end = test_conf.get('end')
#     start_col = start.get('col')
#     start_row = start.get('row')
#     end_col = end.get('col')
#     end_row = end.get('row')
#     title, values = reader.range_values(
#         start_col=start_col,
#         end_col=end_col,
#         start_row=start_row,
#         end_row=end_row
#     ).values()
#     AppKey = bytearray.fromhex(keys.get('AppKey'))
#     nprint('Test for {} data'.format(test_type))
#     for ind, v in enumerate(values):
#         params = dict(zip(title, v))
#         instruction = params.pop('说明')
#         desired_log = params.pop('log')
#         if args.index is not None:
#             if args.index != ind:
#                 continue
#         if args.target == 'simple':
#             desired_log = 'simple'
#         else:
#             desired_log = desired_log.split(',')
#         iprint('Test index: {}  Instruction: {}\n'.format(ind, instruction))
#         gateway_id = params.pop('gateway_id')
#         gateway = phy_parser.GatewayOp(gateway_id)
#         udp_attrs = {k: params.get(k) for k in gateway.gateway_attributes}
#         print('Test data in JSON:')
#         pprint(params)
#         if test_type == 'pull':
#             udp_data = gateway.pull_data(**params)
#             print('RAW pull data: {}'.format(udp_data.hex()))
#         elif test_type == 'join':
#             device_attributes = device_handler.join_attributes
#             params['direction'] = '00'
#             device_data = {k: params.get(k) for k in device_attributes}
#             if len(device_data['DevNonce']) == 4:
#                 device_data['DevNonce'] = os.urandom(2).hex()
#             raw_data = device_handler.form_join(key=AppKey, **device_data)
#             if instruction == 'MIC错误':
#                 raw_data = raw_data[:-2] + 'AA'
#             udp_data = gateway.push_data(data=raw_data, **udp_attrs)
#             # print('Test MACPayload: {}'.format(raw_data))
#             print('RAW join data MACPAYLOAD: {}'.format(raw_data))
#         elif test_type == 'push':
#             device_attributes = device_handler.attributes
#             AppSKey = bytearray.fromhex(keys.get('AppSKey'))
#             NwkSKey = bytearray.fromhex(keys.get('NwkSKey'))
#             params['direction'] = '00'
#             device_data = {k: params.get(k) for k in device_attributes}
#             raw_data = device_handler.form_payload(
#                 NwkSKey=NwkSKey,
#                 AppSKey=AppSKey,
#                 **device_data
#             )
#             print('RAW push data MACPAYLOAD: {}'.format(raw_data))
#             if instruction == 'MIC错误':
#                 raw_data = raw_data[:-2] + 'AA'
# 
#             udp_data = gateway.push_data(data=raw_data, **udp_attrs)
#         elif test_type == 'stat':
#             # pdb.set_trace()
#             stat_data = gateway.form_json(gateway.stat_attributes, typ=test_type, **params)
#             json_obj = gateway.form_gateway_data(stat=stat_data)
#             udp_data = gateway.push_data(json_obj=json_obj)
#         elif test_type == 'rxpk':
#             pdb.set_trace()
#             rxpk_data = gateway.form_json(gateway.rxpk_attributes, typ=test_type, **params)
#             json_obj = gateway.form_gateway_data(rxpk=rxpk_data)
#             udp_data = gateway.push_data(json_obj=json_obj)
#         print(udp_data)
#         # params['gateway_id'] = gateway_id
#         udp_client.send(udp_data)
#         time.sleep(1)
#         log.show(log=desired_log)
