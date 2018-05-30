import argparse
import os
import time
from functools import partial
from pprint import pprint

from colorline import cprint

import yaml
from lora_network_server import data_reader, log_show, network, phy_parser

import pdb

parser = argparse.ArgumentParser(
    description='LoRa server test',
    prefix_chars='-+'
)
parser.add_argument(
    'target',
    help='test simple/full server',
    choices=['simple', 'full'],
    default='simple'
)
parser.add_argument(
    '-t',
    '--data-type',
    help='Specify which kind of packages',
    choices=['pull', 'push', 'join', 'stat', 'rxpk'],
    dest='data_type'
)
parser.add_argument(
    '-i',
    '--index',
    type=int,
    help='Specify which test case',
)

args = parser.parse_args()

# nprint = partial(cprint, color='c', bcolor='k')
# iprint = partial(cprint, color='g', bcolor='k')
nprint = print
iprint = print

config_file = 'config.yml'

with open(config_file) as f:
    config = yaml.load(f)
device_handler = phy_parser.DeviceOp()
basic_config = config.get('target').get(args.target)
target = (config.get('host'), basic_config.get('port'))
keys = basic_config.get('keys')

udp_client = network.UDPClient(target)
reader = data_reader.Test_data(config.get('test_file'))
test_cases = config.get('test_cases')
log = log_show.LogShow(config=config.get('log_config'), print_method=print)

for test_type, test_conf in test_cases.items():
    if args.data_type:
        if args.data_type != test_type:
            continue
    start = test_conf.get('start')
    end = test_conf.get('end')
    start_col = start.get('col')
    start_row = start.get('row')
    end_col = end.get('col')
    end_row = end.get('row')
    title, values = reader.range_values(
        start_col=start_col,
        end_col=end_col,
        start_row=start_row,
        end_row=end_row
    ).values()
    AppKey = bytearray.fromhex(keys.get('AppKey'))
    nprint('Test for {} data'.format(test_type))
    for ind, v in enumerate(values):
        params = dict(zip(title, v))
        instruction = params.pop('说明')
        desired_log = params.pop('log')
        if args.index is not None:
            if args.index != ind:
                continue
        if args.target == 'simple':
            desired_log = 'simple'
        else:
            desired_log = desired_log.split(',')
        iprint('Test index: {}  Instruction: {}\n'.format(ind, instruction))
        gateway_id = params.pop('gateway_id')
        gateway = phy_parser.GatewayOp(gateway_id)
        udp_attrs = {k: params.get(k) for k in gateway.gateway_attributes}
        print('Test data in JSON:')
        pprint(params)
        if test_type == 'pull':
            udp_data = gateway.pull_data(**params)
            print('RAW pull data: {}'.format(udp_data.hex()))
        elif test_type == 'join':
            device_attributes = device_handler.join_attributes
            params['direction'] = '00'
            device_data = {k: params.get(k) for k in device_attributes}
            if len(device_data['DevNonce']) == 4:
                device_data['DevNonce'] = os.urandom(2).hex()
            raw_data = device_handler.form_join(key=AppKey, **device_data)
            if instruction == 'MIC错误':
                raw_data = raw_data[:-2] + 'AA'
            udp_data = gateway.push_data(data=raw_data, **udp_attrs)
            # print('Test MACPayload: {}'.format(raw_data))
            print('RAW join data MACPAYLOAD: {}'.format(raw_data))
        elif test_type == 'push':
            device_attributes = device_handler.attributes
            AppSKey = bytearray.fromhex(keys.get('AppSKey'))
            NwkSKey = bytearray.fromhex(keys.get('NwkSKey'))
            params['direction'] = '00'
            device_data = {k: params.get(k) for k in device_attributes}
            raw_data = device_handler.form_payload(
                NwkSKey=NwkSKey,
                AppSKey=AppSKey,
                **device_data
            )
            print('RAW push data MACPAYLOAD: {}'.format(raw_data))
            if instruction == 'MIC错误':
                raw_data = raw_data[:-2] + 'AA'

            udp_data = gateway.push_data(data=raw_data, **udp_attrs)
        elif test_type == 'stat':
            # pdb.set_trace()
            stat_data = gateway.form_json(gateway.stat_attributes, typ=test_type, **params)
            json_obj = gateway.form_gateway_data(stat=stat_data)
            udp_data = gateway.push_data(json_obj=json_obj)
        elif test_type == 'rxpk':
            pdb.set_trace()
            rxpk_data = gateway.form_json(gateway.rxpk_attributes, typ=test_type, **params)
            json_obj = gateway.form_gateway_data(rxpk=rxpk_data)
            udp_data = gateway.push_data(json_obj=json_obj)
        print(udp_data)
        # params['gateway_id'] = gateway_id
        udp_client.send(udp_data)
        time.sleep(1)
        log.show(log=desired_log)
