import argparse
import json
import os
import shutil
import struct
import sys
import threading
import time
import logging
import socket
from pprint import pprint

import yaml

from motes import log, mac, network

nprint = mac.nprint
logger = logging.getLogger('main')

parser = argparse.ArgumentParser(
    description='Tool for test on LoRaWAN server'
)

parser.add_argument(
    'type',
    help='Data type of uplink',
    choices=['join', 'app', 'pull'],
    default='join'
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

parser.add_argument(
    '-n',
    help='Brand new device',
    default=False,
    dest='new',
    action='store_true'
)

args = parser.parse_args()

config_file = 'config.yml'
device_info_file = 'device.json'
original_file = 'device_back.json'

with open(config_file) as f:
    config = yaml.load(f)

with open(original_file) as f:
    device_info = json.load(f)

target = (config.get('dest').get('hostname'), config.get('dest').get('port'))
local = (config.get('src').get('hostname'), config.get('src').get('port'))
keys = device_info.get('keys')
keys = {
    key: bytes.fromhex(val) for key, val in keys.items()
}

gateway_id = device_info.get('Gateway').get('GatewayEUI')
device_handler = mac.DeviceOp()
gateway_handler = mac.GatewayOp(gateway_id)
udp_client = network.UDPClient(target, address=local)

if args.type == 'pull':
    try:
        gateway_handler.pull(udp_client)
    except socket.timeout as e:
        logger.error('Socket Timeout, remote server is unreachable')
    except struct.error as e:
        logger.error('struct unpacking ERROR {}'.format(e))
    finally:
        sys.exit(0)

if args.new:
    shutil.copyfile(original_file, device_info_file)

device = device_info.get('Device')


def uplink(udp_client, typ='app'):
    while True:
        if typ == 'join':
            join_params = device
            join_params['DevNonce'] = os.urandom(2).hex()
            join_params['MHDR'] = '00'
            AppKey = keys.get('AppKey')
            join_mac = device_handler.form_join(
                key=AppKey,
                **join_params
            )
            nprint('Join MAC Payload:')
            pprint(join_mac)
            data = gateway_handler.push_data(data=join_mac)
        elif typ == 'app':
            DevAddr = device.get('DevAddr')
            FCnt = struct.pack('<i', device.get('FCnt')).hex()
            MHDR = '80'
            device['MHDR'] = MHDR
            direction = '00'
            FPort = struct.pack('<b', device.get('FPort')).hex()
            payload = device.get('payload')
            F_ADR = device.get('ADR')
            F_ADRACKReq = 0
            F_ACK = 0
            F_ClassB = 0
            FCtrl = {
                'ADR': F_ADR,
                'ADRACKReq': F_ADRACKReq,
                'ACK': F_ACK,
                'ClassB': F_ClassB,
            }
            FOpts = device.get('FOpts')
            FHDR = device_handler.form_FHDR(
                    DevAddr=DevAddr,
                    FCtrl=FCtrl,
                    FCnt=FCnt,
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
            nprint('Uplink data:')
            pprint(kwargs)
            macpayload = device_handler.form_payload(
                NwkSKey=keys.get('NwkSKey'),
                AppSKey=keys.get('AppSKey'),
                **kwargs
            )
            nprint('Raw MAC Payload:')
            print(macpayload)
            data = gateway_handler.push_data(data=macpayload)
        else:
            pass
        udp_client.send(data)
        time.sleep(args.interval)
        if args.single:
            return


def downlink(udp_client):
    while True:
        res = udp_client.recv()
        txpk = gateway_handler.parse_dlk(res[0])
        if txpk:
            mac.nprint('---Received a Dlk Package---')
            try:
                out = gateway_handler.get_txpk_data(
                    keys,
                    txpk=txpk
                )
            except ValueError as e:
                mac.eprint(e)
                continue
            if out.get('AppNonce'):
                genedkeys = device_handler.gen_keys(
                    keys.get('AppKey'),
                    out.get('NetID'),
                    out.get('AppNonce'),
                    mac.DeviceOp.str_rev(device.get('DevNonce'))
                )
                device_info['Device'] = {
                    **device,
                    'AppNonce': mac.DeviceOp.str_rev(out.get('AppNonce')),
                    'DevNonce': device.get('DevNonce'),
                    'DevAddr': mac.DeviceOp.str_rev(out.get('DevAddr')),
                    'NetID': mac.DeviceOp.str_rev(out.get('NetID')),
                    'FCnt': 0,
                    'FPort': 1,
                    'ADR': 1,
                    'FOpts': '',
                    'payload': 'hello',
                }
                device_info['keys'] = {
                    **device_info['keys'],
                    **genedkeys,
                }
                nprint('Device info details:')
                pprint(device_info)
                with open(device_info_file, 'w') as f:
                    json.dump(device_info, f, indent=2)
            else:
                nprint('---Dlk package details: ---')
                pprint(out)
                nprint('----------------END----------------')


uplink_thread = threading.Thread(target=uplink, args=(udp_client, args.type))
downlink_thread = threading.Thread(target=downlink, args=(udp_client,))

downlink_thread.start()
uplink_thread.start()
downlink_thread.join()
uplink_thread.join()
