import argparse
import json
import logging
import socket

import yaml

from motes import mac, network

logger = logging.getLogger('main')

parser = argparse.ArgumentParser(
    description='Tool for test on LoRaWAN server'
)

parser.add_argument(
    'type',
    help='Data type of uplink',
    choices=['join', 'app', 'pull', 'cmd'],
    default='join'
)

parser.add_argument(
    '-m', help='Payload', dest='msg'
)

parser.add_argument(
    '-f', help='MAC Command in FOpts field', dest='fopts'
)

parser.add_argument(
    '-c', help='MAC Command in FRMPayload field', dest='cmd'
)

args = parser.parse_args()

config_file = 'config/config.yml'
original_file = 'config/device.json'
device_file = 'models/device.pkl'

with open(config_file) as f:
    config = yaml.load(f)

with open(original_file) as f:
    device_conf = json.load(f)

target = (config.get('dest').get('hostname'), config.get('dest').get('port'))
local = (config.get('src').get('hostname'), config.get('src').get('port'))
appkey = bytes.fromhex(device_conf.get('keys').get('AppKey'))
device_info = device_conf.get('Device')
appeui = bytes.fromhex(device_info.get('AppEUI'))
deveui = bytes.fromhex(device_info.get('DevEUI'))

gateway_id = device_conf.get('Gateway').get('GatewayEUI')
try:
    mote = mac.Mote.load(device_file)
except FileNotFoundError:
    mote = mac.Mote(appeui, deveui, appkey, device_file)
gateway = mac.GatewayOp(gateway_id)
udp_client = network.UDPClient(target, address=local)

try:
    if args.type == 'pull':
        gateway.pull(udp_client)
    elif args.type == 'join':
        mote.join(gateway, udp_client)
    elif args.type == 'app':
        fopts = bytes.fromhex(args.fopts) if args.fopts else b''
        mote.app(
            gateway, udp_client, args.msg.encode(), fopts
        )
    elif args.type == 'cmd':
        pld = bytes.fromhex(args.cmd)
        mote.cmd(
            gateway, udp_client, pld
        )
    else:
        raise NotImplementedError
except socket.timeout as e:
    logger.error('Socket Timeout, remote server is unreachable')
