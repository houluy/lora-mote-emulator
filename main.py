"""LoRa Motes Emulator

This is the main script of the emulator.

"""

import json
import logging
import socket
import random

import yaml

from motes import mac, network
from motes.cli import define_parser

def init():
    """
    Initialization
    """
    logger = logging.getLogger('main')

    args = define_parser().parse_args()

    if not args.debug:
        logger.exception = logger.error

    config_file = 'config/config.yml'
    original_file = 'config/device.json'
    device_file = 'models/device.pkl'

    with open(config_file) as f:
        config = yaml.load(f, Loader=yaml.FullLoader)

    with open(original_file) as f:
        device_conf = json.load(f)

    target = (config.get('dest').get('hostname'), config.get('dest').get('port'))
    local = (config.get('src').get('hostname'), config.get('src').get('port'))
    appkey, nwkkey = [
        bytes.fromhex(device_conf.get('keys').get(key)) for key in ['AppKey', 'NwkKey']
    ]
    device_info = device_conf.get('Device')
    joineui = bytes.fromhex(device_info.get('JoinEUI'))
    deveui = bytes.fromhex(device_info.get('DevEUI'))
    gweui = device_conf.get('Gateway').get('GatewayEUI')
    try:
        mote = mac.Mote.load(device_file)
    except FileNotFoundError:
        mote = mac.Mote(joineui, deveui, appkey, nwkkey, device_file)
    gateway = mac.Gateway(gweui)
    udp_client = network.UDPClient(target, address=local)
    return logger, args, gateway, udp_client, mote


def main():
    """main

    This is the main function
    """
    logger, args, gateway, udp_client, mote = init()

    try:
        if args.type == 'pull':
            gateway.pull(udp_client)
        else:
            if args.type == 'join':
                phypld = mote.form_join()
            elif args.type == 'rejoin':
                phypld = mote.form_rejoin(args.rejointyp)
            elif args.type == 'app':
                fopts = bytes.fromhex(args.fopts) if args.fopts else b''
                fport = random.randint(1, 255)
                msg = args.msg.encode()
                phypld = mote.form_phypld(fport, msg, fopts, args.unconfirmed, args.version)
            elif args.type == 'cmd':
                fport = 0
                phypld = mote.form_phypld(fport, bytes.fromhex(args.cmd), unconfirmed=args.unconfirmed, version=args.version)
            else:
                raise NotImplementedError
            gateway.push(udp_client, phypld, mote)
    except socket.timeout as e:
        logger.exception('Socket Timeout, remote server is unreachable')
    except AttributeError as e:
        logger.exception('You need to finish Join procedure before sending application data')
    except mac.MICError as e:
        logger.exception('MIC mismatch')
    except ValueError as e:
        logger.exception('Value Error')
    except NotImplementedError as e:
        logger.exception(e)

main()
