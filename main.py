"""LoRa Motes Emulator

This is the main script of the emulator.

"""

import json
import logging
import socket
import random
import sys

import yaml

from motes import mac, network
from motes.cli import define_parser
from motes.config import load_config, parse_config


class NewDeviceError(FileNotFoundError):
    pass


def init(args):
    """
    Initialization
    Args:
        args: Command line arguments
    """
    
    original_file = 'config/device.yml'
    abp_file = 'config/abp.yml'
    device_file = 'models/device.pkl'

    with open(original_file) as f:
        device_conf = parse_config(yaml.load(f, Loader=yaml.FullLoader))

    if args.abp:
        with open(abp_file) as f:
            abp_conf = yaml.load(f, Loader=yaml.FullLoader)
        mote = mac.Mote.abp(**abp_conf)
    else:
        if args.new:
            appkey = device_conf.Keys.AppKey
            nwkkey = device_conf.Keys.NwkKey
            device_info = device_conf.Device
            joineui = device_info.JoinEUI
            deveui = device_info.DevEUI
            mote = mac.Mote(joineui, deveui, appkey, nwkkey, device_file)
        else:
            try:
                mote = mac.Mote.load(device_file)
            except FileNotFoundError:
                raise NewDeviceError('No device found, please use -n flag to create brand new device\n'
                    'or use abp command to activate new device by ABP') from None
    config = load_config()
    target = (config.dest.hostname, config.dest.port)
    local = (config.src.hostname, config.src.port)
    gweui = device_conf.Gateway.GatewayEUI
    gateway = mac.Gateway(gweui)
    udp_client = network.UDPClient(target, address=local)
    return gateway, udp_client, mote


def main():
    """main

    This is the main function
    """
    logger = logging.getLogger('main')
    try:
        args = define_parser().parse_args()
        gateway, udp_client, mote = init(args)
        if args.type == 'pull':
            gateway.pull(udp_client)
        elif args.type == 'info':
            print(mote)
        else:
            if args.type == 'join':
                phypld = mote.form_join()
            elif args.type == 'rejoin':
                phypld = mote.form_rejoin(args.rejointyp)
            elif args.type == 'app':
                fopts = bytes.fromhex(args.fopts) if args.fopts else b''
                fport = random.randint(1, 255)
                msg = args.msg.encode()
                phypld = mote.form_phypld(fport, msg, fopts, args.unconfirmed)
            elif args.type == 'cmd':
                fport = 0
                phypld = mote.form_phypld(fport, bytes.fromhex(args.cmd), unconfirmed=args.unconfirmed)
            else:
                raise NotImplementedError
            gateway.push(udp_client, phypld, mote, args.unconfirmed)
    except socket.timeout as e:
        logger.exception('Socket Timeout, remote server is unreachable')
    except AttributeError as e:
        logger.exception('You need to finish Join procedure before sending application data')
    except mac.MICError as e:
        logger.exception(e)
    except ValueError as e:
        logger.exception(e)
    except NotImplementedError as e:
        logger.exception(e)
    except NewDeviceError as e:
        logger.exception(e)
    except yaml.scanner.ScannerError as e:
        logger.exception('Bad config file format, please copy a new file from template')
    except Exception as e:
        logger.error(e)

main()
