#!/usr/bin/env python

"""LoRa Motes Emulator

This is the main script of the emulator.

"""

import json
import logging
import socket
import random
import shutil
import pathlib

import yaml

from motes import mac, network
from motes.cli import define_parser
from motes.config import Config, load_config, parse_config
from motes.exceptions import *


def init_gateway():
    config = load_config()
    target = (config.dest.hostname, config.dest.port)
    local = (config.src.hostname, config.src.port)
    gateway_file = pathlib.Path('config/gateway.yml')
    with open(gateway_file) as f:
        gateway_conf = yaml.load(f, Loader=yaml.FullLoader)
    gweui = gateway_conf.get('GatewayEUI')
    gateway = mac.Gateway(gweui)
    udp_client = network.UDPClient(target, address=local, timeout=config.timeout)
    return gateway, udp_client


def init_mote(args):
    """
    Initialization
    Args:
        args: Command line arguments
    """
    
    original_file = pathlib.Path('config/device.yml')
    abp_file = pathlib.Path('config/abp.yml')
    device_file = pathlib.Path('models/device.pkl')

    with open(original_file) as f:
        device_conf = parse_config(yaml.load(f, Loader=yaml.FullLoader), Config())

    if args.type == 'abp':
        with open(abp_file) as f:
            abp_conf = yaml.load(f, Loader=yaml.FullLoader)
        mote = mac.Mote.abp(**abp_conf)
    else:
        if args.new:
            appkey = device_conf.RootKeys.AppKey
            nwkkey = device_conf.RootKeys.NwkKey
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
    return mote


def main():
    """main

    This is the main function
    """
    logger = logging.getLogger('main')
    try:
        args = define_parser().parse_args()
        gateway, udp_client = init_gateway()
        if args.type == 'pull':
            gateway.pull(udp_client)
        else:
            mote = init_mote(args)
            if args.type == 'info':
                print(mote)
            elif args.type == 'reset':
                mote.reset()
                logger.info('Device is reset')
                print(mote)
            elif args.type == 'abp':
                logger.info('Device successfully been setup in ABP mode')
                print(mote)
            else:
                if args.type == 'join':
                    if mote.activation_mode == 'ABP':
                        raise ActivationError(f'ABP device cannot issue {args.type} request')
                    phypld = mote.form_join()
                elif args.type == 'rejoin':
                    if mote.activation_mode == 'ABP':
                        raise ActivationError(f'ABP device cannot issue {args.type} request')
                    phypld = mote.form_rejoin(args.rejointyp)
                elif args.type == 'app':
                    fopts = bytes.fromhex(args.fopts) if args.fopts else b''
                    fport = random.randint(1, 223)
                    msg = args.msg.encode()
                    phypld = mote.form_phypld(fport, msg, fopts, args.unconfirmed)
                elif args.type == 'cmd':
                    fport = 0
                    phypld = mote.form_phypld(fport, bytes.fromhex(args.cmd), unconfirmed=args.unconfirmed)
                else:
                    raise NotImplementedError
                gateway.push(udp_client, phypld, mote)
    except socket.timeout as e:
        logger.error('Socket Timeout, remote server is unreachable')
    except AttributeError as e:
        logger.error('You need to finish Join procedure before sending application data')
        logger.exception(e)
    except (MICError, StructParseError, FOptsError, NewDeviceError, ActivationError) as e:
        logger.error(e)
    except NotImplementedError as e:
        logger.error(e)
    except yaml.scanner.ScannerError as e:
        logger.error('Bad config file format, please copy a new file from template')
    except Exception as e:
        logger.exception(e)

main()
