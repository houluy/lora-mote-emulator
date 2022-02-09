"""LoRa Motes Emulator

This is the main script of the emulator.
Author: Lu Hou
Email: houlu8674@bupt.edu.cn

"""

import json
import logging
import socket
import random
import shutil
import pathlib

import mote.log
from mote import mac, network
from mote.cli import define_parser
from mote.config import Config, load_config, parse_config
from mote.exceptions import *


def init_gateway(args):
    base_config_dir = pathlib.Path(args.config)
    config = load_config(base_config_dir / 'config.json')
    target = (config.dest.hostname, config.dest.port)
    local = (config.src.hostname, config.src.port)
    gateway_file = base_config_dir / 'gateway.json'
    with open(gateway_file) as f:
        gateway_conf = json.load(f)
    gweui = gateway_conf.get('GatewayEUI')
    gateway = mac.Gateway(gweui)
    udp_client = network.UDPClient(target, address=local, timeout=config.timeout)
    return gateway, udp_client


def init_mote(args):
    base_config_dir = pathlib.Path(args.config)
    base_model_dir = pathlib.Path(args.model)
    original_file = base_config_dir / 'device.json'
    abp_file = base_config_dir / 'abp.json'
    device_file = base_model_dir / 'device.pkl'

    with open(original_file) as f:
        device_conf = parse_config(json.load(f), Config())

    if args.command == 'abp':
        with open(abp_file) as f:
            abp_conf = json.load(f)
        mote = mac.Mote.abp(**abp_conf)
    else:
        if args.command == 'join' and args.new:
            appkey = device_conf.RootKeys.AppKey
            nwkkey = device_conf.RootKeys.NwkKey
            device_info = device_conf.Device
            joineui = device_info.JoinEUI
            deveui = device_info.DevEUI
            mote = mac.Mote(joineui, deveui, appkey, nwkkey)
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
        gateway, udp_client = init_gateway(args)
        if args.command == 'pull':
            gateway.pull(udp_client)
        else:
            mote = init_mote(args)
            if args.command == 'info':
                print(mote)
            elif args.command == 'abp':
                logger.info('Device successfully been setup in ABP mode')
                print(mote)
            else:
                if args.command == 'join':
                    if mote.activation_mode == 'ABP':
                        raise ActivationError(f'ABP device cannot issue {args.command} request')
                    phypld = mote.form_join()
                elif args.command == 'rejoin':
                    if mote.activation_mode == 'ABP':
                        raise ActivationError(f'ABP device cannot issue {args.command} request')
                    phypld = mote.form_rejoin(args.rejointyp)
                elif args.command == 'app':
                    fopts = bytes.fromhex(args.fopts) if args.fopts else b''
                    fport = random.randint(1, 223)
                    msg = args.msg.encode()
                    phypld = mote.form_phypld(fport, msg, fopts, unconfirmed=args.unconfirmed, ack=args.ack)
                elif args.command == 'mac':
                    fport = 0
                    phypld = mote.form_phypld(fport, bytes.fromhex(args.cmd), unconfirmed=args.unconfirmed, ack=args.ack)
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
    except json.decoder.JSONDecodeError as e:
        logger.error('Bad config file format, please copy a new file from template')
    except Exception as e:
        logger.exception(e)

