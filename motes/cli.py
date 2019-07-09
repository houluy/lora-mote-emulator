import argparse

parser = argparse.ArgumentParser(
    description='Tool for test on LoRaWAN server'
)

parser.add_argument(
    'type',
    metavar='type',
    help='Data type of uplink, supported type list: [join, app, pull, cmd]',
    choices=['join', 'app', 'pull', 'cmd'],
    default='join'
)

parser.add_argument(
    '-n',
    '--version',
    metavar='version',
    help='Choose LoRaWAN version, 1.0.2 or 1.1 (default)',
    choices=['1.0.2', '1.1'],
    default='1.1'
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

parser.add_argument(
    '-d', '--debug', help='Start debug mode, log more infomation', dest='debug', action='store_true'
)

parser.add_argument(
    '-u', '--unconfirm', help='Enable unconfirmed data up', dest='unconfirm', action='store_true'
)

del argparse

__all__ = ['parser']
