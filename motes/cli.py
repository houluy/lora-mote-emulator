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
    'version',
    metavar='version',
    help='Choose LoRaWAN version, 1.0.2 or 1.1',
    choices=['1.0.2', '1.1'],
    default='1.0.2'
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

del argparse

__all__ = ['parser']
