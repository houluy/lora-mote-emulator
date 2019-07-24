import argparse

def define_parser():
    parser = argparse.ArgumentParser(
        description='Tool for test on LoRaWAN server'
    )

    message_lst = ['join', 'app', 'pull', 'cmd', 'rejoin', 'info']

    parser.add_argument(
        'type',
        metavar='type',
        help=f'Data type of uplink, supported type list: {message_lst}',
        choices=message_lst,
        default='info'
    )

    parser.add_argument(
        '-v',
        '--version',
        metavar='version',
        help='Choose LoRaWAN version, 1.0.2 or 1.1(default)',
        choices=['1.0.2', '1.1'],
        default='1.1'
    )

    parser.add_argument(
        '-m', help='FRMPayload in string', dest='msg'
    )

    parser.add_argument(
        '-f', help='MAC Command in FOpts field', dest='fopts'
    )

    parser.add_argument(
        '-c', help='MAC Command in FRMPayload field', dest='cmd'
    )

    parser.add_argument(
        '-u', '--unconfirmed', help='Enable unconfirmed data up', dest='unconfirmed', action='store_true'
    )

    parser.add_argument(
        '-n', '--new', help='Flag for brand new device, using device info in device.yml config file', dest='new', action='store_true'
    )

    parser.add_argument(
        '--abp', help='Activate device in ABP mode', dest='abp', action='store_true'
    )

    #parser.add_argument(
    #    '-i', '--info', help='Show information of current device for debugging', dest='info', action='store_true'
    #)

    parser.add_argument(
        '-r',
        '--rejoin',
        help='Specify rejoin type, default is 0',
        dest='rejointyp',
        type=int,
        choices=[0, 1, 2],
        default=0,
    )
    return parser

__all__ = ['define_parser']
