import argparse

def define_parser():
    message_lst = ['join', 'app', 'pull', 'mac', 'rejoin', 'info', 'abp']
    parser = argparse.ArgumentParser(
        description=f'Tool to emulate LoRa mote (a.k.a end-device) and Gateway, supported command list: {message_lst}'
    )
    sub_parsers = parser.add_subparsers(title="Supported commands", dest="command")
    join_parser = sub_parsers.add_parser("join", help="Send join request.", description="Send a join request using parameters in the config file.")
    join_parser.add_argument(
        '-n', '--new', help=('Flag for brand new device, using device info in device.yml config file.'
            ' Be careful this flag can override current device, information may be lost.'), dest='new', action='store_true'
    )
    app_parser = sub_parsers.add_parser("app", help="Send application data.", description="Send a normal application data, and fetch the downlink message if there is any.")
    app_parser.add_argument(
        '-f', help='MAC Command in FOpts field', dest='fopts'
    )
    app_parser.add_argument(
        '-u', '--unconfirmed', help='Enable unconfirmed data up', dest='unconfirmed', action='store_true'
    )
    app_parser.add_argument(
        '-a', '--ack', help=('Identity an acknowledgement of downlink message'), dest='ack', action='store_true'
    )
    app_parser.add_argument(
        "msg", help="Message to be sent, 'str' required, default empty string.", default=""
    )
    pull_parser = sub_parsers.add_parser("pull", help="Send PULL_DATA.")
    mac_parser = sub_parsers.add_parser("mac", help="Send MACCommand.", description="Send MACCommand via FRMPayload field. Using 'mote app -f' to send MACCommand via FOpts field.")
    mac_parser.add_argument(
        'cmd', help="MACCommand to be sent via FRMPayload, 'str' required, must be hex string, no default value."
    )
    mac_parser.add_argument(
        '-u', '--unconfirmed', help='Enable unconfirmed data up', dest='unconfirmed', action='store_true'
    )
    mac_parser.add_argument(
        '-a', '--ack', help=('Identity an acknowledgement of downlink message'), dest='ack', action='store_true'
    )
    rejoin_parser = sub_parsers.add_parser("rejoin", help="Send rejoin request.")
    rejoin_parser.add_argument(
        'typ',
        help="Specify rejoin type, 'int' required, default is 0",
        type=int,
        choices=[0, 1, 2],
        default=0,
    )
    info_parser = sub_parsers.add_parser("info", help="Show information of current mote.")
    abp_parser = sub_parsers.add_parser("abp", help="Initialize mote in ABP mode.")
    parser.add_argument(
        '-v',
        '--version',
        metavar='version',
        help='Choose LoRaWAN version, 1.0.2 or 1.1(default)',
        choices=['1.0.2', '1.1'],
        default='1.1'
    )
    parser.add_argument(
        '-c',
        '--config',
        help="Specify the directory of config files, default './config'",
        type=str,
        default="./config",
    )
    parser.add_argument(
        '--model',
        help="Specify the directory to save the model file, default './models'",
        type=str,
        default="./models",
    )
    return parser

__all__ = ['define_parser']
