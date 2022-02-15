import struct
import socket


class NewDeviceError(FileNotFoundError):
    pass


class ActivationError(TypeError):
    pass


class MICError(ValueError):
    """
    MIC mismatches exception
    Attributes:
        typ: Type of message
        recv_mic: Received MIC in bytes
        calc_mic: Calculated MIC in bytes
    """
    def __init__(self, typ, recv_mic, calc_mic):
        self.typ = typ
        self.recv_mic = recv_mic.hex()
        self.calc_mic = calc_mic.hex()
        self.message = (f'MIC of {self.typ} message mismatches\n'
            f'Received MIC: {self.recv_mic}\n'
            f'Calculated MIC: {self.calc_mic}')
        super().__init__(self.message)


class StructParseError(struct.error):
    """
    Struct parse exception, for better debugging

    Attributes:
        typ: type of message
        fmt: predefined format
        data: bytes data
    """
    def __init__(self, typ, fmt, data):
        self.typ = typ
        self.fmt = fmt
        try:
            self.data = data.tobytes()
        except AttributeError:
            self.data = data
        self.message = f'Parsing {self.typ} message error, \npredefined format: {self.fmt},\nreceived data: {self.data.hex()}'
        super().__init__(self.message)


class FOptsError(ValueError):
    pass


class NoResponseError(socket.timeout):
    pass

