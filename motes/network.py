import socket


class UDPClient:
    def __init__(self, target, address=None):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if address:
            self.s.bind(address)
        self.target = target

    def send(self, data):
        self.s.sendto(data, self.target)

    def recv(self, size=4096):
        return self.s.recvfrom(size)
