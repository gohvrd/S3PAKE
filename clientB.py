from twisted.internet import protocol, reactor
from random import seed, randint
from struct import pack, unpack
import public

pwB = 3
SK = None

g_power_xz = None
y = None

def receiveConnectRequest(message):
    global y

    seed()
    print('B action [*]: receiving A||X from A\n')
    y = randint(1, public.q - 1)
    print('B action [*]: choosing random number y from Zp') 
    print('B paramteters [*]: y = ', y)
    Y = public.g ** y * public.N ** pwB
    print('B action [*]: calculating Y') 
    print('B paramteters [*]: Y = ', Y)

    print('B action [*]: sending A||X||B||Y to S\n')

    return message + pack('hxq', public.B_identifier, Y)

def receiveTrustedServerResponse(response):
    global y
    global g_power_xz

    S_X, S_Y = unpack('qxq', response)
    print('B action [*]: receiving S_X||S_Y from S')
    print('S paramteters (received) [*]: S_X = ', S_X)
    print('S paramteters (received) [*]: S_Y = ', S_Y, '\n')
    g_power_xz = int(S_X / public.G((public.B_identifier, public.S_identifier, public.g ** y)) ** pwB)
    print('B calculates [*]: g^(xz) = ', g_power_xz)
    alpha = int(public.G((public.A_identifier, public.B_identifier, g_power_xz ** y)))
    print('B calculates [*]: alpha = ', alpha)

    print('B action [*]: sending S_Y||alpha to A\n')

    return pack('qxq', S_Y, alpha)

def receiveBeta(beta):
    global SK

    recv_beta = unpack('q', beta)[0]
    print('B action [*]: receiving beta from A')
    print('A paramteters (received) [*]: beta = ', recv_beta)
    print('B action [*]: independently calculate the beta\' and compare it with the beta')
    if recv_beta == int(public.G((public.B_identifier, public.A_identifier, g_power_xz ** y))):
        print('B action [*]: beta\' = beta\n')
        SK = public.H((public.A_identifier, public.B_identifier, g_power_xz ** y))
        print("B calculates [$COMPLETE$]: session key = ", SK)
    else:
        print('B action [*]: beta\' != beta')
        print("Error [!]: Wrong beta.")

    reactor.stop()


class PAKEProxyProtocol(protocol.Protocol):
    def __init__(self):
        self.buffer = None
        self.proxy_to_server_protocol = None

        self.initialReceive = False
        self.betaReceive = False

    def connectionMade(self):
        proxy_to_server_factory = protocol.ClientFactory()
        proxy_to_server_factory.protocol = ProxyToTrustedServerProtocol
        proxy_to_server_factory.server = self

        #reactor.connectTCP(public.TRUSTED_SERVER_IP, public.TRUSTED_SERVER_PORT, proxy_to_server_factory)

        #mitm
        reactor.connectTCP(public.MITM_IP, public.MITM_AS_S_SERVER_PORT, proxy_to_server_factory)

    def dataReceived(self, data):
        if not self.initialReceive:
            mess = receiveConnectRequest(data)
            if self.proxy_to_server_protocol:
                self.proxy_to_server_protocol.write(mess)
            else:
                self.buffer = mess
            self.initialReceive = True
        elif not self.betaReceive:
            receiveBeta(data)
            self.betaReceive = True

    def write(self, data):
        self.transport.write(data)


class ProxyToTrustedServerProtocol(protocol.Protocol):
    def connectionMade(self):
        self.factory.server.proxy_to_server_protocol = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''

        self.serverResponseReceive = False

    def dataReceived(self, data):
        if not self.serverResponseReceive:
            self.factory.server.write(receiveTrustedServerResponse(data))
            self.serverResponseReceive = True

    def write(self, data):
        if data:
            self.transport.write(data)


def _noop(data):
    return data

FORMAT_FN = _noop

factory = protocol.ServerFactory()
factory.protocol = PAKEProxyProtocol
print('Starting client B [*]: id = ', public.B_identifier)
print('Starting client B [*]: ip = ', public.B_CLIENT_IP)
print('Starting client B [*]: port = ', public.B_CLIENT_PORT)
print('Starting client B [*]: listening')
print('Connection public parameters [*]: q = ', public.q)
print('Connection public parameters [*]: g = ', public.g)
print('Connection public parameters [*]: M = ', public.M)
print('Connection public parameters [*]: N = ', public.N, '\n')
reactor.listenTCP(public.B_CLIENT_PORT, factory)
reactor.run()
