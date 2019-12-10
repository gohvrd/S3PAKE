from twisted.internet import protocol, reactor
from random import seed, randint
from struct import pack, unpack
import public

pwMitm = 2
SK = None

g_power_xz = None
v = None
w = None

def receiveConnectRequest(message):
    global y

    A, X = unpack('hxq', message)

    seed()
    v = randint(1, public.q - 1)
    w = randint(1, public.q - 1)
    print('MITM paramteters [*]: v = ', v)
    print('MITM paramteters [*]: w = ', w)
    V = public.g ** v * public.N ** pwMitm
    W = public.g ** w * public.M ** pwMitm
    print('MITM paramteters [*]: V = ', V)
    print('MITM paramteters [*]: W = ', W, '\n')

    return pack('hxq', A, W), message + pack('hxq', public.C_identifier, V)

def receiveTrustedServerResponse(response):
    global y
    global g_power_xz

    S_X, S_Y = unpack('qxq', response)
    print('S paramteters (received) [*]: S_X = ', S_X)
    print('S paramteters (received) [*]: S_Y = ', S_Y)
    g_power_xz = int(S_X / public.G((public.B_identifier, public.S_identifier, public.g ** y)) ** pwB)
    print('B calculates [*]: g^(xz) = ', g_power_xz)
    alpha = int(public.G((public.A_identifier, public.B_identifier, g_power_xz ** y)))
    print('B calculates [*]: alpha = ', alpha)

    return pack('qxq', S_Y, alpha)

def receiveBeta(beta):
    global SK

    recv_beta = unpack('q', beta)[0]
    print('A paramteters (received) [*]: beta = ', recv_beta)
    if recv_beta == int(public.G((public.B_identifier, public.A_identifier, g_power_xz ** y))):
        SK = public.H((public.A_identifier, public.B_identifier, g_power_xz ** y))
        print("B calculates [$COMPLETE$]: session key = ", SK)
    else:
        print("Error [!]: Wrong beta.")

    reactor.stop()


class ListenAProtocol(protocol.Protocol):
    def __init__(self):
        self.connectBFactory = protocol.ClientFactory()
        self.connectBFactory.protocol = ConnectBProtocol
        self.connectBFactory.listner = self
        self.connectBObject = None

        self.connectSFactory = protocol.ClientFactory()
        self.connectSFactory.listner = self
        self.connectSObject = None

        reactor.connectTCP(public.B_CLIENT_IP, public.B_CLIENT_PORT, self.connectBFactory)
        reactor.connectTCP(public.TRUSTED_SERVER_IP, public.TRUSTED_SERVER_PORT, self.connectSFactory)

    def connectionMade(self):
        print('MITM status [*]: client connected.')

    def dataReceived(self, data):
        messForB, messForS = receiveConnectRequest(data)

        self.connectBObject.write(messForB)
        self.connectSObject.write(messForS)

    def write(self, data):
        self.transport.write(data)


class ConnectSProtocol(protocol.Protocol):
    def __init__(self):
        self.factory.listner.connectSObject = self

    def connectionMade(self):
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


class ConnectBProtocol(protocol.Protocol):
    def __init__(self):
        self.factory.listner.connectBObject = self

    def connectionMade(self):
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


serverFactory = protocol.ServerFactory()
serverFactory.protocol = ListenAProtocol

print('Starting MITM [*]: id = ', public.B_identifier)
print('Starting MITM [*]: ip = ', public.B_CLIENT_IP)
print('Starting MITM [*]: port = ', public.B_CLIENT_PORT)
print('Starting MITM [*]: listening')
print('Connection public parameters [*]: q = ', public.q)
print('Connection public parameters [*]: g = ', public.g)
print('Connection public parameters [*]: M = ', public.M)
print('Connection public parameters [*]: N = ', public.N, '\n')
reactor.listenTCP(public.C_CLIENT_PORT, serverFactory)
reactor.run()