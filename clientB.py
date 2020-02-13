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
    print('B action [*]: receiving A||X from A')
    y = randint(1, public.q - 1)
    print('B action [*]: choosing random number y from Zp') 
    print('B paramteters [*]: y = ', y)
    Y = public.g ** y * public.N ** pwB
    print('B action [*]: calculating Y') 
    print('B paramteters [*]: Y = ', Y, '\n')

    print('B action [*]: sending A||X||B||Y to S'

    return message + pack('hxq', public.B_identifier, Y)

def receiveTrustedServerResponse(response):
    global y
    global g_power_xz

    S_X, S_Y = unpack('qxq', response)
    print('B action [*]: receiving S_X||S_Y from S')
    print('S paramteters (received) [*]: S_X = ', S_X)
    print('S paramteters (received) [*]: S_Y = ', S_Y)
    g_power_xz = int(S_X / public.G((public.B_identifier, public.S_identifier, public.g ** y)) ** pwB)
    print('B calculates [*]: g^(xz) = ', g_power_xz)
    alpha = int(public.G((public.A_identifier, public.B_identifier, g_power_xz ** y)))
    print('B calculates [*]: alpha = ', alpha)

    print('B action [*]: sending S_Y||alpha to A')

    return pack('qxq', S_Y, alpha)

def receiveBeta(beta):
    global SK

    recv_beta = unpack('q', beta)[0]
    print('B action [*]: receiving beta from A'
    print('A paramteters (received) [*]: beta = ', recv_beta)
    print('B action [*]: independently calculate the value and compare it with the value')
    if recv_beta == int(public.G((public.B_identifier, public.A_identifier, g_power_xz ** y))):
        SK = public.H((public.A_identifier, public.B_identifier, g_power_xz ** y))
        print("B calculates [$COMPLETE$]: session key = ", SK)
    else:
        print("Error [!]: Wrong beta.")

    reactor.stop()


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
        self.proxy_to_server_protocol = None

        self.initialReceive = False
        self.betaReceive = False

    def connectionMade(self):
        """
        Called by twisted when a client connects to the
        proxy. Makes an connection from the proxy to the
        server to complete the chain.
        """
        #print("Connection made from CLIENT => PROXY")
        proxy_to_server_factory = protocol.ClientFactory()
        proxy_to_server_factory.protocol = ProxyToServerProtocol
        proxy_to_server_factory.server = self

        #reactor.connectTCP(public.TRUSTED_SERVER_IP, public.TRUSTED_SERVER_PORT, proxy_to_server_factory)

        #mitm
        reactor.connectTCP(public.MITM_IP, public.MITM_AS_S_SERVER_PORT, proxy_to_server_factory)

    def dataReceived(self, data):
        """
        Called by twisted when the proxy receives data from
        the client. Sends the data on to the server.

        CLIENT ===> PROXY ===> DST
        """
        if not self.initialReceive:
            mess = receiveConnectRequest(data)
            if self.proxy_to_server_protocol:
                self.proxy_to_server_protocol.write(mess)
            else:
                self.buffer = mess
            #print('connect request received')
            self.initialReceive = True
        elif not self.betaReceive:
            receiveBeta(data)
            self.betaReceive = True

    def write(self, data):
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
        self.factory.server.proxy_to_server_protocol = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''

        self.serverResponseReceive = False

    def dataReceived(self, data):
        """
        Called by twisted when the proxy receives data
        from the server. Sends the data on to to the client.

        DST ===> PROXY ===> CLIENT
        """
        if not self.serverResponseReceive:
            #print('received server response')
            self.factory.server.write(receiveTrustedServerResponse(data))
            self.serverResponseReceive = True

    def write(self, data):
        if data:
            self.transport.write(data)


def _noop(data):
    return data

FORMAT_FN = _noop

factory1 = protocol.ServerFactory()
factory1.protocol = TCPProxyProtocol
print('Starting client B [*]: id = ', public.B_identifier)
print('Starting client B [*]: ip = ', public.B_CLIENT_IP)
print('Starting client B [*]: port = ', public.B_CLIENT_PORT)
print('Starting client B [*]: listening')
print('Connection public parameters [*]: q = ', public.q)
print('Connection public parameters [*]: g = ', public.g)
print('Connection public parameters [*]: M = ', public.M)
print('Connection public parameters [*]: N = ', public.N, '\n')
reactor.listenTCP(public.B_CLIENT_PORT, factory1)
reactor.run()
