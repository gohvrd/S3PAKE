from twisted.internet import protocol, reactor
from random import seed, randint
from struct import pack, unpack
import public

pwMitm = 2

connected = False
v = None
w = None
g_power_xz = None
g_power_yz = None

SK1 = None
SK2 = None

class connectionToTSProtocol(protocol.Protocol):
    def __init__(self):
        pass

    def connectionMade(self):
        self.factory.main.connectionToTS = self

        if self.factory.main.forWaitBuffer != '':
            self.write(self.factory.main.forWaitBuffer)
            self.factory.main.forWaitBuffer = ''

    def dataReceived(self, data):
        global v, g_power_xz

        S_X, S_V = unpack('qxq', data)
        print('MITM action [*SESSION-1*]: receiving S_X||S_V from S')

        print('S paramteters (received) [*SESSION-1*]: S_X = ', S_X)
        print('S paramteters (received) [*SESSION-1*]: S_V = ', S_V, '\n')
        g_power_xz = int(S_X / public.G((public.MITM_identifier, public.S_identifier, public.g ** v)) ** pwMitm)
        print('MITM calculates [*SESSION-1*]: g^(xz) = ', g_power_xz)
        alpha = int(public.G((public.A_identifier, public.B_identifier, g_power_xz ** v)))
        print('MITM calculates [*SESSION-1*]: alpha = ', alpha)

        print('MITM action [*SESSION-1*]: sending S_V||alpha to A\n')
     
        self.factory.main.write(pack('qxq', S_V, alpha))

    def write(self, data):
        self.transport.write(data)


class FakeBClientProtocol(protocol.Protocol):
    def __init__(self):
        self.connectionToTS = None
        self.forWaitBuffer = ''

        connectionToTSFactory = protocol.ClientFactory()
        connectionToTSFactory.protocol = connectionToTSProtocol
        connectionToTSFactory.main = self

        reactor.connectTCP(public.TRUSTED_SERVER_IP, public.TRUSTED_SERVER_PORT,
                           connectionToTSFactory)

    def connectionMade(self):
        pass

    def dataReceived(self, data):
        global v, g_power_xz, SK1, connected

        if not connected:
            seed()
            v = randint(1, public.q - 1)
            V = public.g ** v * public.N ** pwMitm
            print('MITM action [*SESSION-1*]: receiving A||X from A\n')
            
            print('MITM action [*SESSION-1*]: choosing randomg number v from Zp')
            print('MITM paramteters [*SESSION-1*]: v = ', v)
            print('MITM action [*SESSION-1*]: calculating V')
            print('MITM paramteters [*SESSION-1*]: V = ', V)

            print('MITM action [*SESSION-1*]: sending A||X||C||V to S\n')


            if self.connectionToTS is not None:
                self.connectionToTS.write(data + pack('hxq', public.MITM_identifier, V))
            else:
                self.forWaitBuffer = data + pack('hxq', public.MITM_identifier, V)

            connected = True
        else:
            beta = unpack('q', data)[0]
            print('MITM status [*SESSION-1*]: Client A alpha check was successful.')
            print('MITM status [*SESSION-1*]: Session key can be calculated.\n')
            print('MITM action [*SESSION-1*]: receiving beta from A')
            print('A paramteters (received) [*SESSION-1*]: beta = ', beta)
            print('MITM action [*SESSION-1*]: independently calculate the beta\' and compare it with the beta')

            if beta == int(public.G((public.B_identifier, public.A_identifier, g_power_xz ** v))):
                print('MITM action [*SESSION-1*]: beta\' = beta\n')
                SK1 = public.H((public.A_identifier, public.B_identifier, g_power_xz ** v))

                connectionToBFactory = protocol.ClientFactory()
                connectionToBFactory.protocol = FakeAClientProtocol

                reactor.connectTCP(public.B_CLIENT_IP, public.B_CLIENT_PORT,
                                   connectionToBFactory)
            else:
               print('MITM action [*SESSION-1*]: beta\' != beta')
               print("MITM Error [!SESSION-1!]: Wrong beta.\n")

    def write(self, data):
        self.transport.write(data)


class FakeAClientProtocol(protocol.Protocol):
    def connectionMade(self):
        global w

        seed()
        w = randint(1, public.q - 1)
        W = public.g ** w * public.M ** pwMitm
        print('MITM action [*SESSION-2*]: choosing random number w from Zp')
        print('MITM paramteters [*SESSION-2*]: w = ', w)
        print('MITM paramteters [*SESSION-2*]: W = ', W)
        print('MITM action [*SESSION-2*]: calculating W')

        print('MITM action [*SESSION-2*]: sending A||W to B\n')

        self.write(pack('hxq', public.A_identifier, W))

    def dataReceived(self, data):
        #C (client) <== B --- C (server) --- S
        global g_power_yz, w, SK1, SK2

        S_W, alpha = unpack('qxq', data)
        print('MITM action [*SESSION-2*]: receiving S_W||alpha from B')
        print('S paramteters (received) [*SESSION-2*]: S_W = ', S_W)
        print('B paramteters (received) [*SESSION-2*]: alpha = ', alpha, '\n')

        g_power_yz = int(S_W / (public.G((public.MITM_identifier, public.S_identifier, public.g ** w)) ** pwMitm))
        print('MITM calculates [*SESSION-2*]: g^(yz) = ', g_power_yz)

        test_alpha = int(public.G((public.A_identifier, public.B_identifier, g_power_yz ** w)))

        if alpha == test_alpha:
            print('MITM action [*SESSION-2*]: alpha\' = alpha')
            print('MITM status [*SESSION-2*]: MITM alpha check was successful.')
            print('MITM status [*SESSION-2*]: Session key can be calculated.\n')

            SK2 = public.H((public.A_identifier, public.B_identifier, g_power_yz ** w))

            beta = int(public.G((public.B_identifier, public.A_identifier, g_power_yz ** w)))
            print('MITM calculates [*SESSION-2*]: beta = ', beta)
            print('MITM action [*SESSION-2*]: sending beta to B\n')


            self.write(pack('q', beta))
            self.transport.loseConnection()

            print('MITM status [*]: Attack completed successfully.')
            print('MITM results [*A <--> MITM*]: SK = ', SK1)
            print('MITM results [*MITM <--> B*]: SK = ', SK2)
        else:
            print('MITM action [*SESSION-2*]: alpha\' != alpha')

    def write(self, data):
        self.transport.write(data)


class proxyToTSProtocol(protocol.Protocol):
    def __init__(self):
        pass

    def connectionMade(self):
        self.factory.main.connectionToTS = self

        if self.factory.main.forWaitBuffer != '':
            self.write(self.factory.main.forWaitBuffer)
            self.factory.main.forWaitBuffer = ''

        pass

    def dataReceived(self, data):
        self.factory.main.write(data)
        self.transport.loseConnection()

    def write(self, data):
        self.transport.write(data)


class FakeSServerProtocol(protocol.Protocol):
    def __init__(self):
        self.connectionToTS = None
        self.forWaitBuffer = ''

        connectionToTSFactory = protocol.ClientFactory()
        connectionToTSFactory.protocol = proxyToTSProtocol
        connectionToTSFactory.main = self

        reactor.connectTCP(public.TRUSTED_SERVER_IP, public.TRUSTED_SERVER_PORT,
                           connectionToTSFactory)

    def connectionMade(self):
        pass

    def dataReceived(self, data):
        A, W, B, Y = unpack('hxqhxq', data)

        if self.connectionToTS is not None:
            self.connectionToTS.write(pack('hxqhxq', public.MITM_identifier, W, B, Y))
        else:
            self.forWaitBuffer = pack('hxqhxq', public.MITM_identifier, W, B, Y)

        print('MITM status [*SESSION-2*]: Change message from A||W||B||Y to C||W||B||Y and send to TS.\n')

    def write(self, data):
        self.transport.write(data)

        print('MITM status [*SESSION-2*]: Proxy TS answer W\'||Y\' to B.\n')


fakeSServer = protocol.ServerFactory()
fakeSServer.protocol = FakeSServerProtocol

fakeBClient = protocol.ServerFactory()
fakeBClient.protocol = FakeBClientProtocol

print('Starting MITM [*]: id = ', public.MITM_identifier)
print('Starting MITM [*]: ip = ', public.MITM_IP)
print('Starting MITM [*]: portB, portS = ', public.MITM_AS_B_CLIENT_PORT, ', ', public.MITM_AS_S_SERVER_PORT)
print('Starting MITM [*]: listening')
print('Connection public parameters [*]: q = ', public.q)
print('Connection public parameters [*]: g = ', public.g)
print('Connection public parameters [*]: M = ', public.M)
print('Connection public parameters [*]: N = ', public.N, '\n')
reactor.listenTCP(public.MITM_AS_B_CLIENT_PORT, fakeBClient)
reactor.listenTCP(public.MITM_AS_S_SERVER_PORT, fakeSServer)
reactor.run()
