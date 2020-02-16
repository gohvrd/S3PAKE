from twisted.internet import protocol, reactor
from random import seed, randint
from struct import pack, unpack
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
    print('Attacker action [*]: choosing random y from Zp')
    print('Attacker parameters [*]: y = ', y)

    print('\nAttacker action [*]: receiving A||X from A')

    A, X = unpack('hxq', message)

    print('A parameters [*]: A = ', A)
    print('A parameters [*]: X = ', X, '\n')

    random_S_Y = randint(1, 100000)
    random_alpha = randint(1, 100000)
    print('Attacker parameters [*]: random S_Y = ', random_S_Y)
    print('Attacker parameters [*]: random alpha = ', random_alpha, '\n')

    print('Attacker action [*]: sending random S_Y||alpha to A (the correctness of the parameters is not important)')

    return pack('qxq', random_S_Y, random_alpha), A, X

def passwordGuesseResult(response):
    global y, guessed, responseReceived, g_x

    print('Attacker action [*]: receiving S_X||S_Y from S')

    S_X, S_Y = unpack('qxq', response)
    print('S parameters (received) [*]: S_X = ', S_X)
    print('S parameters (received) [*]: S_Y = ', S_Y)

    print('\nAttacker action [*]: checking a guess')

    g_power_xz = int(S_X / public.G((public.B_identifier, public.S_identifier, public.g ** (g_x * y))) ** pwB)
    print('Attacker calculates [*]: g^(xz) = ', g_power_xz)

    g_power_xzy = int(S_Y / public.G((A, public.S_identifier, public.g ** g_x)) ** g_pwA)
    print('Attacker calculates [*]: g^(x\'zy) = ', g_power_xzy, '\n')

    if (g_power_xz ** y == g_power_xzy):
        print('Attacker action [*]: g^(xz) = g^(x\'zy)')
        print('Attacker action [*]: the guess is correct')
        guessed = True
        return True

    print('Attacker action [*]: g^(xz) != g^(x\'zy)')
    print('Attacker action [*]: the guess isn\'t correct')

    responseReceived = True

    return False


def tryPassword(pwA):
    global y, g_x

    print('\n----------------------------------------\n')

    print('Attacker action [*]: trying password pwA\' = ', pwA)

    g_power_g_x = int(X / public.M ** pwA)
    g_x = int(log(g_power_g_x, public.g))

    print('Attacker calculates [*]: g^x = ', g_x)

    Y = (g_power_g_x ** y) * public.N ** pwB
    print('Attacker calculates [*]: Y = ', Y, '\n')

    message = pack('hxq', A, X) + pack('hxq', public.B_identifier, Y)

    print('Attacker action [*]: sending A||X||B||Y to S\n')

    return message

class TCPProxyProtocol(protocol.Protocol):
    def __init__(self):
        self.buffer = None
        self.proxyToServerProtocol = None

        self.initialReceive = False
        self.betaReceive = False

    def connectionMade(self):
        proxyToServerFactory = protocol.ClientFactory()
        proxyToServerFactory.protocol = ProxyToServerProtocol
        proxyToServerFactory.server = self

        reactor.connectTCP(public.TRUSTED_SERVER_IP, public.TRUSTED_SERVER_PORT,
                           proxyToServerFactory)

    def dataReceived(self, data):
        global A, X
        
        if not self.initialReceive:
            messForA, A, X = receiveConnectRequest(data)

            message = tryPassword(g_pwA)
            
            if self.proxyToServerProtocol:
                self.proxyToServerProtocol.write(message)
            else:
                self.buffer = message

            self.initialReceive = True

            self.writeToClient(messForA)

    def writeToClient(self, data):
        self.transport.write(data)


class ProxyToServerProtocol(protocol.Protocol):
    def connectionMade(self):
        self.factory.server.proxyToServerProtocol = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''

        self.serverResponseReceive = False

    def connectionLost(self, reason):
        pass

    def dataReceived(self, data):
        global g_pwA

        if not passwordGuesseResult(data):
            g_pwA += 1
            message = tryPassword(g_pwA)
            self.write(message)
        else:
            print('\n----------------------------------------\n')
            print('Attacker guessed password [$COMPLETE$] pwA = ', g_pwA, '\n')
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
