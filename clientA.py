from twisted.internet import reactor, protocol

from random import seed, randint
from struct import pack, unpack
import public

pwA = 2
SK = None

g_power_yz = None
x = None

def connectionInitializationMessage():
    global x

    seed()
    x = randint(1, public.q - 1)
    print('A action [*]: choosing random number x from Zp')
    print('A paramteters [*]: x = ', x)
    X = public.g ** x * public.M ** pwA
    print('A action [*]: calculating X')
    print('A paramteters [*]: X = ', X, '\n')

    return pack('hxq', public.A_identifier, X)

def betaMessage():
    return int(public.G((public.B_identifier, public.A_identifier, g_power_yz ** x)))

def responseMessageHandler(message):
    global x
    global g_power_yz
    global SK

    S_Y, alpha = unpack('qxq', message)
    print('S paramteters (received) [*]: S_Y = ', S_Y)
    print('B paramteters (received) [*]: alpha = ', alpha)
    g_power_yz = int(S_Y / (public.G((public.A_identifier, public.S_identifier, public.g ** x)) ** pwA))
    print('A calculates [*]: g^(yz) = ', g_power_yz)

    test_alpha = int(public.G((public.A_identifier, public.B_identifier, g_power_yz ** x)))

    if alpha == test_alpha:
        SK = public.H((public.A_identifier, public.B_identifier, g_power_yz ** x))
        return betaMessage()

    return None

class EchoClient(protocol.Protocol):
    def connectionMade(self):
        self.transport.write(connectionInitializationMessage())
        print('A action [*]: sending A||X to B')
 
    def dataReceived(self, data):
        #print('received response from B')
        beta = responseMessageHandler(data)
        print('A calculates [*]: beta = ', beta)

        if beta is not None:
            message = pack('q', beta)
            self.transport.write(message)
            print("A calculates [$COMPLETE$]: session key = ", SK)

            self.transport.loseConnection()
        else:
            print("Error [!]: Wrong alpha.")
            self.transport.loseConnection()


    def connectionLost(self, reason):
        pass
        #print("connection lost")


class EchoFactory(protocol.ClientFactory):
    protocol = EchoClient

    def clientConnectionFailed(self, connector, reason):
        #print("Connection failed - goodbye!")
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        #print("Connection lost - goodbye!")
        reactor.stop()


# this connects the protocol to a server running on port 8000
def main():
    print('Starting client A [*]: id = ', public.A_identifier)
    print('Starting client A [*]: ip = ', public.A_CLIENT_IP)
    print('Starting client A [*]: connecting')
    print('Connection public parameters [*]: q = ', public.q)
    print('Connection public parameters [*]: g = ', public.g)
    print('Connection public parameters [*]: M = ', public.M)
    print('Connection public parameters [*]: N = ', public.N, '\n')
    f = EchoFactory()
    #reactor.connectTCP(public.B_CLIENT_IP, public.B_CLIENT_PORT, f)

    #mitm
    reactor.connectTCP(public.MITM_IP, public.MITM_AS_B_CLIENT_PORT, f)
    reactor.run()


# this only runs if the module was *not* imported
if __name__ == '__main__':
    main()
