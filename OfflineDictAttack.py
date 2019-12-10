from twisted.internet import reactor, protocol

from random import seed, randint
from struct import pack, unpack
import public

pwAttackerB = 3

x = None
y = None

def connectionInitializationMessage():
    global x, y, pwAttackerB

    seed()
    x = randint(1, public.q - 1)
    y = randint(1, public.q - 1)

    print('Attacker paramteters [*]: x = ', x)
    print('Attacker paramteters [*]: y = ', y)
    X = public.M ** x
    Y = public.M ** y * public.N ** pwAttackerB
    print('Attacker paramteters [*]: X = ', X)
    print('Attacker paramteters [*]: Y = ', Y, '\n')

    return pack('hxq', public.A_identifier, X) + pack('hxq', public.B_identifier, Y)

def receiveTrustedServerResponse(response):
    global y, pwAttackerB

    S_X, S_Y = unpack('qxq', response)
    print('S paramteters (received) [*]: S_X = ', S_X)
    print('S paramteters (received) [*]: S_Y = ', S_Y)

    K = int((int(S_X / (public.G((public.B_identifier, public.S_identifier, public.M ** y)) ** pwAttackerB))) ** y)
    print('Attacker calculates [*]: K = ', K)

    return K, S_Y

def guessPasswordA(K, S_Y):
    global x

    pwA = 0
    calculatedK = None

    while (K != calculatedK and pwA - 1 < x):
        pwA += 1

        calculatedK = int((int(S_Y / (public.G((public.A_identifier, public.S_identifier, public.M ** (x - pwA))) ** pwA))) ** (x - pwA))

        print('\n----------------------------------------\n')

        print('Attacker calculates [*]: K\' = ', calculatedK)
        print('Attacker try password [*]: guessed password = ', pwA)

    print('\n----------------------------------------\n')
    print('Attacker guessed password [$COMPLETE$]: pwA = ', pwA)


class Attacker(protocol.Protocol):

    def connectionMade(self):
        self.transport.write(connectionInitializationMessage())

    def dataReceived(self, data):
        K, S_Y = receiveTrustedServerResponse(data)

        guessPasswordA(K, S_Y)

        self.transport.loseConnection()

    def connectionLost(self, reason):
        pass


class AttackerFactory(protocol.ClientFactory):
    protocol = Attacker

    def clientConnectionFailed(self, connector, reason):
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        reactor.stop()


# this connects the protocol to a server running on port 8000
def main():
    attackerFactory = AttackerFactory()

    print('Starting attacker B [*]: id = ', public.B_identifier)
    print('Starting attacker B [*]: ip = ', public.B_CLIENT_IP)
    print('Starting attacker B [*]: connecting')
    print('Connection public parameters [*]: q = ', public.q)
    print('Connection public parameters [*]: g = ', public.g)
    print('Connection public parameters [*]: M = ', public.M)
    print('Connection public parameters [*]: N = ', public.N, '\n')

    reactor.connectTCP(public.TRUSTED_SERVER_IP, public.TRUSTED_SERVER_PORT,
                       attackerFactory)
    reactor.run()


# this only runs if the module was *not* imported
if __name__ == '__main__':
    main()