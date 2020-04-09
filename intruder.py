from twisted.internet import reactor, protocol
from random import seed, randint
from struct import pack, unpack
from optparse import OptionParser
import re
import xml.etree.ElementTree as xml

settings = {
    'port': None,
    'pw': None,
    'id': None,
    'q': None,
    'g': None,
    'M': None,
    'N': None,
    'aid':None,
    'bid':None,
    'sid':None
}

def G(values: tuple):
    return (int((values[0] + int(values[1] / 2)) / 2) + values[2]) % 10 + 1


class IntruderClientFactory(protocol.ClientFactory):
    def __init__(self, inProtocol):
        protocol = inProtocol

    def clientConnectionFailed(self, connector, reason):
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        reactor.stop()


class OFFDA(protocol.Protocol):
    def __init__(self):
        seed()
        self.x = randint(1, settings['q'] - 1)
        self.y = randint(1, settings['q'] - 1)

    def connectionMade(self):
        self.transport.write(self.sendClientRequest())

    def dataReceived(self, data):
        K, S_Y = self.receiveServerResponse(data)

        self.guessPasswordA(K, S_Y)

        self.transport.loseConnection()

    def sendClientRequest(self):              
        print('Attacker action [*]: choosing random number x and y from Zp')
        
        print('Attacker paramteters [*]: x = ', self.x)
        print('Attacker paramteters [*]: y = ', self.y)
        X = settings['M'] ** self.x
        Y = settings['M'] ** self.y * settings['N'] ** settings['pw']

        print('Attacker action [*]: calculating specific X and Y')

        print('Attacker paramteters [*]: X = ', X)
        print('Attacker paramteters [*]: Y = ', Y)

        print('Attacker action [*]: sending A||X||B||Y to S\n')

        return pack('hxq', settings['aid'], X) + pack('hxq', settings['bid'], Y)

    def receiveServerResponse(self, response):
        S_X, S_Y = unpack('qxq', response)
        print('Attacker action [*]: receiving S_X||S_Y from S')
        print('S paramteters (received) [*]: S_X = ', S_X)
        print('S paramteters (received) [*]: S_Y = ', S_Y, '\n')

        print('Attacker action [*]: start guessing the password\n')

        K = int((int(S_X / (G((settings['bid'], settings['sid'], settings['M'] ** self.y)) ** settings['pw']))) ** self.y)
        print('Attacker calculates [*]: K = ', K)

        return K, S_Y

    def guessPasswordA(self, K, S_Y):
        pwA = 0
        cK = None

        while (K != cK and pwA - 1 < self.x):
            pwA += 1

            cK = int((int(S_Y / (G((settings['aid'], settings['sid'], settings['M'] ** (self.x - pwA))) ** pwA))) ** (self.x - pwA))

            print('\n----------------------------------------\n')

            print('Attacker calculates [*]: K\' = ', cK)
            print('Attacker try password [*]: guessed password = ', pwA)

        print('\n----------------------------------------\n')
        print('Attacker guessed password [$COMPLETE$]: pwA = ', pwA)


class UONDAlistner(protocol.Protocol):
    def __init__(self):
        self.buffer = None
        self.proxyToServerProtocol = None

        self.initialReceive = False
        self.betaReceive = False

    def connectionMade(self):
        proxyToServerFactory = protocol.ClientFactory()
        proxyToServerFactory.protocol = UONDAproxy
        proxyToServerFactory.server = self

        reactor.connectTCP(public.TRUSTED_SERVER_IP, public.TRUSTED_SERVER_PORT,
                           proxyToServerFactory)

    def dataReceived(self, data):
        global A, X
        
        if not self.initialReceive:
            messForA, A, X = self.receiveConnectRequest(data)

            message = self.tryPassword(g_pwA)
            
            if self.proxyToServerProtocol:
                self.proxyToServerProtocol.write(message)
            else:
                self.buffer = message

            self.initialReceive = True

            self.writeToClient(messForA)

    def writeToClient(self, data):
        self.transport.write(data)

    def receiveConnectRequest(self, message):
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

    def tryPassword(self, pwA):
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


class UONDAproxy(protocol.Protocol):
    def connectionMade(self):
        self.factory.server.proxyToServerProtocol = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''

        self.serverResponseReceive = False

    def connectionLost(self, reason):
        pass

    def dataReceived(self, data):
        global g_pwA

        if not self.passwordGuesseResult(data):
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


class MITM(protocol.Protocol):
    pass


def main():
    optionParser = OptionParser()

    optionParser.add_option('-m', '--mitm', action='store_true')
    optionParser.add_option('-o', '--offline-dict', action='store_true')
    optionParser.add_option('-u', '--undetectable-online-dict', action='store_true')

    reactor.run()


if __name__ == '__main__':
    main()