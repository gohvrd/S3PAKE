from twisted.internet import reactor, protocol

from random import seed, randint
from struct import pack, unpack
import xml.etree.ElementTree as xml
import public

settings = {
    "pw": None,
    "id": None,
    "q": None,
    "g": None,
    "M": None,
    "N": None,
}

SK = None

g_power_yz = None
x = None

def connectionInitializationMessage():
    global x

    seed()
    x = randint(1, public.q - 1)
    print('A action [*]: choosing random number x from Zp')
    print('A paramteters [*]: x = ', x)
    X = public.g ** x * public.M ** pw
    print('A action [*]: calculating X')
    print('A paramteters [*]: X = ', X)

    return pack('hxq', public.A_identifier, X)

def betaMessage():
    return int(public.G((public.B_identifier, public.A_identifier, g_power_yz ** x)))

def responseMessageHandler(message):
    global x
    global g_power_yz
    global SK

    S_Y, alpha = unpack('qxq', message)
    print('A action [*]: receiving S_Y||alpha from B')
    print('S paramteters (received) [*]: S_Y = ', S_Y)
    print('B paramteters (received) [*]: alpha = ', alpha, '\n')
    g_power_yz = int(S_Y / (public.G((public.A_identifier, public.S_identifier, public.g ** x)) ** pw))
    print('A calculates [*]: g^(yz) = ', g_power_yz)

    test_alpha = int(public.G((public.A_identifier, public.B_identifier, g_power_yz ** x)))
    
    print('A action [*]: independently calculate the alpha\' and compare it with the alpha')

    if alpha == test_alpha:
        print('A action [*]: alpha\' = alpha')
        SK = public.H((public.A_identifier, public.B_identifier, g_power_yz ** x))
        return betaMessage()

    print('A action [*]: alpha\' != alpha')

    return None

class PAKEClient(protocol.Protocol):
    def connectionMade(self):
        self.transport.write(connectionInitializationMessage())
        print('A action [*]: sending A||X to B\n')
 
    def dataReceived(self, data):
        beta = responseMessageHandler(data)

        if beta is not None:
            print('\nA calculates [*]: beta = ', beta)
            print('A action [*]: sending beta to B\n')

            message = pack('q', beta)
            self.transport.write(message)
            print("A calculates [$COMPLETE$]: session key = ", SK)

            self.transport.loseConnection()
        else:
            print("Error [!]: Wrong alpha.")
            self.transport.loseConnection()

    def connectionLost(self, reason):
        pass


class PAKEFactory(protocol.ClientFactory):
    protocol = PAKEClient

    def clientConnectionFailed(self, connector, reason):
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        reactor.stop()


class ClientSettingsManager():
    def __init__(self):
        self.filename = 'client_settings.xml'

    def setSettings(self, inSettings: dict):
        global settings

        if type(inSettings) is not 'dict':
            print("Передавать настройки можно только в словаре")
            return

        for key in settings.keys():
            newVal = inSettings.get(key)
            
            if newVal is not None:
                settings[key] = newVal

    def createSettingsFile(self):
        root = xml.Element('settings')

        private = xml.Element('private')
        public = xml.Element('public')

        root.append(private)
        root.append(public)

        pw = xml.SubElement(private, 'pw')
        pw.text = 'test'
        xml.SubElement(public, 'id')
        xml.SubElement(public, 'q')
        xml.SubElement(public, 'g')
        xml.SubElement(public, 'M')

        tree = xml.ElementTree(root)
        tree.write(self.filename)        


    def getClientSettings(self):
        global settings

        try:
            self.clSettings = xml.ElementTree(file=self.filename)
        except IOError:
            self.createSettingsFile()
            self.clSettings = xml.ElementTree(file=self.filename)

        settingsXML = self.clSettings.getroot()

        for settingsType in settingsXML:
            for parametr in settingsType:
                settings[parametr.tag] = parametr.text


def main():
    global settings

    print('Starting client A [*]: id = ', public.A_identifier)
    print('Starting client A [*]: ip = ', public.A_CLIENT_IP)
    print('Starting client A [*]: connecting')
    print('Connection public parameters [*]: q = ', public.q)
    print('Connection public parameters [*]: g = ', public.g)
    print('Connection public parameters [*]: M = ', public.M)
    print('Connection public parameters [*]: N = ', public.N, '\n')
    csm = ClientSettingsManager()
    print(settings)
    csm.getClientSettings()
    print(settings)
    csm.setSettings([1, 2])
    print(settings)
    
    #f = PAKEFactory()
    #reactor.connectTCP(public.B_CLIENT_IP, public.B_CLIENT_PORT, f)

    #mitm
    #reactor.connectTCP(public.MITM_IP, public.MITM_AS_B_CLIENT_PORT, f)
    #reactor.run()


if __name__ == '__main__':
    main()
