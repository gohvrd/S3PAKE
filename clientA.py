from twisted.internet import reactor, protocol

from random import seed, randint
from struct import pack, unpack
from optparse import OptionParser
import xml.etree.ElementTree as xml
import xml.etree as etree
import public

settings = {
    'ip': None,
    'port': None,
    'pw': None,
    'id': None,
    'q': None,
    'g': None,
    'M': None,
    'N': None,
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

    def checkOptionName(self, optionName, inNames: list):
        
        for name in inNames:
            if optionName == name:
                return True

        return False

    def createSettingsFile(self):
        root = xml.Element('settings')

        network = xml.Element('network')
        private = xml.Element('private')
        public = xml.Element('public')

        root.append(network)
        root.append(private)
        root.append(public)

        xml.SubElement(network, 'ip')
        xml.SubElement(network, 'port')

        xml.SubElement(private, 'pw')        

        xml.SubElement(public, 'id')
        xml.SubElement(public, 'q')
        xml.SubElement(public, 'g')
        xml.SubElement(public, 'M')

        tree = xml.ElementTree(root)
        tree.write(self.filename)   

    def setSettings(self, inSettings: dict):
        global settings

        if type(inSettings) is not dict:
            print("Передавать настройки можно только в словаре, передан: %s" % type(inSettings))
            return

        try:
            tree = xml.ElementTree(file=self.filename)
        except IOError:
            self.createSettingsFile()
            tree = xml.ElementTree(file=self.filename)

        root = tree.getroot()

        for settingsType in root:
            for option in settingsType:
                if self.checkOptionName(option.tag, inSettings.keys()):
                    option.text = str(inSettings.get(option.tag))

        tree = xml.ElementTree(root)
        tree.write(self.filename)
    
    def getSettings(self):
        global settings

        try:
            clSettings = xml.ElementTree(file=self.filename)
        except IOError:
            self.createSettingsFile()
            clSettings = xml.ElementTree(file=self.filename)

        settingsXML = clSettings.getroot()

        for settingsType in settingsXML:
            for parametr in settingsType:
                settings[parametr.tag] = parametr.text

    def checkSettingsFile(self):
        try:
            tree = xml.ElementTree(file=self.filename)
        except IOError:
            print("Создайте файл перед проверкой корректности его формата")
            return
        
        root = tree.getroot()

        trueTypeNames = ['network', 'private', 'public']
        trueOptionNames = [
            ['ip', 'port'], 
            ['pw'], 
            ['id', 'q', 'g', 'M']]

        settingsType = enumerate(root)
        
        for i, typeName in settingsType:
            if typeName.tag != trueTypeNames[i]:
                return False

            for j, optionName in enumerate(typeName):
                if optionName.tag != trueOptionNames[i][j]:
                    return False

        return True

def addSettings(options):
    settingsDict = {}

    if options['ip'] is not None:
        settingsDict['ip'] = options['ip']

    if options['port'] is not None:
        settingsDict['port'] = options['port']

    if options['pw'] is not None:
        settingsDict['pw'] = options['pw']

    if options['q'] is not None:
        settingsDict['q'] = options['q']

    if options['g'] is not None:
        settingsDict['g'] = options['g']

    if options['M'] is not None:
        settingsDict['M'] = options['M']

    return settingsDict

def main():
    global settings

    optionParser = OptionParser()
    
    optionParser.add_option('-a', '--ip', action='store')
    optionParser.add_option('-p', '--port', action='store')
    optionParser.add_option('-w', '--pw', action='store')
    optionParser.add_option('-q', '--q', action='store')
    optionParser.add_option('-g', '--g', action='store')
    optionParser.add_option('-M', '--M', action='store')

    (options, arguments) = optionParser.parse_args()

    csm = ClientSettingsManager()

    if not csm.checkSettingsFile():
        print("Поврежден файл с настройками клиента")
        return

    settingsDict = addSettings(options.__dict__)
    
    if settingsDict != {}:
        csm.setSettings(settingsDict)                

    csm.getSettings()

    print('Starting client A [*]: id = ', settings['id'])
    print('Starting client A [*]: ip = ', settings['ip'])
    print('Starting client A [*]: connecting')
    print('Connection public parameters [*]: q = ', settings['q'])
    print('Connection public parameters [*]: g = ', settings['g'])
    print('Connection public parameters [*]: M = ', settings['M'], '\n')
        
    #f = PAKEFactory()
    #reactor.connectTCP(public.B_CLIENT_IP, public.B_CLIENT_PORT, f)

    #mitm
    #reactor.connectTCP(public.MITM_IP, public.MITM_AS_B_CLIENT_PORT, f)
    #reactor.run()


if __name__ == '__main__':
    main()
