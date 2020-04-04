from twisted.internet import reactor, protocol

from random import seed, randint
from struct import pack, unpack
from optparse import OptionParser
import re
import xml.etree.ElementTree as xml
import public

settings = {
    'port': None,
    'pw': None,
    'id': None,
    'q': None,
    'g': None,
    'M': None,
    'N': None,
    'sid': None, 
    'sip': None,
    'sport': None,
    'uid': None
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
    X = settings['g'] ** x * settings['M'] ** settings['pw']
    print('A action [*]: calculating X')
    print('A paramteters [*]: X = ', X)

    return pack('hxq', settings['id'], X)

def betaMessage():
    return int(public.G((settings['uid'], settings['id'], g_power_yz ** x)))

def responseMessageHandler(message):
    global x
    global g_power_yz
    global SK

    S_Y, alpha = unpack('qxq', message)
    print('A action [*]: receiving S_Y||alpha from B')
    print('S paramteters (received) [*]: S_Y = ', S_Y)
    print('B paramteters (received) [*]: alpha = ', alpha, '\n')
    g_power_yz = int(S_Y / (public.G((settings['id'], settings['sid'], settings['g'] ** x)) ** settings['pw']))
    print('A calculates [*]: g^(yz) = ', g_power_yz)

    test_alpha = int(public.G((settings['id'], settings['uid'], g_power_yz ** x)))
    
    print('A action [*]: independently calculate the alpha\' and compare it with the alpha')

    if alpha == test_alpha:
        print('A action [*]: alpha\' = alpha')
        SK = public.H((settings['id'], settings['uid'], g_power_yz ** x))
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

        try:
            open(self.filename, 'r')
        except IOError:
            self.createSettingsFile()      

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
        server = xml.Element('server')
        user = xml.Element('user')

        root.append(network)
        root.append(private)
        root.append(public)
        root.append(server)
        root.append(user)

        xml.SubElement(network, 'port')

        xml.SubElement(private, 'pw')        

        xml.SubElement(public, 'id')
        xml.SubElement(public, 'q')
        xml.SubElement(public, 'g')
        xml.SubElement(public, 'M')

        xml.SubElement(server, 'sid')
        xml.SubElement(server, 'sip')
        xml.SubElement(server, 'sport')

        xml.SubElement(user, 'uid')

        tree = xml.ElementTree(root)       
        
        try:
            tree.write(self.filename, xml_declaration=True)   
        except:
            print('Ошибка создания файла настроек')

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
        try:
            tree.write(self.filename)
        except:
            print('Ошибка добавления новых настроек')
    
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

        settings = self.convertTypeSettings(settings)

    def checkSettingsFile(self):
        try:
            tree = xml.ElementTree(file=self.filename)
        except IOError:
            print("Создайте файл перед проверкой корректности его формата")
            return
        
        root = tree.getroot()

        trueTypeNames = ['network', 'private', 'public', 'server', 'user']
        trueOptionNames = [
            ['port'], 
            ['pw'], 
            ['id', 'q', 'g', 'M'],
            ['sid', 'sip', 'sport'],
            ['uid']]

        settingsType = enumerate(root)
        
        for i, typeName in settingsType:
            if typeName.tag != trueTypeNames[i]:
                return False

            for j, optionName in enumerate(typeName):
                if optionName.tag != trueOptionNames[i][j]:
                    return False

        return True

    def generalCheckSettings(self, settings):
        if settings['q'] is None:
            return False
        elif settings['g'] is None:
            return False
        elif settings['id'] is None:
            return False
        elif settings['sid'] is None:
            return False
        elif settings['pw'] is None:
            return False

        return True

    def initiatorCheckSettings(self, settings):
        if self.generalCheckSettings(settings):
            if settings['M'] is None:
                return False
            elif settings['uid'] is None:
                return False
            
            return True
        
        return False

    def listnerCheckSettings(self, settings):
        if self.generalCheckSettings(settings):
            if settings['N'] is None:
                return False
            elif settings['port'] is None:
                return False
            elif settings['sip'] is None:
                return False
            elif settings['sport'] is None:
                return False

            return True

        return False

    def addSettings(self, options):
        settingsDict = {}

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

        if options['N'] is not None:
            settingsDict['N'] = options['N']

        if options['sid'] is not None:
            settingsDict['sid'] = options['sid']

        if options['sip'] is not None:
            settingsDict['sip'] = options['sip']

        if options['sport'] is not None:
            settingsDict['sport'] = options['sport']

        if options['uid'] is not None:
            settingsDict['uid'] = options['uid']

        return settingsDict

    def convertTypeSettings(self, settings: dict):
        for key in settings.keys():
            if key.find('ip') == -1 and settings.get(key) is not None:
                settings[key] = int(settings.get(key))

        return settings


def connectionAddressParser(address):
    regexAddressValidation = r'^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)):(\d{1,5}){1}$'
    ip = None
    port = None

    result = re.search(regexAddressValidation, address)

    if result is not None:
        ip = result.group(1)
        port = int(result.group(2))

        if not port in range(0, 65536):
            print('Неверное значение порта')

        return (ip, port)

    return (None, None)

    print('Неверный формат ip-адреса. Ожидается: \"ip:port\"')
    return False

def main():
    global settings

    optionParser = OptionParser()
    
    optionParser.add_option('-p', '--port', action='store')
    optionParser.add_option('-w', '--pw', action='store')
    optionParser.add_option('-q', '--q', action='store')
    optionParser.add_option('-g', '--g', action='store')
    optionParser.add_option('-M', '--M', action='store')
    optionParser.add_option('-N', '--N', action='store')
    optionParser.add_option('-S', '--sid', action='store')
    optionParser.add_option('-i', '--sip', action='store')
    optionParser.add_option('-s', '--sport', action='store')
    optionParser.add_option('-u', '--uid', action='store')

    optionParser.add_option('-c', '--connect', action='store')
    optionParser.add_option('-l', '--listen', action='store_true')    

    (options, arguments) = optionParser.parse_args()

    csm = ClientSettingsManager()

    if not csm.checkSettingsFile():
        print("Поврежден файл с настройками клиента")
        return

    settingsDict = csm.addSettings(options.__dict__)
    
    if settingsDict != {}:
        csm.setSettings(settingsDict)                

    csm.getSettings()

    print('Starting client A [*]: id = ', settings['id'])
    print('Connection public parameters [*]: q = ', settings['q'])
    print('Connection public parameters [*]: g = ', settings['g'])
    print('Connection public parameters [*]: M = ', settings['M'], '\n')

    if options.__dict__['connect'] is not None:
        if options.__dict__['listen']:
            print('Одновременно можно выбрать только один режим работы')
            return

        if not csm.initiatorCheckSettings(settings):
            return

        ip, port = connectionAddressParser(options.__dict__['connect'])

        if ip is not None and port is not None:
            f = PAKEFactory()
            reactor.connectTCP(ip, port, f)
            print('Starting client A [*]: connecting')
        else:
            print('Ошибка при подключении')
            return
    elif options.__dict__['listen']:
        if not csm.listnerCheckSettings(settings):
            return

        port = settings['port']

        factory = protocol.ServerFactory()
        factory.protocol = PAKEProxyProtocol
        reactor.listenTCP(port, factory)        

    #mitm
    #reactor.connectTCP(public.MITM_IP, public.MITM_AS_B_CLIENT_PORT, f)
    reactor.run()


if __name__ == '__main__':
    main()
