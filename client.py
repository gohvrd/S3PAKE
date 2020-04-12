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
    'sid': None, 
    'sip': None,
    'sport': None,
    'uid': None,
    'umip': None,
    'umport': None,
    'smip': None,
    'smport': None    
}

mitm = False

def G(values: tuple):    
    #return (int((values[0] + int(values[1] / 2)) / 2) + values[2]) % 10 + 1
    return settings['g'] ** ((values[0] + values[1] + values[2]) % settings['q'])


def H(values: tuple):
    #return (values[0] + values[1] / 2 + values[2]) % 100 + 1
    return settings['g'] ** ((values[0] + values[1] + values[2]) % settings['q'])


class ClientInitiator(protocol.Protocol):
    def __init__(self):
        global settings
        
        self.settings = settings
        self.SK = None
        self.g_power_yz = None
        self.x = None

    def connectionMade(self):
        self.transport.write(self.connectionInitializationMessage())
        print("\n[*A→B S*]: A||X")
 
    def dataReceived(self, data):
        beta = self.responseMessageHandler(data)

        if beta is not None:
            print("[*]: Вычисляется beta = {0:d}".format(beta))
            print("\n[*A→B S*]: beta")

            message = pack('q', beta)
            self.transport.write(message)
            print("\n[$Выполнено$]: SK = {0:d}".format(self.SK))

            self.transport.loseConnection()
        else:
            print("Ошибка [!]: Получено неверное значение alpha.")
            self.transport.loseConnection()

    def connectionLost(self, reason):
        pass

    def connectionInitializationMessage(self):
        seed()
        self.x = randint(1, self.settings['q'] - 1)
        print("[*]: Выбирается случайное x = {0:d} из Zp".format(self.x))
        X = self.settings['g'] ** self.x * self.settings['M'] ** self.settings['pw']
        print("[*]: Вычисляется X = {0:d}".format(X))

        return pack('hxq', self.settings['id'], X)

    def betaMessage(self):
        return int(G((self.settings['uid'], self.settings['id'], self.g_power_yz ** self.x)))

    def responseMessageHandler(self, message):
        S_Y, alpha = unpack('qxq', message)
        print("[*A←B S*]: S_Y||alpha\n")
        print("[*]: \tS_Y = {0:d}".format(S_Y))
        print("[*]: \talpha = {0:d}".format(alpha))
        self.g_power_yz = int(S_Y / (G((self.settings['id'], self.settings['sid'], self.settings['g'] ** self.x)) ** self.settings['pw']))
        print("[*]: Вычисляется g^(yz) = {0:d}".format(self.g_power_yz))

        test_alpha = int(G((self.settings['id'], self.settings['uid'], self.g_power_yz ** self.x)))
        
        print("[*]: Проверка полученного значения alpha")
        print("[*]: Самостоятельное вычисление alpha\' = {0:d}".format(test_alpha))

        if alpha == test_alpha:
            print("[*]: alpha\' = alpha")
            self.SK = int(H((self.settings['id'], self.settings['uid'], self.g_power_yz ** self.x)))
            return self.betaMessage()

        print("[*]: alpha\' != alpha")

        return None


class ClientInitiatorFactory(protocol.ClientFactory):
    protocol = ClientInitiator

    def clientConnectionFailed(self, connector, reason):
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        reactor.stop()


class ClientListner(protocol.Protocol):
    def __init__(self):
        global settings, mitm

        self.settings = settings
        seed()
        self.y = randint(1, self.settings['q'] - 1)
        self.SK = None
        self.initId = None
        self.mitm = mitm

        self.buffer = None
        self.proxy_to_server_protocol = None

        self.initialReceive = False
        self.betaReceive = False

    def connectionMade(self):
        proxy_to_server_factory = protocol.ClientFactory()
        proxy_to_server_factory.protocol = ClientProxy
        proxy_to_server_factory.server = self

        if self.mitm:
            reactor.connectTCP(self.settings['smip'], self.settings['smport'], proxy_to_server_factory)
        else:
            reactor.connectTCP(self.settings['sip'], self.settings['sport'], proxy_to_server_factory)       

    def dataReceived(self, data):
        if not self.initialReceive:
            mess = self.receiveConnectRequest(data)
            if self.proxy_to_server_protocol:
                self.proxy_to_server_protocol.write(mess)
            else:
                self.buffer = mess
            self.initialReceive = True
        elif not self.betaReceive:
            self.receiveBeta(data)
            self.betaReceive = True

    def write(self, data):
        self.transport.write(data)

    def receiveConnectRequest(self, message):        
        print("[*A→B S*]: A||X\n")
        self.initId, X = unpack('hxq', message)
        print("[*]: \tA = {0:d}".format(self.initId))
        print("[*]: \tX = {0:d}".format(X))
        print("[*]: Выбирается случайное y = {0:d} из Zp".format(self.y))
        Y = self.settings['g'] ** self.y * self.settings['N'] ** self.settings['pw']
        print("[*]: Вычисляется Y = {0:d}".format(Y))

        print("\n[*A B→S*]: A||X||B||Y")

        return message + pack('hxq', self.settings['id'], Y)

    def receiveBeta(self, beta):
        recv_beta = unpack('q', beta)[0]
        print("[*A→B S*]: beta\n")
        print("[*]: \tbeta = {0:d}".format(recv_beta))
        print("[*]: Проверка полученного значения beta")
        print("[*]: Самостоятельное вычисление beta\'")
        if recv_beta == int(G((self.settings['id'], self.initId, self.proxy_to_server_protocol.g_power_xz ** self.y))):
            print("[*]: beta\' = beta")
            self.SK = int(H((self.initId, self.settings['id'], self.proxy_to_server_protocol.g_power_xz ** self.y)))
            print("\n[$Выполнено$]: SK = {0:d}".format(self.SK))
        else:
            print("[*]: beta\' != beta")
            print("Ошибка [!]: Получено неверное значение beta")

        reactor.stop()


class ClientProxy(protocol.Protocol):
    def __init__(self):
        global settings

        self.settings = settings
        self.g_power_xz = None

    def connectionMade(self):
        self.factory.server.proxy_to_server_protocol = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''

        self.serverResponseReceive = False

    def dataReceived(self, data):
        if not self.serverResponseReceive:
            self.factory.server.write(self.receiveTrustedServerResponse(data))
            self.serverResponseReceive = True

    def write(self, data):
        if data:
            self.transport.write(data)

    def receiveTrustedServerResponse(self, response):
        S_X, S_Y = unpack('qxq', response)
        print("[*A B←S*]: S_X||S_Y\n")
        print("[*]: \tS_X = {0:d}".format(S_X))
        print("[*]: \tS_Y = {0:d}".format(S_Y))
        self.g_power_xz = int(S_X / G((self.settings['id'], self.settings['sid'], self.settings['g'] ** self.factory.server.y)) ** self.settings['pw'])
        print("[*]: Вычисление g^(xz) = {0:d}".format(self.g_power_xz))
        alpha = int(G((self.factory.server.initId, self.settings['id'], self.g_power_xz ** self.factory.server.y)))
        print("[*]: Вычисление alpha = {0:d}".format(alpha))

        print("\n[*A←B S*]: S_Y||alpha")

        return pack('qxq', S_Y, alpha)


class ClientSettingsManager():
    def __init__(self, filename):
        self.filename = filename

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
        mitm = xml.Element('mitm')

        root.append(network)
        root.append(private)
        root.append(public)
        root.append(server)
        root.append(user)
        root.append(mitm)

        xml.SubElement(network, 'port')

        xml.SubElement(private, 'pw')        

        xml.SubElement(public, 'id')
        xml.SubElement(public, 'q')
        xml.SubElement(public, 'g')
        xml.SubElement(public, 'M')
        xml.SubElement(public, 'N')

        xml.SubElement(server, 'sid')
        xml.SubElement(server, 'sip')
        xml.SubElement(server, 'sport')

        xml.SubElement(user, 'uid')

        xml.SubElement(mitm, 'umip')
        xml.SubElement(mitm, 'umport')
        xml.SubElement(mitm, 'smip')
        xml.SubElement(mitm, 'smport')

        tree = xml.ElementTree(root)       
        
        try:
            tree.write(self.filename, xml_declaration=True)   
        except:
            print("Ошибка [!]: Ошибка создания файла настроек")

    def setSettings(self, inSettings: dict):
        global settings

        if type(inSettings) is not dict:
            print("Ошибка [!]: Передавать настройки можно только в словаре, передан: %s" % type(inSettings))
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
            print("Ошибка [!]: Ошибка добавления новых настроек")
    
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
            print("Ошибка [!]: Создайте файл перед проверкой корректности его формата")
            return
        
        root = tree.getroot()

        trueTypeNames = ['network', 'private', 'public', 'server', 'user', 'mitm']
        trueOptionNames = [
            ['port'], 
            ['pw'], 
            ['id', 'q', 'g', 'M', 'N'],
            ['sid', 'sip', 'sport'],
            ['uid'],
            ['umip', 'umport', 'smip', 'smport']]

        settingsType = enumerate(root)

        if len(root) != len(trueTypeNames):
            return False
        
        for i, typeName in settingsType:
            if typeName.tag != trueTypeNames[i]:
                return False

            if len(typeName) != len(trueOptionNames[i]):
                return False

            for j, optionName in enumerate(typeName):
                if optionName.tag != trueOptionNames[i][j]:
                    return False

        return True

    def isIpValid(self, ip):
        regexIpValidation = r'^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$'
    
        if re.search(regexIpValidation, ip) is None:            
            return False

        return True


    def generalCheckSettings(self, settings):
        result = True

        if settings['q'] is None:
            print("Ошибка [!]: Необходимо указать q")
            result = False
        if settings['g'] is None:
            print("Ошибка [!]: Необходимо указать g")
            result = False
        if settings['id'] is None:
            print("Ошибка [!]: Необходимо указать id")
            result = False
        if settings['sid'] is None:
            print("Ошибка [!]: Необходимо указать sid")
            result = False
        if settings['pw'] is None:
            print("Ошибка [!]: Необходимо указать pw")
            result = False

        return result

    def initiatorCheckSettings(self, settings):
        result = self.generalCheckSettings(settings)

        if settings['M'] is None:
            print("Ошибка [!]: Необходимо указать M")
            result = False
        if settings['uid'] is None:
            print("Ошибка [!]: Необходимо указать uid")
            result = False
        if settings.get('mitm') is not None:
            if settings['umip'] is None:
                print("Ошибка [!]: Необходимо указать umip")
                result = False
            elif not self.isIpValid(settings['umip']):
                print("Ошибка [!]: Некорректный формат адреса umip")
                result = False

            if settings['umport'] is None:
                print("Ошибка [!]: Необходимо указать umport")
                result = False        
        
        return result

    def listenerCheckSettings(self, settings):
        result = self.generalCheckSettings(settings)
        
        if settings['N'] is None:
            print("Ошибка [!]: Необходимо указать N")
            result = False
        if settings['port'] is None:
            print("Ошибка [!]: Необходимо указать port")
            result = False
        if settings['sip'] is None:
            print("Ошибка [!]: Необходимо указать sip")
            result = False
        if settings['sport'] is None:
            print("Ошибка [!]: Необходимо указать sport")
            result = False
        if settings.get('mitm') is not None:
            if settings['usip'] is None:
                print("Ошибка [!]: Необходимо указать usip")
                result = False
            elif not self.isIpValid(settings['usip']):
                print("Ошибка [!]: Некорректный формат адреса usip")
                result = False

            if settings['usport'] is None:
                print("Ошибка [!]: Необходимо указать usport")
                result = False  

        return result    

    def addSettings(self, options):
        settingsDict = {}

        for name in settings.keys():
            if options[name] is not None:
                settingsDict[name] = options[name]

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
            print("Ошибка [!]: Неверное значение порта")
            return (None, None)

        return (ip, port)

    print("Ошибка [!]: Неверный формат ip-адреса. Ожидается: \"ip:port\"")

    return (None, None)    


def printOptions(isInitiator, port = None, uip = None, uport = None):
    print("[*]: Запуск легального клиента")

    if isInitiator:
        print("[*]: Режим инициатора\n")
    else:
        print("[*]: Режим ожидания инициатора\n")
        print("[*]: Параметры сети")
        print("[*]: \tport = {0:d}".format(port))

    print("[*]: Параметры клиента (секретные)")
    print("[*]: \tpw = {0:d}".format(settings['pw']))
    print("[*]: Параметры клиента (публичные)")
    print("[*]: \tid = {0:d}".format(settings['id']))
    print("[*]: \tq = {0:d}".format(settings['q']))
    print("[*]: \tg = {0:d}".format(settings['g']))

    if isInitiator:
        print("[*]: \tM = {0:d}".format(settings['M']))
        print("[*]: Параметры принимающего клиента")
        print("[*]: \tid = {0:d}".format(settings['uid']))
        print("[*]: \tip = {0:s}".format(uip))
        print("[*]: \tport = {0:d}".format(uport))
    else:
        print("[*]: \tN = {0:d}".format(settings['N']))
        print("[*]: Параметры сервера")
        print("[*]: \tid = {0:d}".format(settings['sid']))
        print("[*]: \tip = {0:s}".format(settings['sip']))
        print("[*]: \tport = {0:d}".format(settings['sport']))


def main():
    global settings, mitm

    optionParser = OptionParser(description='Клиент легального пользователя, работающий по протоколу S-3PAKE')
    
    optionParser.add_option('-p', '--port', action='store', help='Установка порта, на котором клиент будет ожидать подключения')
    optionParser.add_option('-d', '--id', action='store', help='Установка числового идентификатора клиента')
    optionParser.add_option('-w', '--pw', action='store', help='Установка секретного пароля клиента')
    optionParser.add_option('-q', '--q', action='store', help='Установка значения порядка группы')
    optionParser.add_option('-g', '--g', action='store', help='Установка порождающего элемента группы')
    optionParser.add_option('-M', '--M', action='store', help='Установка затемняющего значения M')
    optionParser.add_option('-N', '--N', action='store', help='Установка затемняющего значения N')
    optionParser.add_option('-S', '--sid', action='store', help='Установка числового идентификатора доверенного сервера')
    optionParser.add_option('-i', '--sip', action='store', help='Установка ip-адреса доверенного сервера')
    optionParser.add_option('-s', '--sport', action='store', help='Установка порта доверенного сервера')
    optionParser.add_option('-u', '--uid', action='store', help='Установка числового идентификатора клиента, с которым устанавливается соединение')

    optionParser.add_option('-c', '--connect', action='store', help='Выбор режима инициатора')
    optionParser.add_option('-l', '--listen', action='store_true', help='Выбор режима ожидания подключения инициатора')

    optionParser.add_option('-m', '--mitm', action='store_true', help='Включение опции, позволяющей провести MITM атаку')

    optionParser.add_option('--umip', action='store', help='Установка ip-адреса атакующего, выдающего себя за другого клиента')   
    optionParser.add_option('--umport', action='store', help='Установка порта атакующего, выдающего себя за другого клиента')   
    optionParser.add_option('--smip', action='store', help='Установка ip-адреса атакующего, выдающего себя за доверенный сервер')   
    optionParser.add_option('--smport', action='store', help='Установка порта атакующего, выдающего себя за доверенный сервер')   

    (options, arguments) = optionParser.parse_args()      
        
    if options.__dict__['connect'] is not None:        
        if options.__dict__['listen']:
            print('Ошибка [!]: Одновременно можно выбрать только один режим работы')
            return

        csm = ClientSettingsManager('cclient_settings.xml')

        if not csm.checkSettingsFile():
            print("Ошибка [!]: Поврежден файл с настройками клиента")
            return

        settingsDict = csm.addSettings(options.__dict__)
    
        if settingsDict != {}:
            csm.setSettings(settingsDict)                

        csm.getSettings() 

        if not csm.initiatorCheckSettings(settings):
            print("Ошибка [!]: Не правильно сконфигурирован инициатор")
            return

        ip, port = (None, None)

        if options.__dict__['mitm']:
            ip = settings['umip']
            port = settings['umport']
        else:
            ip, port = connectionAddressParser(options.__dict__['connect'])

        printOptions(isInitiator=True, uip=ip, uport=port)

        if ip is not None and port is not None:
            f = ClientInitiatorFactory()
            try:                
                reactor.connectTCP(ip, port, f)
            except:
                print("Ошибка [!]: Ошибка сети - Не удалось подключиться к клиенту {0:s}:{1:d}".format(ip, port))
        else:
            print("Ошибка [!]: Укажите корректные значения ip и port")
            return
            
        print("\n[*]: Клиент готов")
        print("[*]: Подключение...\n")        
    elif options.__dict__['listen']:
        csm = ClientSettingsManager('lclient_settings.xml')

        if not csm.checkSettingsFile():
            print("Ошибка [!]: Поврежден файл с настройками клиента")
            return

        settingsDict = csm.addSettings(options.__dict__)
    
        if settingsDict != {}:
            csm.setSettings(settingsDict)                

        csm.getSettings() 

        if not csm.listenerCheckSettings(settings):
            print("Ошибка [!]: Не правильно сконфигурирован принимающий клиент")
            return

        port = settings['port']                

        printOptions(isInitiator=False, port=port)

        factory = protocol.ServerFactory()
        factory.protocol = ClientListner
        mitm = options.__dict__['mitm']
        try:
            reactor.listenTCP(port, factory)
        except:
            print("Ошибка [!]: Ошибка при инициализации порта")
        
        print("\n[*]: Клиент готов")
        print("[*]: Ожидание подключения...\n")

    reactor.run()


if __name__ == '__main__':
    main()
