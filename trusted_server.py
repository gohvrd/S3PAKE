from twisted.internet import reactor, protocol
from struct import unpack, pack
from random import seed, randint
import sqlite3

settings = {
    'port': None,
    'id': None,
    'q': None,
    'g': None,
    'M': None,
    'N': None    
}

def G(values: tuple):
    return (int((values[0] + int(values[1] / 2)) / 2) + values[2]) % 10 + 1

class TrustedServer(protocol.Protocol):
    def __init__(self):
        global settings

        self.settings = settings
        self.sessionNum = 1
        self.dbName = './s3pake.db'

    def connectionMade(self):
        """
        Called by twisted when a client connects to the
        proxy. Makes an connection from the proxy to the
        server to complete the chain.
        """
        pass
        #print("Connection made from B => TRUSTED")

    def dataReceived(self, data):
        '''
        Received connection data from client and send answer.

        :param data: connection data from client(format: id(2) || A(2) || 00 || X(4) || B(2) || Y(4))
        :return:
        '''
        print("     Session #", self.sessionNum, ":")

        seed()
        z = randint(1, self.settings['q'] - 1)
        print('S action [*]: received A||X||B||Y from B')
        print("S parameters [*]: z = ", z, "\n")

        A, X, B, Y = unpack('hxqhxq', data)
        print("A parameters (received) [*]: A = ", A)
        print("A parameters (received) [*]: X = ", X)
        print("B parameters (received) [*]: B = ", B)
        print("B parameters (received) [*]: Y = ", Y)


        pwA = self.GetClientSecretPassowrd(A)
        pwB = self.GetClientSecretPassowrd(B)

        gPowerX = int(X / self.settings['M'] ** pwA)
        print('S calculates [*]: g^x = ', gPowerX)
        gPowerY = int(Y / self.settings['N'] ** pwB)
        print('S calculates [*]: g^y = ', gPowerY)



        S_X = int((gPowerX ** z) * (G((B, self.settings['id'], gPowerY)) ** pwB))
        print('S calculates [*]: S_X = ', S_X)
        S_Y = int((gPowerY ** z) * (G((A, self.settings['id'], gPowerX)) ** pwA))
        print('S calculates [*]: S_Y = ', S_Y)
        print('S action [*]: sending S_X||S_Y')

        print("\n")

        self.sessionNum += 1

        self.transport.write(pack("qxq", S_X, S_Y))

    def GetClientSecretPassowrd(self, id: int):
        connection = sqlite3.connect(self.dbName)
        cursor = connection.cursor()
        cursor.execute("SELECT SECRET_PASS FROM USERS_SECRETS WHERE USER_ID = {0:d}".format(id))
        result = cursor.fetchone()

        return int(result[0])


class ServerSettingsManager():
    def __init__(self):
        self.filename = 'server_settings.xml'

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
        public = xml.Element('public')

        root.append(network)
        root.append(public)

        xml.SubElement(network, 'port')   

        xml.SubElement(public, 'id')
        xml.SubElement(public, 'q')
        xml.SubElement(public, 'g')
        xml.SubElement(public, 'M')
        xml.SubElement(public, 'N')

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
                settings[parametr.tag] = int(parametr.text)

    def checkSettingsFile(self):
        try:
            tree = xml.ElementTree(file=self.filename)
        except IOError:
            print("Создайте файл перед проверкой корректности его формата")
            return
        
        root = tree.getroot()

        trueTypeNames = ['network', 'public']
        trueOptionNames = [
            ['port'],
            ['id', 'q', 'g', 'M', 'N']]

        settingsType = enumerate(root)
        
        for i, typeName in settingsType:
            if typeName.tag != trueTypeNames[i]:
                return False

            for j, optionName in enumerate(typeName):
                if optionName.tag != trueOptionNames[i][j]:
                    return False

        return True

    def checkSettings(self, settings):
        result = True

        if settings['q'] is None:
            print("Необходимо указать q")
            result = False
        if settings['g'] is None:
            print("Необходимо указать g")
            result = False
        if settings['id'] is None:
            print("Необходимо указать id")
            result = False
        if settings['M'] is None:
            print("Необходимо указать M")
            result = False
        if settings['N'] is None:
            print("Необходимо указать N")
            result = False
        elif settings['port'] is None:
            print("Необходимо указать port")
            result = False

        return result

    def addSettings(self, options):
        settingsDict = {}

        if options['port'] is not None:
            settingsDict['port'] = options['port']

        if options['q'] is not None:
            settingsDict['q'] = options['q']

        if options['g'] is not None:
            settingsDict['g'] = options['g']

        if options['M'] is not None:
            settingsDict['M'] = options['M']

        if options['N'] is not None:
            settingsDict['N'] = options['N']

        if options['id'] is not None:
            settingsDict['id'] = options['id']

        return settingsDict


def main():
    global settings

    """This runs the protocol on port 1997"""
    factory = protocol.ServerFactory()
    factory.protocol = TrustedServer
    print('Starting trusted server S [*]: id = ', settings['id'])
    print('Starting client S [*]: port = ', settings['port'])
    print('Starting client S [*]: listening')
    print('Connection public parameters [*]: q = ', settings['q'])
    print('Connection public parameters [*]: g = ', settings['g'])
    print('Connection public parameters [*]: M = ', settings['M'])
    print('Connection public parameters [*]: N = ', settings['N'], '\n')
    reactor.listenTCP(settings['port'], factory)
    reactor.run()

# this only runs if the module was *not* imported
if __name__ == '__main__':
    main()
