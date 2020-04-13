from twisted.internet import reactor, protocol
from struct import unpack, pack
from random import seed, randint
import sqlite3
import optparse
import xml.etree.ElementTree as xml
import re

settings = {
    'port': None,
    'id': None,
    'q': None,
    'g': None,
    'M': None,
    'N': None    
}

sessionNum = 1

def G(values: tuple):
    return settings['g'] ** ((values[0] + values[1] + values[2]) % settings['q'])

class TrustedServer(protocol.Protocol):
    def __init__(self):
        global settings, sessionNum

        self.settings = settings
        self.sessionNum = sessionNum
        self.dbm = DatabaseManager('./s3pake.db')

    def incrementSessionNumber(self):
        global sessionNum

        sessionNum = self.sessionNum + 1
        self.sessionNum += 1

    def dataReceived(self, data):
        print("[*]: Сеанс №{0:d}".format(self.sessionNum))

        seed()
        #z = randint(1, self.settings['q'] - 1)
        z = 2
        A, X, B, Y = unpack('hxqhxq', data)

        print("[*A B→S*]: A||X||B||Y от пользователя с id = {0:d}".format(B))
        print("[*]: \tA = {0:d}".format(A))
        print("[*]: \tX = {0:d}".format(X))
        print("[*]: \tB = {0:d}".format(B))
        print("[*]: \tY = {0:d}".format(Y))

        print("[*]: Выбирается случайное z = {0:d} из Zp".format(z))   
        
        pwA = self.dbm.getPwById(A)
        pwB = self.dbm.getPwById(B)

        gPowerX = int(X / self.settings['M'] ** pwA)
        print("[*]: Вычисляется g^x = {0:d}".format(gPowerX))
        gPowerY = int(Y / self.settings['N'] ** pwB)
        print("[*]: Вычисляется g^y = {0:d}".format(gPowerY))
        
        S_X = int((gPowerX ** z) * (G((B, self.settings['id'], gPowerY)) ** pwB))
        print("[*]: Вычисляется S_X = {0:d}".format(S_X))
        S_Y = int((gPowerY ** z) * (G((A, self.settings['id'], gPowerX)) ** pwA))
        print("[*]: Вычисляется S_Y = {0:d}".format(S_Y))
        print("[*A B←S*]: S_X||S_Y\n")

        self.incrementSessionNumber()

        self.transport.write(pack("qxq", S_X, S_Y))        


class DatabaseManager():
    def __init__(self, dbName):
        self.dbName = dbName

    def getPwById(self, id):
        connection = sqlite3.connect(self.dbName)

        cursor = connection.cursor()
        cursor.execute("SELECT SECRET_PASS FROM USERS_SECRETS WHERE USER_ID = {0:d}".format(id))
        result = cursor.fetchone()
        
        connection.close()

        return int(result[0])

    def setPwById(self, id, pw):
        connection = sqlite3.connect(self.dbName)

        cursor = connection.cursor()
        try:
            cursor.execute("UPDATE USERS_SECRETS SET SECRET_PASS = {0:d} WHERE USER_ID = {1:d}".format(pw, id))
        except:
            print("Ошибка [!]: Ошибка при изменении пароля пользователя (id = {0:d})".format(id))
        
        if cursor.rowcount == 0:
            print("Ошибка [!]: Пользователя с id = {0:d} не существует".format(id))
        else:
            print("[*]: Количество обновленных строк: {0:d}".format(cursor.rowcount))

        connection.commit()
        
        connection.close()

    def checkUniqId(self, id):
        connection = sqlite3.connect(self.dbName)

        cursor = connection.cursor()
        cursor.execute("SELECT * FROM USERS_SECRETS WHERE USER_ID = {0:d}".format(id))
        result = cursor.fetchone()

        if result is None:
            return True
        
        return False

    def clientRegistration(self, id, pw):
        if type(id) is not int and id <= 0:
            print("Ошибка [!]: Идентификатор должен быть положительным целым числом")
            return

        if not self.checkUniqId(id):
            print("Ошибка [!]: Выбранный идентификатор уже занят другим пользователем")
            return

        if type(pw) is not int and pw <= 0:
            print("Ошибка [!]: Пароль должен быть положительным целым числом")
            return

        connection = sqlite3.connect(self.dbName)

        cursor = connection.cursor()
        try:
            cursor.execute("INSERT INTO USERS_SECRETS VALUES ({0:d},{1:d})".format(id, pw))
        except:
            print("Ошибка [!]: Ошибка регистрации пользователя (id = {0:d})".format(id))

        print("[*]: Пользователь успешно зарегистрирован (id = {0:d})".format(id))

        connection.commit()
        
        connection.close()

    def deleteClient(self, id):
        connection = sqlite3.connect(self.dbName)

        cursor = connection.cursor()
        try:
            cursor.execute("DELETE FROM USERS_SECRETS WHERE USER_ID = {0:d}".format(id))        
        except:
            print("Ошибка [!]: Ошибка удаления пользователя (id = {0:d})".format(id))

        if cursor.rowcount == 0:
            print("Ошибка [!]: Пользователя с id = {0:d} не существует".format(id))
        else:
            print("[*]: Пользователь успешно удален (id = {0:d})".format(id))

        connection.commit()
        
        connection.close()       


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
            print('Ошибка [!]: Ошибка создания файла настроек')

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
            print('Ошибка [!]: Ошибка добавления новых настроек')
    
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
            print("Ошибка [!]: Создайте файл перед проверкой корректности его формата")
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
            print("Ошибка [!]: Необходимо указать q")
            result = False
        if settings['g'] is None:
            print("Ошибка [!]: Необходимо указать g")
            result = False
        if settings['id'] is None:
            print("Ошибка [!]: Необходимо указать id")
            result = False
        if settings['M'] is None:
            print("Ошибка [!]: Необходимо указать M")
            result = False
        if settings['N'] is None:
            print("Ошибка [!]: Необходимо указать N")
            result = False
        elif settings['port'] is None:
            print("Ошибка [!]: Необходимо указать port")
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


def dbOptions(new: str, dele: str, upd: str):
    newExists = new is not None
    delExists = dele is not None
    updExists = upd is not None

    if (newExists and updExists) or \
        (delExists and updExists) or \
        (delExists and newExists):
        print("Ошибка [!]: Выберите только одну опцию n/d/u")
        return False

    dbm = DatabaseManager('./s3pake.db')

    if newExists:
        regex = r"^([\d]+):([\d]+$)"
        
        result = re.search(regex, new)

        if result is None:
            print("Ошибка [!]: Переданы некорректные значения")
            print("Ошибка [!]: Формат передачи данных нового пользователя: \'id:pw\'")
            return False

        id = int(result.group(1))
        pw = int(result.group(2))

        dbm.clientRegistration(id, pw)        
    elif delExists:
        dbm.deleteClient(int(dele))
    elif updExists:
        regex = r"^([\d]+):([\d]+$)"
        
        result = re.search(regex, new)

        if result is None:
            print("Ошибка [!]: Переданы некорректные значения")
            print("Ошибка [!]: Формат передачи данных для обновления пароля пользователя: \'id:pw\'")
            return False

        id = int(result.group(1))
        pw = int(result.group(2))

        dbm.setPwById(id, pw)

    return True


def main():
    global settings

    optionParser = optparse.OptionParser(description='Реализация доверенного сервера, работающего по протоколу S-3PAKE')
    
    optionParser.add_option('-i', '--id', action='store', help='Установка числового значения идентификатора доверенного сервера')
    optionParser.add_option('-p', '--port', action='store', help='Установка значения порта доверенного сервера, на котором ожидается подключение клиентов')
    optionParser.add_option('-q', '--q', action='store', help='Установка значения порядка группы')
    optionParser.add_option('-g', '--g', action='store', help='Установка значения порождающего элемента группы')
    optionParser.add_option('-M', '--M', action='store', help='Установка затемняющего значения M')
    optionParser.add_option('-N', '--N', action='store', help='Установка затемняющего значения N')

    optionParser.add_option('-n', '--new', action='store', help='Добавление нового пользователя в базу')
    optionParser.add_option('-d', '--del', action='store', help='Удаление пользователя из базы')
    optionParser.add_option('-u', '--upd', action='store', help='Изменение пароля пользователя')

    (options, arguments) = optionParser.parse_args()

    csm = ServerSettingsManager()

    if not csm.checkSettingsFile():
        print("Ошибка [!]: Поврежден файл с настройками клиента")
        return

    settingsDict = csm.addSettings(options.__dict__)
    
    if settingsDict != {}:
        csm.setSettings(settingsDict)                

    csm.getSettings()

    if not dbOptions(options.__dict__['new'], options.__dict__['del'], options.__dict__['upd']):
        return

    factory = protocol.ServerFactory()
    factory.protocol = TrustedServer
    print("[*]: Запуск доверенного сервера")
    print("[*]:")
    print("[*]: Параметры сети")
    print('[*]: \tport = ', settings['port'])
    print("[*]: Параметры протокола")
    print('[*]: \tid = ', settings['id'])    
    print('[*]: \tq = ', settings['q'])
    print('[*]: \tg = ', settings['g'])
    print('[*]: \tM = ', settings['M'])
    print('[*]: \tN = ', settings['N'])
    
    try:
        reactor.listenTCP(settings['port'], factory)
    except:
        print("Ошибка [!]: Ошибка при инициализации порта")

    print("[*]:")
    print("[*]: Сервер готов")    
    print("[*]: Ожидание подключений...")
    print("[*]:")

    reactor.run()

if __name__ == '__main__':
    main()
