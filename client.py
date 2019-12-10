from twisted.internet import reactor
from twisted.internet.protocol import Protocol, ClientFactory
from random import seed, randint
from struct import pack, unpack
from Crypto.Hash import SHA256

def MySize(value):
    if isinstance(value, int):
        return 4
    if isinstance(value, float):
        return 8
    if isinstance(value, str):
        return len(value)
    if isinstance(value, (set, tuple, list)):
        v_size = 0

        for elem in value:
            v_size += MySize(elem)

        return v_size

class S3PAKE(Protocol):
    def __init__(self, id, id_S, id_Cl, secretKey, g, q, M):
        self._id = id
        self._id_S = id_S
        self._id_Cl = id_Cl
        self._secretKey = secretKey
        self._randValue = None
        self._g = g
        self._q = q
        self._M = M

    def connectionMade(self):
        message = None

        #add condition
        message = self.ConnectionInitialization()

        self.transport.write(message)

    def dataReceived(self, data):
        pass

    def MySHA256(self, values: tuple):
        hash = SHA256.new()

        for elem in values:
            elem_size = MySize(elem)
            hash.update(elem.to_bytes(elem_size, byteorder='little'))

        return int.from_bytes(hash.digest(), byteorder='little') % 1000


    def ConnectionInitialization(self):
        '''
        Generate an initialization message to the other side

        :return: message byte string
        '''
        seed()
        self._randValue = randint(0, self._q - 1)

        key = self._g ** self._randValue * self._M ** self._secretKey

        return pack('hxi', self._id, key)

    def ListnerHandler(self, message):
        '''
        Request generation to a trusted server

        :param message: initialization message from other client
        :return: message byte string
        '''
        seed()
        self._randValue = randint(0, self._q - 1)
        key = self._g ** self._randValue * self._M ** self._secretKey

        return message + pack('hxi', self._id, key)

    def ToTrustServer(self, message):
        messageToSend = self.ListnerHandler(message)


        pass

    def FromTrustServer(self, message):
        pass

    def CheckBSide(self, message):
        X, alpha = unpack("QQ", message)

        C_S_gx_hash = self.MySHA256((self._id, self._id_S, self._g ** self._randValue))

        X_ = X / (C_S_gx_hash ** self._secretKey)

        true_alpha_hash = self.MySHA256((self._id, self._id_Cl, X_ ** self._randValue))

        if true_alpha_hash == alpha:
            sessionKey = SHA256.new(self._id)
            sessionKey.update(self._id_Cl)
            sessionKey.update(X_ ** self._randValue)
            self._sessionKey = sessionKey.digest()

            beta = self.MySHA256((self._id_Cl, self._id_, X_ ** self._randValue))

            self.transport.write(pack('Q', beta))
        else:
            #maybe terminate connection?
            pass

    def CheckASide(self, message):
        pass


class S3PAKEFactory(ClientFactory):
    def __init__(self, id, secretKey, g, q, M):
        self._id = id
        self._secretKey = secretKey
        self._g = g
        self._q = q
        self._M = M

    def buildProtocol(self, addr):
        return S3PAKE(self._id, self._secretKey, self._g, self._q, self._M)


