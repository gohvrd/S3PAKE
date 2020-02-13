from twisted.internet import reactor, protocol
from struct import unpack, pack
from random import seed, randint
import sqlite3
import public

DB_NAME = './s3pake.db'
session_num = 1

class S3PAKE(protocol.Protocol):
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
        global session_num

        print("     Session #", session_num, ":")

        seed()
        z = randint(1, public.q - 1)
        print('S action [*]: received A||X||B||Y from B')
        print("S parameters [*]: z = ", z, "\n")

        A, X, B, Y = unpack('hxqhxq', data)
        print("A parameters (received) [*]: A = ", A)
        print("A parameters (received) [*]: X = ", X)
        print("B parameters (received) [*]: B = ", B)
        print("B parameters (received) [*]: Y = ", Y)


        pwA = self.GetClientSecretPassowrd(A)
        pwB = self.GetClientSecretPassowrd(B)

        g_power_x = int(X / public.M ** pwA)
        print('S calculates [*]: g^x = ', g_power_x)
        g_power_y = int(Y / public.N ** pwB)
        print('S calculates [*]: g^y = ', g_power_y)



        S_X = int((g_power_x ** z) * (public.G((B, public.S_identifier, g_power_y)) ** pwB))
        print('S calculates [*]: S_X = ', S_X)
        S_Y = int((g_power_y ** z) * (public.G((A, public.S_identifier, g_power_x)) ** pwA))
        print('S calculates [*]: S_Y = ', S_Y)
        print('S action [*]: sending S_X||S_Y')

        print("\n")

        session_num += 1

        self.transport.write(pack("qxq", S_X, S_Y))

    def GetClientSecretPassowrd(self, id: int):
        connection = sqlite3.connect(DB_NAME)
        cursor = connection.cursor()
        cursor.execute("SELECT SECRET_PASS FROM USERS_SECRETS WHERE USER_ID = {0:d}".format(id))
        result = cursor.fetchone()

        return int(result[0])

def main():
    """This runs the protocol on port 1997"""
    factory = protocol.ServerFactory()
    factory.protocol = S3PAKE
    print('Starting trusted server S [*]: id = ', public.S_identifier)
    print('Starting client S [*]: ip = ', public.TRUSTED_SERVER_IP)
    print('Starting client S [*]: port = ', public.TRUSTED_SERVER_PORT)
    print('Starting client S [*]: listening')
    print('Connection public parameters [*]: q = ', public.q)
    print('Connection public parameters [*]: g = ', public.g)
    print('Connection public parameters [*]: M = ', public.M)
    print('Connection public parameters [*]: N = ', public.N, '\n')
    reactor.listenTCP(public.TRUSTED_SERVER_PORT, factory)
    reactor.run()

# this only runs if the module was *not* imported
if __name__ == '__main__':
    main()
