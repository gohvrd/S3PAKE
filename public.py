q = 3   #prime order
g = 2   #parent element
M = 4
N = 8

def H(values: tuple):
    return (values[0] + values[1] / 2 + values[2]) % 100 + 1

def G(values: tuple):
    return (int((values[0] + int(values[1] / 2)) / 2) + values[2]) % 10 + 1

A_identifier = 111
B_identifier = 222
S_identifier = 333
C_identifier = 444

TRUSTED_SERVER_IP = '127.0.0.1'
TRUSTED_SERVER_PORT = 1997

B_CLIENT_IP = '127.0.0.1'
B_CLIENT_PORT = 3456

A_CLIENT_IP = '127.0.0.1'

C_CLIENT_IP = '127.0.0.1'
C_CLIENT_PORT = 4567