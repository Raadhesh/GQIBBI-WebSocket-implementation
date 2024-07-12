from Crypto.PublicKey import RSA
from Crypto.Util.number import size, inverse
import math
import random
import timeit
import time
import ast
import pickle


# to convert string dictionary to dictionary
def stringDict_to_dict(stringMessage):
    return ast.literal_eval(stringMessage)

# to convert from int to hex string
def int_to_hex(message):
    hexMessage = f'{message:x}'
    return hexMessage
# to convert from hex to int string
def hex_to_int(message):
    hexMessage = int(message, 16)
    return hexMessage


#gcd function
def gcd(a,b):
    while b > 0:
        a, b = b, a % b
    return a

#RSA setup
def setupRSA(keySize):
    setupStartTime = time.time()
    keyPair = RSA.generate(keySize)
    N = keyPair.n
    e = keyPair.e
    d = keyPair.d
    # p = keyPair.p
    # q = keyPair.q
    # phi_N = (p-1) * (q-1)

    # Show attributes of keyPair.
    # print("N = ", N)
    # print("e = ", e)
    # print("d = ", d)
    # print("p = ", p)
    # print("q = ", q)
    setupEndTime = time.time()
    setupTime =  setupEndTime - setupStartTime
    print("Setup Time for {k} bit keySize = {t}".format(k=str(keySize), t=str(setupTime)))
    return (setupTime, N, e, d)

#signing pk to produce sk
def signRSA(N, exponent, message):
    sigma = pow(message, exponent, N)
    return sigma

# generate random value which is co-prime to N
def generateRandomVal(N):
    y = random.randint(3, N)
    while gcd(y, N) != 1:
        y = random.randint(3,N)
    return y

#verification check
def verifyGQIBBI(N, e, Y, c, z, publicID):
    val1 = pow(z, e, N)
    temp = Y * pow(publicID, c, N)
    val2 = pow(temp, 1, N)
    print("\n")
    check = (val1 == val2)
    if check:
        print("Prover is verified through blinded identity")
    else:
        print("Prover is false")
    
    return check
    