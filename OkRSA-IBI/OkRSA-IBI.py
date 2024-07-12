
from Crypto.PublicKey import RSA
from Crypto.Util.number import size, inverse
import random

# from myFunctions import *

#helper functions
def gcd(a,b):
    while b > 0:
        a, b = b, a % b
    return a

def generateRandomVal(maxVal) :
    r = random.randint(3, maxVal)
    while gcd(r, maxVal) != 1:
        r = random.randint(3,maxVal)
    return pow(r,1,maxVal)

#main functions
def keygenOKRSA(keySize):
    keyPair = RSA.generate(keySize)
    N = keyPair.n
    e = keyPair.e
    d = keyPair.d
    p = keyPair.p
    q = keyPair.q
    phi_N = (p-1) * (q-1)

    print("Setup STAGE: \n")
    # Show attributes of keyPair.
    print("N = ", N)
    print("e = ", e)
    print("d = ", d)
    print("p = ", p)
    print("q = ", q)
    g = generateRandomVal(N)
    print("g = ", g)
    # N, e, g are params and d is msk
    return (N, e, g, d)

def extractOKRSA(X, N, e, g, d):
    # X is ID
    x1 = generateRandomVal(e)
    # x2 = (g^x1 . X)^-d mod N = ((g)^-d*x1 . X^-d) mod N
    x2 = (pow(inverse(g,N),(d*x1), N) * pow(inverse(X,N), d, N)) % N
    return (x1, x2)


def prover(N, e, g, X, x1, x2):
    print("\n\n\nIdentification Stage: \n")
    y1 = generateRandomVal(e)
    y2 = generateRandomVal(N)
    Y = pow(pow(g,y1,N) * pow(y2,e,N),1,N)
    print("y1 = ", y1)
    print("y2 = ", y2)
    print("Y = ", Y)

    print("\nSending COMMITMENT....\n")
    c = generateRandomVal(N)
    print("c = ", c)
    print("\nSending CHALLENGE...\n")

    z1 = pow((y1 + (c*x1)),1, e)
    tempest = (y1 + (c*x1)) // e
    print("Tempest = ", tempest)
    z2 = pow((pow(g,tempest,N) * (y2 % N) * pow(x2,c,N)),1,N)
    print("z1 = ", z1)
    print("z2 = ", z2)
    print("\nSending RESPONSE...\n")
    return Y, c, z1, z2, y1, y2

def verifier(N, e, g, X, Y, c, z1, z2):
    print("\n\nCORRECTENESS Check\n")
    Check = pow((pow(g,z1,N) * pow(z2,e,N) * pow(X,c,N)),1, N)
    print("\nY = ", Y)
    print("")
    print("Check = ", Check)
    print("\n")
    if (Y == Check):
        print("OkRSA Check Successful\nIdentification Successful\n")
    else:
        print("OkRSA Check Unsuccessful\nIdentification Unsuccessful\n")


#program start
k = 1024
(N, e, g, d) = keygenOKRSA(k)

name = "Aravaan"
X = hash(name) 
print("X = ", X)

(x1, x2) = extractOKRSA(X,N,e,g,d)

Y, c, z1, z2, y1, y2 = prover(N, e, g, X, x1, x2)
verifier(N, e, g, X, Y, c, z1, z2)

