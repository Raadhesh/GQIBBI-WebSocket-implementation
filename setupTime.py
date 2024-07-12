from Crypto.PublicKey import RSA
from Crypto.Util.number import size, inverse
import math
import random
import timeit
import time
import myWebSocketFunctions


i = 0
keySize = 2048

while i<100:
    i+=1
    (setupTime, N, e, d) = myWebSocketFunctions.setupRSA(keySize=keySize)
    message = "{t}\n".format(t=str(setupTime))
    with open('setupRuntimes.txt', 'a') as the_file:
        the_file.write(message)
