import asyncio
import websockets
import json
from Crypto.PublicKey import RSA
from Crypto.Util.number import size, inverse
import math
import random
import timeit
import time
import ast
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
# to convert string dictionary to dictionary
def stringDict_to_dict(stringMessage):
    return ast.literal_eval(stringMessage)
# to convert from int to hex string
def hex_from_int(message):
    hexMessage = f'{message:x}'
    return hexMessage
# to convert from hex to int string
def int_from_hex(message):
    hexMessage = int(message, 16)
    return hexMessage

#main functions
def keygenOKRSA(keySize):
    setupStartTime = time.time()
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
    setupEndTime = time.time()
    setupTime =  setupEndTime - setupStartTime
    print("Setup Time for {k} bit keySize = {t}".format(k=str(keySize), t=str(setupTime)))
    # N, e, g are params and d is msk
    return (setupTime, N, e, g, d)
def extractOKRSA(X, N, e, g, d):
    # X is ID
    x1 = generateRandomVal(e)
    # x2 = (g^x1 . X)^-d mod N = ((g)^-d*x1 . X^-d) mod N
    x2 = (pow(inverse(g,N),(d*x1), N) * pow(inverse(X,N), d, N)) % N
    return (x1, x2)
def verifier(N, e, g, X, Y, c, z1, z2):
    print("\n\nCORRECTENESS Check\n")
    Check = pow((pow(g,z1,N) * pow(z2,e,N) * pow(X,c,N)),1, N)
    print("\nY = ", Y)
    print("")
    print("Check = ", Check)
    print("\n")
    if (Y == Check):
        # print("OkRSA Check Successful\nIdentification Successful\n")
        return True
    else:
        # print("OkRSA Check Unsuccessful\nIdentification Unsuccessful\n")
        return False
    

#keySize
k = 2048

(setupTime, N, e, g, d) = keygenOKRSA(k)
params = {
    "N": N,
    "e": e,
    "g": g
}
publicKeyJSON = {
    "response": "Public Parameters",
    "N_hex": hex_from_int(N),
    "e_hex": hex_from_int(e),
    "g_hex": hex_from_int(g)
}

# Default reply if no process takes place
defaultReplyJSON = {
    "response": "ERROR",
    "message": "Default Reply"
}




#websocket main part starts here
async def server(websocket):
    while True:
        try:
            receiveData = await websocket.recv()
            reply = "Default Reply"
            data = json.loads(receiveData)
            print("Received Data = ")
            print(data)
            #response for parameters request
            if str(data["request"]) == "Public Parameters":
                print("\n\nPublic Parameters Requested\n")
                reply = json.dumps(publicKeyJSON)
            elif str(data["request"]) == "User Secret Key":
                print("\n\nUser Secret Key Requested\n")
                u_N_hex = data["N_hex"]
                u_e_hex = data["e_hex"]
                u_g_hex = data["g_hex"]
                u_N = int_from_hex(u_N_hex)
                u_e = int_from_hex(u_e_hex)
                u_g = int_from_hex(u_g_hex)
                checkParams = (N == u_N) and (e == u_e) and (g == u_g)
                if checkParams:
                    print("\n\nUser Public Parameters MATCH Server Public Parameters\n\n")
                    # tempData = myWebSocketFunctions.stringDict_to_dict(data)
                    id_hex = data["ID"]
                    id = int_from_hex(id_hex)
                    #extracting secret key
                    # sk = signRSA(N=N, exponent=d, message=id)
                    (sk1, sk2) = extractOKRSA(id, N, e, g, d)
                    sk1_hex = hex_from_int(sk1)
                    sk2_hex = hex_from_int(sk2)
                    userSecretKeyJSON = {
                        "response": "Extracted User Secret Key",
                        "ID": id_hex,
                        "sk1": sk1_hex,
                        "sk2": sk2_hex
                    }
                    reply = json.dumps(userSecretKeyJSON)
            elif str(data["request"]) == "OkRSA Identification":
                #Receive Commitment 
                Y_hex = data["Y_hex"]
                Y = int_from_hex(Y_hex)
                id_hex = data["ID"]
                id = int_from_hex(id_hex)

                #Send Challenge for Sh identification
                c = generateRandomVal(N)
                c_hex = hex_from_int(c)
                print("Sending Challenge (c_hex) = " + c_hex)
                await websocket.send(c_hex)

                #Receive Response
                responseData = await websocket.recv()
                response = json.loads(responseData)
                print("Received Data = ")
                print(response)
                z1_hex = response["z1_hex"]
                z2_hex = response["z2_hex"]
                print("Response (z1_hex) = " + z1_hex)
                print("Response (z2_hex) = " + z2_hex)
                z1 = int_from_hex(z1_hex)
                z2 = int_from_hex(z2_hex)

                #Check if User identity is valid
                identityCheck = verifier(N, e, g, id, Y, c, z1, z2)
                if identityCheck == True:
                        print("User Verification is Successful!")
                        reply = "Success"
                elif identityCheck == False:
                    print("User Verification is Unsuccessful!")
                    reply = "Failure"
                else:
                    reply = "Default Reply ERROR: Something Wrong or I am currently testing!"
                    print("Default Reply ERROR: Something Wrong or I am currently testing!")
                print("\n\n")

            

            await websocket.send(reply)

        except websockets.ConnectionClosedOK:
            print("\nWebsocket Connection Closed\n")
            break
    



async def main():
    async with websockets.serve(server,"localhost", 8765):
        await asyncio.Future() #run forever


if __name__ == "__main__":
    asyncio.run(main())