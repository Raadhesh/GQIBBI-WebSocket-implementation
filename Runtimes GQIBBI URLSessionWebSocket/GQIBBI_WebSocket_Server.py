import asyncio
import websockets
import json
from Crypto.PublicKey import RSA
from Crypto.Util.number import size, inverse
import math
import random
import timeit
import time
import myWebSocketFunctions





(setupTime, N, e, d) = myWebSocketFunctions.setupRSA(1024)
params = {
    "N": N,
    "e": e
}
N_hex = myWebSocketFunctions.int_to_hex(N)
e_hex = myWebSocketFunctions.int_to_hex(e)
print("Params = ", params)

publicKeyJSON = {
    "response": "Parameters",
    "N_hex": N_hex,
    "e_hex": e_hex
}
print(publicKeyJSON)

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
                u_N = myWebSocketFunctions.hex_to_int(u_N_hex)
                u_e = myWebSocketFunctions.hex_to_int(u_e_hex)
                checkParams = (N == u_N) and (e == u_e)
                if checkParams:
                    print("\n\nUser Public Parameters MATCH Server Public Parameters\n\n")
                    # tempData = myWebSocketFunctions.stringDict_to_dict(data)
                    id_hex = data["ID"]
                    id = myWebSocketFunctions.hex_to_int(id_hex)
                    #extracting secret key
                    sk = myWebSocketFunctions.signRSA(N=N, exponent=d, message=id)
                    sk_hex = myWebSocketFunctions.int_to_hex(sk)
                    userSecretKeyJSON = {
                        "response": "Extracted User Secret Key",
                        "ID": id_hex,
                        "sk": sk_hex
                    }
                    reply = json.dumps(userSecretKeyJSON)
            elif str(data["request"]) == "Identification":
                #Receive Commitment 
                Y_hex = data["Y_hex"]
                Y = myWebSocketFunctions.hex_to_int(Y_hex)
                id_hex = data["ID"]
                id = myWebSocketFunctions.hex_to_int(id_hex)

                #Send Challenge
                c = myWebSocketFunctions.generateRandomVal(N)
                c_hex = myWebSocketFunctions.int_to_hex(c)
                print("Sending Challenge (c_hex) = " + c_hex)
                await websocket.send(c_hex)

                #Receive Response
                z_hex = await websocket.recv()
                print("Response (z_hex) = " + z_hex)
                z = myWebSocketFunctions.hex_to_int(z_hex)

                #Check if User identity is valid
                identityCheck = myWebSocketFunctions.verifyGQIBBI(N=N,e=e,Y=Y,c=c,z=z,publicID=id)
                if identityCheck == True:
                        print("User Verification is Successful!")
                        reply = "Success"
                elif identityCheck == False:
                    print("User Verification is Unsuccessful!")
                    reply = "Failure"
                else:
                    reply = "ERROR: Something Wrong or I am currently testing!"
                    print("ERROR: Something Wrong or I am currently testing!")
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
