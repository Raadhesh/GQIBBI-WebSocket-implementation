//
//  ContentView.swift
//  Sh-IBI and Sh*-IBI URLSessionWebsocket Client
//
//  Created by Raadhesh Kannan on 24/05/2024.
//

import SwiftUI
import CryptoSwift

//Temp Runtime Date variables
var startTime = Date()
var endTime = Date()
var rP1Time = Date()
var rP2Time = Date()
var ep1Time = Date()        // extract start time
var ep2Time = Date()        // extract end time
var sk1Time = Date()       // secret key start time
var sk2Time = Date()       // secret key end time
// Sh Identification
var nVerify1Time = Date()   //generate commitment
var nVerify2Time = Date()   //send commitment
var nVerify3Time = Date()   //receive response
var nVerify4Time = Date()   //send response
var nVerify5Time = Date()   //receive verification result
// Sh* Identification
var bVerify1Time = Date()   //generate commitment
var bVerify2Time = Date()   //send commitment
var bVerify3Time = Date()   //receive response
var bVerify4Time = Date()   //send response
var bVerify5Time = Date()   //receive verification result

//Runtime variables
var totalTime:Double = 0
var connectWebsocketTime:Double = 0
var requestParamTime:Double = 0
var generatePKTime:Double = 0
var preExtractTime:Double = 0
//Extract
var requestSecretKeyTime:Double = 0
//Sh Identification
var nGenerateCMTTime:Double = 0
var nReceiveCHLTime:Double = 0
var nGenerateRSPTime:Double = 0
var nReceiveVerificationTime:Double = 0
var nTotalVerificationTime:Double = 0
//Sh* Identification
var bGenerateCMTTime:Double = 0
var bReceiveCHLTime:Double = 0
var bGenerateRSPTime:Double = 0
var bReceiveVerificationTime:Double = 0
var bTotalVerificationTime:Double = 0

var totalRuntime:Double = 0


//MARK: Global variables
//message count
var sendCount = 0
var receiveCount = 0
//parameters
var e:BigUInteger?
var N:BigUInteger?
var e_hex:String?
var N_hex:String?
//public key and blind public key
var name:String = "Raadhesh"
var userID: Array<UInt8>?       //Hash of Username and public key

//secret key
var sk: Array<UInt8> = name.bytes   // secret key
var sk_hex:String?
//Sh identification
var y:BigUInteger?
var Y:BigUInteger?
var Y_hex:String?
var c_hex:String?
var c:BigUInteger?
var z:BigUInteger?
var z_hex:String?
//Sh* identification
var by:BigUInteger?
var bY:BigUInteger?
var bY_hex:String?
var bc_hex:String?
var bc:BigUInteger?
var bz:BigUInteger?
var bz_hex:String?


struct ContentView: View {
    //MARK: display checks
    @State var paramCheck = false
    @State var prepExtractCheck = false
    @State var secretKeyCheck = false
    @State var nVerificationCheck = false
    @State var nFailureVerificationCheck = false
    @State var bVerificationCheck = false
    @State var bFailureVerificationCheck = false
    @State var runtimeCheck = false
    
    @State var errorCheck = false
    @State var nErrorCheck = false
    @State var bErrorCheck = false
    @State var errorCount = 0
    @State var nVerificationResult:String?
    @State var bVerificationResult:String?
    @State var iteration = 0
    @State var saveCount = 0
    @State var iCheck = false //iteration check
    
    var body: some View {
        ScrollView {
            Button("Start") {
                // start time
                startTime = Date()
                //MARK: Connect to WebSocket
                let wsDelegate = myWebSocket()
                let session = URLSession(configuration: .default, delegate: wsDelegate, delegateQueue: OperationQueue())
//                    let url = URL(string: "ws://localhost:8765")!
                let url = URL(string: "wss://4bd0-141-163-105-129.ngrok-free.app")!
                let wsTask = session.webSocketTask(with: url)
                wsTask.resume()     //connect to websocket
                
                //starting function
                requestParameters()
                
                //MARK: my Functions
                func close() {
                    let reason = "Closing connection".data(using: .utf8)
                    wsTask.cancel(with: .goingAway, reason: reason)
                }
                func requestParameters() {
                    print("Running the Setup\n")
                    //Send Request for parameters
                    rP1Time = Date() // request/receive Parameters 1 Time
                    let requestParamsDict = [
                        "request": "Public Parameters",
                        "message": "This is the iOS Client"
                    ]
                    let requestParamsJSON = dictionaryToJsonString(dictionary: requestParamsDict)
                    sendCount+=1
                    print("\nSending Message \(String(sendCount)):\n \(String(describing: requestParamsJSON))\n")
                    wsTask.send(.string(requestParamsJSON!)) { error in
                      if let error = error {
                        print("Error when sending a message \(error)\n")
                      }
                    }
                    //next step
                    receiveParameters()
                }
                func receiveParameters() {
                    //Receive Parameters
                    receiveCount += 1
                    wsTask.receive { result in
                        switch result {
                        case .success(let message):
                            switch message {
                            case .data(let data):
                                print("Data received \(data)\n")
                            case .string(let text):
                                print("Receiving Message \(receiveCount):\n\(text)\n)")
                                rP2Time = Date()
                                let receivedParameters = jsonStringToDictionary(jsonString: text)!
                                e_hex = receivedParameters["e_hex"] as? String
                                N_hex = receivedParameters["N_hex"] as? String

                                e = int_from_hex(hexString: e_hex!)
                                N = int_from_hex(hexString: N_hex!)
                                
                                print("Completed running the Setup\n")
                                paramCheck = true
                                prepExtract()
                            @unknown default:
                                print("Receiving Parameters Error: Unknown Default")
                            }
                        case .failure(let error):
                            print("Receiving Parameters Error: \(error)")
                        }
                    }
                }
                //prep before Extract
                func prepExtract(){
                    print("Running the Prep Extract operation\n")
                    ep1Time = Date()
                    userID = name.bytes.sha256()
                    
                    ep2Time = Date()
                    print("Completed running the Prep Extract operation\n")
                    prepExtractCheck = true
                    requestSecretKey()
                }
                //request secret key
                func requestSecretKey() {
                    print("Request Normal Secret Key\n")
                    sk1Time = Date()
                    let requestSkDict = [
                        "request": "User Secret Key",
                        "ID": userID!.toHexString(),
                        "N_hex": N_hex!,
                        "e_hex": e_hex!
                    ] as [String : Any]
                    
                    let requestSkJSON = dictionaryToJsonString(dictionary: requestSkDict)
                    
                    sendCount += 1
                    print("\nSending Message \(String(sendCount)):\n \(String(describing: requestSkJSON))\n")
                    wsTask.send(.string(requestSkJSON!)) { error in
                      if let error = error {
                        print("Error when sending a message \(error)\n")
                      }
                    }
                    
                    receiveSecretKey()
                }
                func receiveSecretKey() {
                    receiveCount += 1
                    wsTask.receive { result in
                        switch result {
                        case .success(let message):
                            switch message {
                            case .data(let data):
                                print("Data received \(data)\n")
                            case .string(let text):
                                print("Receiving Message \(receiveCount):\n\(text)\n)")
                                sk2Time = Date()
                                let receivedMSG = jsonStringToDictionary(jsonString: text)!
                                sk_hex = receivedMSG["sk"] as? String
                                sk = sk_hex!.hexa

                                print("Completed running the normal secret key extraction\n")
                                //next function
                                nIdentification1()
                            @unknown default:
                                print("Receiving Secret Key Error: Unknown Default")
                            }
                        case .failure(let error):
                            print("Receiving Secret Key Error: \(error)")
                        }
                    }
                }
                
                //MARK: Identification Phase
                //Sh identification
                func nIdentification1(){
                    nVerify1Time = Date()
                    y = generateRandomVal(N: N!)
                    Y = y?.power(e!, modulus: N!)
                    Y_hex = hex_from_int(intVal: Y!)
                    let verifyRequestDict = [
                        "request": "Sh Identification",
                        "ID": userID!.toHexString(),
                        "Y_hex": Y_hex,
                        "N_hex": N_hex!,
                        "e_hex": e_hex!
                    ]
                    let verifyRequestJSON = dictionaryToJsonString(dictionary: verifyRequestDict as [String : Any])
                    
                    nVerify2Time = Date()
                    sendCount += 1
                    print("\nSending Message \(String(sendCount)):\n \(String(describing: verifyRequestJSON))\n")
                    wsTask.send(.string(verifyRequestJSON!)) { error in
                      if let error = error {
                        print("Error when sending a Commitment \(error)\n")
                      }
                    }
                    print("Commitment has been sent")
                    nIdentification2()
                    
                }
                
                func nIdentification2() {
                    print("Receiving CHL\n")
                    receiveCount += 1
                    wsTask.receive { result in
                        switch result {
                        case .success(let message):
                            switch message {
                            case .data(let data):
                                print("Data received \(data)\n")
                            case .string(let text):
                                print("Receiving Message \(receiveCount):\n\(text)\n)")
                                nVerify3Time = Date()
                                c_hex = text
                                c = int_from_hex(hexString: c_hex!)
                                z = y!.power(c!, modulus: N!).multiplied(by: BigUInteger(Data(sk))).power(1, modulus: N!)
                                z_hex = hex_from_int(intVal: z!)
                                print("Generated Response z_hex = \(String(describing: z_hex))")
                                //insert next function
                                nIdentification3()
                                
                            @unknown default:
                                print("Receiving Blind Secret Key Error: Unknown Default")
                            }
                        case .failure(let error):
                            print("Receiving Blind Secret Key Error: \(error)")
                        }
                    }
                }
                func nIdentification3() {
                    print("Sending Response")
                    nVerify4Time = Date()
                    sendCount += 1
                    print("\nSending Message \(String(sendCount)):\n \(String(describing: z_hex))\n")
                    wsTask.send(.string(z_hex!)) { error in
                      if let error = error {
                        print("Error when sending a Commitment \(error)\n")
                      }
                    }
                    print("Response has been sent")
                    //next function
                    nIdentification4()
                    
                }
                func nIdentification4() {
                    print("Receving Verification Result")
                    receiveCount += 1
                    wsTask.receive { result in
                        switch result {
                        case .success(let message):
                            switch message {
                            case .data(let data):
                                print("Data received \(data)\n")
                            case .string(let text):
                                print("Receiving Message \(receiveCount):\n\(text)\n)")
                                nVerify5Time = Date()
                                if text == "Success" {
                                    print("Iteration \(String(iteration)) Normal User Verification Successful :)")
                                    
                                    nVerificationCheck = true
                                    nVerificationResult = "Success"
                                    //insert next function
                                    bIdentification1()
                                }
                                else if text == "Failure" {
                                    print("Iteration \(String(iteration)) Normal User Verification Failed :(")
                                    nFailureVerificationCheck = true
                                    errorCheck = true
                                    nErrorCheck = true
                                    nVerificationResult = "Failure"
                                    //insert next function
                                    bIdentification1()
                                }
                                else {
                                    print("Unknown = \(text)")
                                    errorCheck = true
                                    nVerificationResult = "Failure"
                                }
                                
                                
                            @unknown default:
                                print("Receiving Blind Secret Key Error: Unknown Default")
                            }
                        case .failure(let error):
                            print("Receiving Blind Secret Key Error: \(error)")
                        }
                    }
                }
                
                // Sh* Identification
                func bIdentification1(){
                    bVerify1Time = Date()
                    by = generateRandomVal(N: N!)
                    bY = by?.power(e!, modulus: N!)
                    bY_hex = hex_from_int(intVal: bY!)
                    let verifyRequestDict = [
                        "request": "Sh* Identification",
                        "ID": userID!.toHexString(),
                        "Y_hex": bY_hex,
                        "N_hex": N_hex!,
                        "e_hex": e_hex!
                    ]
                    let verifyRequestJSON = dictionaryToJsonString(dictionary: verifyRequestDict as [String : Any])
                    
                    bVerify2Time = Date()
                    sendCount += 1
                    print("\nSending Message \(String(sendCount)):\n \(String(describing: verifyRequestJSON))\n")
                    wsTask.send(.string(verifyRequestJSON!)) { error in
                      if let error = error {
                        print("Error when sending a Commitment \(error)\n")
                      }
                    }
                    print("Commitment has been sent")
                    bIdentification2()
                    
                }
                
                func bIdentification2() {
                    print("Receiving CHL\n")
                    receiveCount += 1
                    wsTask.receive { result in
                        switch result {
                        case .success(let message):
                            switch message {
                            case .data(let data):
                                print("Data received \(data)\n")
                            case .string(let text):
                                print("Receiving Message \(receiveCount):\n\(text)\n)")
                                bVerify3Time = Date()
                                bc_hex = text
                                bc = int_from_hex(hexString: bc_hex!)
                                bz = by!.power(bc!, modulus: N!).multiplied(by: BigUInteger(Data(sk))).power(1, modulus: N!)
                                bz_hex = hex_from_int(intVal: bz!)
                                print("Generated Response bz_hex = \(String(describing: bz_hex))")
                                //insert next function
                                bIdentification3()
                                
                            @unknown default:
                                print("Receiving Blind Secret Key Error: Unknown Default")
                            }
                        case .failure(let error):
                            print("Receiving Blind Secret Key Error: \(error)")
                        }
                    }
                }
                func bIdentification3() {
                    print("Sending Response")
                    bVerify4Time = Date()
                    sendCount += 1
                    print("\nSending Message \(String(sendCount)):\n \(String(describing: bz_hex))\n")
                    wsTask.send(.string(bz_hex!)) { error in
                      if let error = error {
                        print("Error when sending a Commitment \(error)\n")
                      }
                    }
                    print("Response has been sent")
                    //next function
                    bIdentification4()
                    
                }
                func bIdentification4() {
                    print("Receving Verification Result")
                    receiveCount += 1
                    wsTask.receive { result in
                        switch result {
                        case .success(let message):
                            switch message {
                            case .data(let data):
                                print("Data received \(data)\n")
                            case .string(let text):
                                print("Receiving Message \(receiveCount):\n\(text)\n)")
                                bVerify5Time = Date()
                                if text == "Success" {
                                    print("Iteration \(String(iteration)) Blind User Verification Successful :)")
                                    bVerificationCheck = true
                                    bVerificationResult = "Success"
                                    //insert next function
                                    runtimeResults()
                                }
                                else if text == "Failure" {
                                    print("Iteration \(String(iteration)) Blind User Verification Failed :(")
                                    bVerificationResult = "Failure"
                                    errorCheck = true
                                    bErrorCheck = true
                                    //insert next function
                                    runtimeResults()
                                }
                                else {
                                    print("Unknown = \(text)")
                                    bVerificationResult = "Failure"
                                    errorCheck = true
                                }
                                
                                
                            @unknown default:
                                print("Receiving Blind Secret Key Error: Unknown Default")
                            }
                        case .failure(let error):
                            print("Receiving Blind Secret Key Error: \(error)")
                        }
                    }
                }
                
                func runtimeResults() {
                    endTime = Date()
                    print("Runtimes are as follows\n")
                    totalTime = myRuntime(begin: startTime, end: endTime)
                    connectWebsocketTime = myRuntime(begin: startTime, end: rP1Time)
                    requestParamTime = myRuntime(begin: rP1Time, end: rP2Time)
                    generatePKTime = myRuntime(begin: ep1Time, end: ep2Time)
                    
                    requestSecretKeyTime = myRuntime(begin: sk1Time, end: sk2Time)
                   
                    
                    nGenerateCMTTime = myRuntime(begin: nVerify1Time, end: nVerify2Time)
                    nReceiveCHLTime = myRuntime(begin: nVerify2Time, end: nVerify3Time)
                    nGenerateRSPTime = myRuntime(begin: nVerify3Time, end: nVerify4Time)
                    nReceiveVerificationTime = myRuntime(begin: nVerify4Time, end: nVerify5Time)
                    nTotalVerificationTime = myRuntime(begin: nVerify1Time, end: nVerify5Time)
                    
                    bGenerateCMTTime = myRuntime(begin: bVerify1Time, end: bVerify2Time)
                    bReceiveCHLTime = myRuntime(begin: bVerify2Time, end: bVerify3Time)
                    bGenerateRSPTime = myRuntime(begin: bVerify3Time, end: bVerify4Time)
                    bReceiveVerificationTime = myRuntime(begin: bVerify4Time, end: bVerify5Time)
                    bTotalVerificationTime = myRuntime(begin: bVerify1Time, end: bVerify5Time)
                    
                    print("Total Time = \(String(totalTime))")
                    print("Connect to Websocket = \(String(connectWebsocketTime))")
                    print("requestParamTime = \(String(requestParamTime))")
                    print("Generate public key = \(String(generatePKTime))")
                    
                    print("")
                    
                    print("Extract Time for the user = \(String(requestSecretKeyTime))")
                    
                    print("\n")
                    
                    print("Sh Identification:")
                    print("Generate CMT time = \(String(nGenerateCMTTime))")
                    print("Send CMT and Receive CHL Time = \(String(nReceiveCHLTime))")
                    print("Generate RSP = \(String(nGenerateRSPTime))")
                    print("Send RSP and receive Verification = \(String(nReceiveVerificationTime))")
                    print("Identification Total Time = \(String(nTotalVerificationTime))")
                    
                    print("")
                    
                    print("Sh* Identification:")
                    print("Generate CMT time = \(String(bGenerateCMTTime))")
                    print("Send CMT and Receive CHL Time = \(String(bReceiveCHLTime))")
                    print("Generate RSP = \(String(bGenerateRSPTime))")
                    print("Send RSP and receive Verification = \(String(bReceiveVerificationTime))")
                    print("Identification Total Time = \(String(bTotalVerificationTime))")
                    
                    runtimeCheck = true
                }
                
            }.buttonStyle(.borderedProminent).controlSize(.large).padding(.all)
            if paramCheck {
                VStack {
                    Text("N_hex = " + N_hex!)
                                .padding(.vertical)
                    Text("e_hex = " + e_hex!)
                        .padding(.vertical)
                    Text("N = " + String(N!))
                                .padding(.vertical)
                    Text("e = " + String(e!))
                        .padding(.vertical)
                }
            }
            if prepExtractCheck {
                VStack {
                    Text("Name = \(name)").padding(.all)
                    Text("User ID = \(userID!.toHexString())").padding(.all)
                    
                }
            }
            if secretKeyCheck {
                VStack {
                    Text("sk = " + sk_hex!).padding(.all)
                }
            }
            if nVerificationCheck {
                VStack {
                    Text(":) Normal Verification Successfull!!!!!").padding(.all)
                }
            }
            if nFailureVerificationCheck {
                VStack {
                    Text(":( Normal Verification Unsuccessfull!!!!!").padding(.all)
                }
            }
            if bVerificationCheck {
                VStack {
                    Text(":) Blind Verification Successfull!!!!!").padding(.all)
                }
            }
            if bFailureVerificationCheck {
                VStack {
                    Text(":( Blind Verification Unsuccessfull!!!!!").padding(.all)
                }
            }
            
            if runtimeCheck {
                VStack {
                    Text("Total Time = \(String(totalTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Connect to Websocket = \(String(connectWebsocketTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("requestParamTime = \(String(requestParamTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Generate public key = \(String(generatePKTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    
                }
                VStack {
                    Text("Extract using userID = \(String(requestSecretKeyTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    
                }
                VStack {
                    
                    Text("Sh Identification:").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.orange, lineWidth: 4))
                    Text("Generate CMT time = \(String(nGenerateCMTTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Send CMT and Receive CHL Time = \(String(nReceiveCHLTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Generate RSP = \(String(nGenerateRSPTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Send RSP and receive Verification = \(String(nReceiveVerificationTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Identification Total Time = \(String(nTotalVerificationTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    
                }
                VStack {
                    
                    Text("Sh* Identification:").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.orange, lineWidth: 4))
                    Text("Generate CMT time = \(String(bGenerateCMTTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Send CMT and Receive CHL Time = \(String(bReceiveCHLTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Generate RSP = \(String(bGenerateRSPTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Send RSP and receive Verification = \(String(bReceiveVerificationTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Identification Total Time = \(String(bTotalVerificationTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                }
            }
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
