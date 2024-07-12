//
//  ContentView.swift
//  GQIBBI URLSessionWebSocket
//
//  Created by Raadhesh Kannan on 06/04/2024.
//

import SwiftUI
import CryptoSwift

//Temp Runtime Date variables
var startTime = Date()
var endTime = Date()
var rP1Time = Date()
var rP2Time = Date()
var ep1Time = Date()        // normal part
var ep2Time = Date()        // normal part
var ep3Time = Date()        // blind part
var nsk1Time = Date()
var nsk2Time = Date()
var bsk1Time = Date()
var bsk2Time = Date()
var bsk3Time = Date()       //unblind part
var nVerify1Time = Date()   //generate commitment
var nVerify2Time = Date()   //send commitment
var nVerify3Time = Date()   //receive response
var nVerify4Time = Date()   //send response
var nVerify5Time = Date()   //receive verification result
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
var generateBPKTime:Double = 0
var preExtractTime:Double = 0
//Extract
var requestSecretKeyTime:Double = 0
var requestBlindSecretKeyTime:Double = 0
var unblindBlindSecretKeyTime:Double = 0
//Identification
var nGenerateCMTTime:Double = 0
var nReceiveCHLTime:Double = 0
var nGenerateRSPTime:Double = 0
var nReceiveVerificationTime:Double = 0
var nTotalVerificationTime:Double = 0
//Blind Identification
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
var r:BigUInteger?
var r_hex:String?
var blindID: Array<UInt8>?      //blind version of userID
//secret key
var nsk: Array<UInt8> = name.bytes   // secret key
var nsk_hex:String?
var bsk: Array<UInt8> = name.bytes  // blind secret key
var bsk_hex:String?
var usk: Array<UInt8> = name.bytes  // unblinded secret key
//normal identification
var y:BigUInteger?
var Y:BigUInteger?
var Y_hex:String?
var c_hex:String?
var c:BigUInteger?
var z:BigUInteger?
var z_hex:String?
//blind identification
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
    
    var body: some View {
        ScrollView {
            VStack {
                Button("Start") {
                    // start time
                    startTime = Date()
                    
                    //MARK: Connect to WebSocket
                    let wsDelegate = myWebSocket()
                    let session = URLSession(configuration: .default, delegate: wsDelegate, delegateQueue: OperationQueue())
//                    let url = URL(string: "ws://localhost:8765")!
                    let url = URL(string: "wss://cb93-141-163-105-129.ngrok-free.app")!
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
                    //prepare for Extract function
                    func prepExtract(){
                        print("Running the Prep Extract operation\n")
                        ep1Time = Date()
                        userID = name.bytes.sha256()
                        
                        ep2Time = Date()
                        
                        r = generateRandomVal(N: N!)
                        blindID = blindFunc(randomVal: r!, messageBytes: userID!, e: e!, N: N!)
                        
                        ep3Time = Date()
                        print("Completed running the Prep Extract operation\n")
                        prepExtractCheck = true
                        requestNSecretKey()
                    }
                    
                    //request normal secret key
                    func requestNSecretKey() {
                        print("Request Normal Secret Key\n")
                        nsk1Time = Date()
                        let requestNskDict = [
                            "request": "User Secret Key",
                            "ID": userID!.toHexString(),
                            "N_hex": N_hex!,
                            "e_hex": e_hex!
                        ] as [String : Any]
                        
                        let requestNskJSON = dictionaryToJsonString(dictionary: requestNskDict)
                        
                        sendCount += 1
                        print("\nSending Message \(String(sendCount)):\n \(String(describing: requestNskJSON))\n")
                        wsTask.send(.string(requestNskJSON!)) { error in
                          if let error = error {
                            print("Error when sending a message \(error)\n")
                          }
                        }
                        
                        receiveNSecretKey()
                    }
                    
                    func receiveNSecretKey() {
                        
                        receiveCount += 1
                        wsTask.receive { result in
                            switch result {
                            case .success(let message):
                                switch message {
                                case .data(let data):
                                    print("Data received \(data)\n")
                                case .string(let text):
                                    print("Receiving Message \(receiveCount):\n\(text)\n)")
                                    nsk2Time = Date()
                                    let receivedMSG = jsonStringToDictionary(jsonString: text)!
                                    nsk_hex = receivedMSG["sk"] as? String
                                    nsk = nsk_hex!.hexa

                                    print("Completed running the normal secret key extraction\n")
                                    requestBSecretKey()
                                @unknown default:
                                    print("Receiving Secret Key Error: Unknown Default")
                                }
                            case .failure(let error):
                                print("Receiving Secret Key Error: \(error)")
                            }
                        }
                    }
                    
                    //request blind secret key
                    func requestBSecretKey() {
                        print("Request Blind Secret Key\n")
                        bsk1Time = Date()
                        let requestBskDict = [
                            "request": "User Secret Key",
                            "ID": blindID!.toHexString(),
                            "N_hex": N_hex!,
                            "e_hex": e_hex!
                        ] as [String : Any]
                        
                        let requestBskJSON = dictionaryToJsonString(dictionary: requestBskDict)
                        
                        sendCount += 1
                        print("\nSending Message \(String(sendCount)):\n \(String(describing: requestBskJSON))\n")
                        wsTask.send(.string(requestBskJSON!)) { error in
                          if let error = error {
                            print("Error when sending a message \(error)\n")
                          }
                        }
                        
                        receiveBSecretKey()
                    }
                    
                    func receiveBSecretKey() {
                        
                        receiveCount += 1
                        wsTask.receive { result in
                            switch result {
                            case .success(let message):
                                switch message {
                                case .data(let data):
                                    print("Data received \(data)\n")
                                case .string(let text):
                                    print("Receiving Message \(receiveCount):\n\(text)\n)")
                                    bsk2Time = Date()
                                    let receivedMSG = jsonStringToDictionary(jsonString: text)!
                                    bsk_hex = receivedMSG["sk"] as? String
                                    bsk = bsk_hex!.hexa
                                    usk = unBlindFunc(randomVal: r!, blindedMessageBytes: bsk, e: e!, N: N!)
                                    if(usk == nsk){
                                        print("\nUnblinded secret key is equal to normal secret key!!!!!!\n")
                                    }
                                    bsk3Time = Date()
                                    print("Completed running the blind secret key extraction\n")
                                    secretKeyCheck = true
                                    //insert next function
                                    nIdentification1()
                                    
                                @unknown default:
                                    print("Receiving Blind Secret Key Error: Unknown Default")
                                }
                            case .failure(let error):
                                print("Receiving Blind Secret Key Error: \(error)")
                            }
                        }
                    }
                    //MARK: Identification Phase
                    func nIdentification1(){
                        nVerify1Time = Date()
                        y = generateRandomVal(N: N!)
                        Y = y?.power(e!, modulus: N!)
                        Y_hex = hex_from_int(intVal: Y!)
                        let verifyRequestDict = [
                            "request": "Identification",
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
                                    z = BigUInteger(Data(nsk)).power(c!, modulus: N!).multiplied(by: y!).power(1, modulus: N!)
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
                                        print("Normal User Verification Successful :)")
                                        nVerificationCheck = true
                                    }
                                    else if text == "Failure" {
                                        print("Normal User Verification Failed :(")
                                        nFailureVerificationCheck = true
                                        errorCheck = true
                                    }
                                    else {
                                        print("Unknown = \(text)")
                                        errorCheck = true
                                    }
                                    //insert next function
                                    bIdentification1()
                                    
                                @unknown default:
                                    print("Receiving Blind Secret Key Error: Unknown Default")
                                }
                            case .failure(let error):
                                print("Receiving Blind Secret Key Error: \(error)")
                            }
                        }
                    }
                    
                    // Blind Identification
                    func bIdentification1(){
                        bVerify1Time = Date()
                        by = generateRandomVal(N: N!)
                        bY = by?.power(e!, modulus: N!)
                        bY_hex = hex_from_int(intVal: bY!)
                        let verifyRequestDict = [
                            "request": "Identification",
                            "ID": blindID!.toHexString(),
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
                                    bz = BigUInteger(Data(bsk)).power(bc!, modulus: N!).multiplied(by: by!).power(1, modulus: N!)
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
                                        print("Blind User Verification Successful :)")
                                        bVerificationCheck = true
                                    }
                                    else if text == "Failure" {
                                        print("Blind User Verification Failed :(")
                                        bFailureVerificationCheck = true
                                        errorCheck = true
                                    }
                                    else {
                                        print("Unknown = \(text)")
                                        errorCheck = true
                                    }
                                    //insert next function
                                    runtimeResults()
                                    
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
                        generateBPKTime = myRuntime(begin: ep2Time, end: ep3Time)
                        preExtractTime = myRuntime(begin: ep1Time, end: ep3Time)
                        
                        requestSecretKeyTime = myRuntime(begin: nsk1Time, end: nsk2Time)
                        requestBlindSecretKeyTime = myRuntime(begin: bsk1Time, end: bsk2Time)
                        unblindBlindSecretKeyTime = myRuntime(begin: bsk2Time, end: bsk3Time)
                        
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
                        print("Generate Blind public key = \(String(generateBPKTime))")
                        print("Pre Extract Time = \(String(preExtractTime))")
                        
                        print("")
                        
                        print("Extract using userID = \(String(requestSecretKeyTime))")
                        print("Get Blind Secret Key = \(String(requestBlindSecretKeyTime))")
                        print("Unblind Blind Secret Key = \(String(unblindBlindSecretKeyTime))")
                        print("Extract using blindID = \(String(myRuntime(begin: bsk1Time, end: bsk3Time)))")
                        
                        print("\n")
                        
                        print("Normal Identification:")
                        print("Generate CMT time = \(String(nGenerateCMTTime))")
                        print("Send CMT and Receive CHL Time = \(String(nReceiveCHLTime))")
                        print("Generate RSP = \(String(nGenerateRSPTime))")
                        print("Send RSP and receive Verification = \(String(nReceiveVerificationTime))")
                        print("Identification Total Time = \(String(nTotalVerificationTime))")
                        
                        print("")
                        
                        print("Blind Identification:")
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
                        Text("Random Value = " + String(r!)).padding(.all)
                        Text("Blind ID = " + (blindID!.toHexString())).padding(.all)
                    }
                }
                if secretKeyCheck {
                    VStack {
                        Text("nsk = " + nsk_hex!).padding(.all)
                        Text("bsk = " + bsk_hex!).padding(.all)
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
                        Text("Generate Blind public key = \(String(generateBPKTime))").padding().overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(.green, lineWidth: 4))
                        Text("Pre Extract Time = \(String(preExtractTime))").padding().overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(.green, lineWidth: 4))
                    }
                    VStack {
                        Text("Extract using userID = \(String(requestSecretKeyTime))").padding().overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(.green, lineWidth: 4))
                        Text("Get Blind Secret Key = \(String(requestBlindSecretKeyTime))").padding().overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(.green, lineWidth: 4))
                        Text("Unblind Blind Secret Key = \(String(unblindBlindSecretKeyTime))").padding().overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(.green, lineWidth: 4))
                        Text("Extract using blindID = \(String(myRuntime(begin: bsk1Time, end: bsk3Time)))").padding().overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(.green, lineWidth: 4))
                        
                    }
                    VStack {
                        
                        Text("Normal Identification:").padding().overlay(
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
                        
                        Text("Blind Identification:").padding().overlay(
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
        }
        .padding()
    }
}



#Preview {
    ContentView()
}
