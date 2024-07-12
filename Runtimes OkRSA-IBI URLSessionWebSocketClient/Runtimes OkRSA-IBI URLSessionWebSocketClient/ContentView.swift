//
//  ContentView.swift
//  Runtimes OkRSA-IBI URLSessionWebSocketClient
//
//  Created by Raadhesh Kannan on 21/06/2024.
//

import SwiftUI
import CryptoSwift

//iteration runs
let iterationRuns:Int = 1000
let urlText:String = "wss://24f9-141-163-105-129.ngrok-free.app"
//file store variables
let deviceName:String = UIDevice.current.name
let keySize:Int = 2048
let runtimeFileName = deviceName + "OkRSA WebSocket runtimes" + String(keySize) + ".txt"
let runtimePath = getDocumentDirectory().appendingPathComponent(runtimeFileName)

//1000 random names
let nameFilePath = Bundle.main.url(forResource: "NamesRandom1000", withExtension: "txt")
var namesArray:[String] = []

//Temp Runtime Date variables
var loopStartTime = Date()
var loopEndTime = Date()

var startTime = Date()
var endTime = Date()
var rP1Time = Date()
var rP2Time = Date()
var ep1Time = Date()        // extract start time
var ep2Time = Date()        // extract end time
var sk1Time = Date()       // secret key start time
var sk2Time = Date()       // secret key end time
// Sh Identification
var verify1Time = Date()   //generate commitment
var verify2Time = Date()   //send commitment
var verify3Time = Date()   //receive response
var verify4Time = Date()   //send response
var verify5Time = Date()   //receive verification result

//Runtime variables
var iterationRuntime:Double = 0
var connectWebsocketTime:Double = 0
var requestParamTime:Double = 0
var generatePKTime:Double = 0
var preExtractTime:Double = 0
//Extract
var requestSecretKeyTime:Double = 0
//Sh Identification
var generateCMTTime:Double = 0
var receiveCHLTime:Double = 0
var generateRSPTime:Double = 0
var receiveVerificationTime:Double = 0
var totalVerificationTime:Double = 0

var totalRuntime:Double = 0

//MARK: Global variables
//message count
var sendCount = 0
var receiveCount = 0
//parameters
var e:BigUInteger?
var N:BigUInteger?
var g:BigUInteger?
var e_hex:String?
var N_hex:String?
var g_hex:String?
//public key and blind public key
var name:String = "Raadhesh"
// userID is equal to X in OkRSA-SI scheme
var userID: Array<UInt8>?       //Hash of Username and public key

//secret key
var sk1: Array<UInt8> = name.bytes   // secret key
var sk1_hex:String?
var x1: BigUInteger?
var sk2: Array<UInt8> = name.bytes   // secret key
var sk2_hex:String?
var x2: BigUInteger?
//OkRSA identification
var y1:BigUInteger?
var y2:BigUInteger?
var Y:BigUInteger?
var Y_hex:String?
var c_hex:String?
var c:BigUInteger?
var z1:BigUInteger?
var z1_hex:String?
var z2:BigUInteger?
var z2_hex:String?


struct ContentView: View {
    //MARK: display checks
    @State var paramCheck = false
    @State var prepExtractCheck = false
    @State var secretKeyCheck = false
    @State var verificationCheck = false
    @State var failureVerificationCheck = false
    @State var runtimeCheck = false
    
    @State var errorCheck = false
    @State var errorCount = 0
    @State var verificationResult:String?
    @State var iteration = 0
    @State var saveCount = 0
    @State var iCheck = false //iteration check
    
    var body: some View {
        ScrollView {
            VStack {
                Button("Start") {
                    loopStartTime = Date()
                    let initialString = "Number;IterationTime;Name;Get Parameters Time; Generate Public Key Time;Extract Time;Generate CMT Time;Send CMT and Receive CHL Time;Generate RSP;Send RSP and Receive Verification Time;Identification Total Time;Verfication Result\n"
                    do {
                        try initialString.write(to: runtimePath, atomically: true, encoding: String.Encoding.utf8)
                        print("String has been sucessfully saved to the created new file " + runtimeFileName)
                        
                    } catch {
                        print("Initial File save error")
                    }
                    // MARK: 1000 random names are read into a String Array
                    do {
                        let data = try String(contentsOf: nameFilePath!, encoding: .utf8)
                        namesArray = data.components(separatedBy: .newlines)
                        print("\nNames have been loaded to String array called namesArray\n")
                        
                    } catch {
                        print("\nError in reading Names file")
                    }
                    //MARK: Connect to WebSocket
                    let wsDelegate = myWebSocket()
                    let session = URLSession(configuration: .default, delegate: wsDelegate, delegateQueue: OperationQueue())
//                    let url = URL(string: "ws://localhost:8765")!
                    let url = URL(string: urlText)!
                    let wsTask = session.webSocketTask(with: url)
                    wsTask.resume()     //connect to websocket
                    
                    //starting function
                    loopStartFunc()
                    
                    
                    //MARK: my Functions
                    func close() {
                        let reason = "Closing connection".data(using: .utf8)
                        wsTask.cancel(with: .goingAway, reason: reason)
                        
                        loopEndTime = Date()
                        let loopTime = myRuntime(begin: loopStartTime, end: loopEndTime)
                        print("\n\n\n\n\nPROGRAM HAS ENDED")
                        print("ERROR COUNTS = \(String(errorCount))")
                        print("Total Time Taken = \(String(loopTime))\n\n\n\n")
                        
                    }
                    
                    //MARK: Starting Function
                    func loopStartFunc() {
                        if saveCount != iterationRuns {
                            iteration += 1
                            if iteration > 1000 {
                                iteration -= 1000
                            }
                            //reset checks to false
                            paramCheck = false
                            prepExtractCheck = false
                            secretKeyCheck = false
                            verificationCheck = false
                            failureVerificationCheck = false
                            
                            runtimeCheck = false
                            errorCheck = false
                            iCheck = false
                            sendCount = 0
                            receiveCount = 0
                            
                            print("\n\nIteration \(String(iteration)) is being run\n")
                            iCheck = true
//                            var namePosition = (iteration % 10) - 1
//                            if namePosition < 0 {
//                                namePosition = 9
//                            }
//                            name = namesArray[namePosition]
                            
                            name = namesArray[iteration - 1]
                            requestParameters()
                        } else {
                            close()
                        }
                    }
                    func requestParameters() {
                        startTime = Date()
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
                                    g_hex = receivedParameters["g_hex"] as? String
                                    
                                    e = int_from_hex(hexString: e_hex!)
                                    N = int_from_hex(hexString: N_hex!)
                                    g = int_from_hex(hexString: g_hex!)
                                    
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
                            "e_hex": e_hex!,
                            "g_hex": g_hex!
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
                                    sk1_hex = receivedMSG["sk1"] as? String
                                    sk1 = sk1_hex!.hexa
                                    x1 = BigUInteger(Data(sk1))
                                    sk2_hex = receivedMSG["sk2"] as? String
                                    sk2 = sk2_hex!.hexa
                                    x2 = BigUInteger(Data(sk2))

                                    print("Completed running the normal secret key extraction\n")
                                    //next function
                                    identification1()
                                @unknown default:
                                    print("Receiving Secret Key Error: Unknown Default")
                                }
                            case .failure(let error):
                                print("Receiving Secret Key Error: \(error)")
                            }
                        }
                    }
                    //MARK: Identification Phase
                    //OkRSA identification
                    func identification1(){
                        verify1Time = Date()
                        y1 = generateRandomVal(N: e!)
                        y2 = generateRandomVal(N: N!)
                        let tempA = g?.power(y1!, modulus: N!)
                        let tempB = y2?.power(e!, modulus: N!)
                        Y = tempA?.multiplied(by: tempB!)
                        Y = Y?.power(1, modulus: N!)
                        
                        Y_hex = hex_from_int(intVal: Y!)
                        let verifyRequestDict = [
                            "request": "OkRSA Identification",
                            "ID": userID!.toHexString(),
                            "Y_hex": Y_hex,
                            "N_hex": N_hex!,
                            "e_hex": e_hex!,
                            "g_hex": g_hex!
                        ]
                        let verifyRequestJSON = dictionaryToJsonString(dictionary: verifyRequestDict as [String : Any])
                        
                        verify2Time = Date()
                        sendCount += 1
                        print("\nSending Message \(String(sendCount)):\n \(String(describing: verifyRequestJSON))\n")
                        wsTask.send(.string(verifyRequestJSON!)) { error in
                          if let error = error {
                            print("Error when sending a Commitment \(error)\n")
                          }
                        }
                        print("Commitment has been sent")
                        identification2()
                        
                    }
                    
                    func identification2() {
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
                                    verify3Time = Date()
                                    c_hex = text
                                    c = int_from_hex(hexString: c_hex!)
                                    z1 = y1!.power(1, modulus: e!) + (x1!.multiplied(by: c!)).power(1, modulus: e!)
                                    z1 = z1!.power(1, modulus: e!)
                                    
                                    let (tess, _) = BigUInteger(y1! + (x1!.multiplied(by: c!))).quotientAndRemainder(dividingBy: e!)
                                    let tempA = g!.power(tess, modulus: N!)
                                    let tempB = x2!.power(c!, modulus: N!)
                                    z2 = tempA.multiplied(by: y2!).multiplied(by: tempB).power(1, modulus: N!)
                                    
                                    z1_hex = hex_from_int(intVal: z1!)
                                    z2_hex = hex_from_int(intVal: z2!)
                                    print("Generated Response z1_hex = \(String(describing: z1_hex))")
                                    print("Generated Response z2_hex = \(String(describing: z2_hex))")
                                    //insert next function
                                    identification3()
                                    
                                @unknown default:
                                    print("Receiving Blind Secret Key Error: Unknown Default")
                                }
                            case .failure(let error):
                                print("Receiving Blind Secret Key Error: \(error)")
                            }
                        }
                    }
                    
                    func identification3() {
                        print("Sending Response")
                        verify4Time = Date()
                        sendCount += 1
                        let responseDict = [
                            "request": "Response",
                            "z1_hex": z1_hex!,
                            "z2_hex": z2_hex!
                        ]
                        let responseJSON = dictionaryToJsonString(dictionary: responseDict as [String : Any])
                        
                        print("\nSending Message \(String(sendCount)):\n \(String(describing: responseJSON))\n")
                        wsTask.send(.string(responseJSON!)) { error in
                          if let error = error {
                            print("Error when sending a Commitment \(error)\n")
                          }
                        }
                        print("Response has been sent")
                        //next function
                        identification4()
                        
                    }
                    func identification4() {
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
                                    verify5Time = Date()
                                    if text == "Success" {
                                        print("Iteration \(String(iteration)) OkRSA User Verification Successful :)")
                                        
                                        verificationCheck = true
                                        verificationResult = "Success"
                                        //insert next function
                                        runtimeResults()
                                    }
                                    else if text == "Failure" {
                                        print("Iteration \(String(iteration)) OkRSA User Verification Failed :(")
                                        failureVerificationCheck = true
                                        errorCheck = true
                                        verificationResult = "Failure"
                                        //insert next function
                                        runtimeResults()
                                    }
                                    else {
                                        print("Unknown = \(text)")
                                        errorCheck = true
                                        verificationResult = "Failure"
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
                        iterationRuntime = myRuntime(begin: startTime, end: endTime)
                        connectWebsocketTime = myRuntime(begin: startTime, end: rP1Time)
                        requestParamTime = myRuntime(begin: rP1Time, end: rP2Time)
                        generatePKTime = myRuntime(begin: ep1Time, end: ep2Time)
                        
                        requestSecretKeyTime = myRuntime(begin: sk1Time, end: sk2Time)
                       
                        
                        generateCMTTime = myRuntime(begin: verify1Time, end: verify2Time)
                        receiveCHLTime = myRuntime(begin: verify2Time, end: verify3Time)
                        generateRSPTime = myRuntime(begin: verify3Time, end: verify4Time)
                        receiveVerificationTime = myRuntime(begin: verify4Time, end: verify5Time)
                        totalVerificationTime = myRuntime(begin: verify1Time, end: verify5Time)
                        
                        
                        print("Iteration \(String(iteration)) Runtime = \(String(iterationRuntime))")
                        print("Connect to Websocket = \(String(connectWebsocketTime))")
                        print("requestParamTime = \(String(requestParamTime))")
                        print("Generate public key = \(String(generatePKTime))")
                        
                        print("")
                        
                        print("Extract Time for the user = \(String(requestSecretKeyTime))")
                        
                        print("\n")
                        
                        print("OkRSA Identification:")
                        print("Generate CMT time = \(String(generateCMTTime))")
                        print("Send CMT and Receive CHL Time = \(String(receiveCHLTime))")
                        print("Generate RSP = \(String(generateRSPTime))")
                        print("Send RSP and receive Verification = \(String(receiveVerificationTime))")
                        print("Identification Total Time = \(String(totalVerificationTime))")
                        
                        print("")
                        
                        runtimeCheck = true
                        
                        if errorCheck {
                            errorCount += 1
                        }
                        else {
                            //MARK: File Update Section
                            saveCount += 1
                            let stringToWrite = String(saveCount) + ";" + String(iterationRuntime) + ";" + name + ";" + String(requestParamTime) + ";" + String(generatePKTime) + ";" +  String(requestSecretKeyTime) + ";" +  String(generateCMTTime) + ";" + String(receiveCHLTime) + ";" + String(generateRSPTime) + ";" + String(receiveVerificationTime) + ";" + String(totalVerificationTime) + ";" +  String(verificationResult!) + "\n"
                            do {
                                if let fileUpdater = try? FileHandle(forUpdating: runtimePath) {
                                    try fileUpdater.seekToEnd()
                                    try fileUpdater.write(contentsOf: Data(stringToWrite.utf8))
                                    try fileUpdater.close()
                                    print("Successfully updated Iteration \(String(iteration)) \(name) in " + runtimeFileName)
                                }
                            } catch {
                                print("Error with File Update " + String(iteration) + " " + name + "\n")
                            }
                        }
                        
                                                
                        
                        if saveCount < iterationRuns {
                            loopStartFunc()
                        } else {
                            close()
                        }
                    }
                }.buttonStyle(.borderedProminent).controlSize(.large).padding(.all)
            }
            //MARK: Display
            if iCheck {
                VStack {
                    Text("Save Count = \(String(saveCount))").padding(.all).underline(color: .red)
                    Text("Iteration \(String(iteration)) \(name)").padding(.all).underline(color: .cyan)
                }
            }
            if paramCheck {
                VStack {
                    Text("N_hex = " + N_hex!)
                                .padding(.vertical)
                    Text("N = " + String(N!))
                                .padding(.vertical)
                    Text("e = " + String(e!))
                        .padding(.vertical)
                    Text("e_hex = " + e_hex!)
                        .padding(.vertical)
                    Text("g_hex = " + g_hex!)
                                .padding(.vertical)
                    Text("g = " + String(g!))
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
                    Text("sk1 (x1) = " + String(x1!)).padding(.all)
                    Text("sk1_hex = " + sk1_hex!).padding(.vertical)
                    Text("sk2 (x2) = " + String(x2!)).padding(.all)
                    Text("sk2_hex = " + sk2_hex!).padding(.vertical)
                }
            }
            if verificationCheck {
                VStack {
                    Text(":) OkRSA Verification Successfull!!!!!").padding(.all)
                }
            }
            if failureVerificationCheck {
                VStack {
                    Text(":( OkRSA Verification Unsuccessfull!!!!!").padding(.all)
                }
            }
            
            if runtimeCheck {
                VStack {
                    Text("Iteration Runtime = \(String(iterationRuntime))").padding().overlay(
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
                    
                    Text("OkRSA Identification:").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.orange, lineWidth: 4))
                    Text("Generate CMT time = \(String(generateCMTTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Send CMT and Receive CHL Time = \(String(receiveCHLTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Generate RSP = \(String(generateRSPTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Send RSP and receive Verification = \(String(receiveVerificationTime))").padding().overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(.green, lineWidth: 4))
                    Text("Identification Total Time = \(String(totalVerificationTime))").padding().overlay(
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
