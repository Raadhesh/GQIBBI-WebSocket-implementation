//
//  ContentView.swift
//  GQ-IBBI
//
//  Created by Raadhesh Kannan on 06/04/2024.
//

import SwiftUI
import CryptoSwift

// Screen width.
public var screenWidth: CGFloat {
    return UIScreen.main.bounds.width
}

//Setup variables
var e:BigUInteger?
var d:BigUInteger?
var N:BigUInteger?

//Time Taken variables
var setupTime:Double = 0
var generatepkTime:Double = 0   //convert string to byte format and then hash format
var generatebpkTime:Double = 0  //convert given id to blind form
var generateSKTime:Double = 0   //time to generate sk from pk
var getBSKTime:Double = 0       //time to get bsk from server
var getUSKTime:Double = 0       //time to perform unblind operation on bsk to get sk
var normalIdentificationTime: Double = 0    //time taken for identification protocol using pk and sk
var blindIdentificationTime: Double = 0     //time taken for identification protocol using bpk and bsk.


//all variables used
var name:String = ""
var byteName: Array<UInt8> = name.bytes      //Username converted to byte format
var userID: Array<UInt8> = byteName.sha256()            //Hash of Username and public key
var r: BigUInteger = 0
var tempR: BigUInteger = 0
var blindID: Array<UInt8> = name.bytes  //Result of blind operation on userID and blind public key

var sigma: Array<UInt8> = name.bytes   // secret key
var bSigma: Array<UInt8> = name.bytes  // blind secret key
var uSigma: Array<UInt8> = name.bytes  // unblinded secret key





struct ContentView: View {
    // Input Username||ID
    @State var nameTextField = "Raadhesh"
    // Boolean Checks
    @State var setupCheck = false
    @State var clearExtractCheck = false
    @State var getSKCheck = false
    @State var nIdentificationCheck = false
    @State var bIdentificationCheck = false
    
    var body: some View {
        ScrollView{
            VStack {
                Image(systemName: "globe")
                    .imageScale(.large)
                    .foregroundStyle(.tint)
                Text("Hello, world!").padding(.all)
                
                //Setup
                VStack{
                    Button("Setup"){
                        let startTime = Date()
                        //setup code
                        print("Running setup code...\n")
                        (setupCheck,e,d,N) = setRSAParameters(keySize: 256)
                        setupTime = Date().timeIntervalSince(startTime)
                        print("Finished running setup code\n")
                        
                    }.padding(.all)
                    
                    if setupCheck{
                        VStack {
                            Text("e = " + String(e!)).padding(.vertical)
                            Text("d = " + String(d!)).padding(.vertical)
                            Text("N = " + String(N!)).padding(.vertical)
                            Text("Runtime = " + String(setupTime)).padding(.vertical)
                        }
                    }
                    
                }
                // PreExtract
                if setupCheck {
                    TextField("Enter your String ID", text: $nameTextField).padding(.all)
                    Button("Confirm ID"){
                        print("Running the Pre Extract operation\n")
                        let startTime = Date()
                        name = nameTextField
                        byteName = name.bytes
                        userID = byteName.sha256()
                        generatepkTime = Date().timeIntervalSince(startTime)
                        
                        let start2Time = Date()
                        r = generateRandomVal(N: N!)
                        blindID = blindFunc(randomVal: r, messageBytes: userID, e: e!, N: N!)
                        generatebpkTime = Date().timeIntervalSince(start2Time)
                        
                        print("Completed running the Pre Extract operation\n")
                        print("generatebpkTime value = " + String(generatebpkTime))
                        clearExtractCheck = true
                    }.padding(.all)
                    
                    if clearExtractCheck {
                        VStack {
                            Text("name = " + String(name)).padding(.vertical)
                            Text("byteName = " + String(byteName.toHexString())).padding(.vertical)
                            Text("userID (sha256) = " + String(userID.toHexString())).padding(.vertical)
                            Text("Runtime to get userID = " + String(generatepkTime)).padding(.vertical)
                            
                            Text("Random Value r = " + String(r)).padding(.vertical)
                            Text("blindID = " + String(blindID.toHexString())).padding(.vertical)
                            Text("Runtime to convert userID to blindID = " + String(generatebpkTime)).padding(.vertical)
                        }.padding(.vertical)
                    }
                }
                // Extract Portion
                if clearExtractCheck {
                    HStack {
                        Button("Secret key") {
                            print("Running get secret key\n")
                            let startTime = Date()
                            sigma = signKGC(d: d!, N: N!, message: userID)
                            generateSKTime = Date().timeIntervalSince(startTime)
                            print("Secret key from userID = " + sigma.toHexString())
                            print("Completed running get secret key\n)")
                        }.frame(width: 150.0, height: 50.0).border(/*@START_MENU_TOKEN@*/Color.orange/*@END_MENU_TOKEN@*/, width: /*@START_MENU_TOKEN@*/2/*@END_MENU_TOKEN@*/)
                        Button("Blind secret key") {
                            print("Running get blind secret key and unblind blind secret key\n")
                            let start1Time = Date()
                            bSigma = signKGC(d: d!, N: N!, message: blindID)
                            getBSKTime = Date().timeIntervalSince(start1Time)
                            print("Secret key from userID = " + bSigma.toHexString())
                            print("Completed running get blind secret key\n)")
                            let start2Time = Date()
                            uSigma = unBlindFunc(randomVal: r, blindedMessageBytes: bSigma, e: e!, N: N!)
                            getUSKTime = Date().timeIntervalSince(start2Time)
                            print("Completed unblinding blind secret key\n)")
                            getSKCheck = true
                        }.frame(width: 150.0, height: 50.0).border(/*@START_MENU_TOKEN@*/Color.orange/*@END_MENU_TOKEN@*/, width: /*@START_MENU_TOKEN@*/2/*@END_MENU_TOKEN@*/)
                    }
                    if getSKCheck {
                        VStack {
                            Text("sk (sigma) = " + String(sigma.toHexString())).padding(.vertical)
                            Text("Runtime to get sk from userID = " + String(generateSKTime))
                            
                            Text("blind sk (bSigma) = " + String(bSigma.toHexString())).padding(.vertical)
                            Text("Runtime to get sk from blindID = " + String(getBSKTime))
                            
                            Text("unblind sk (uSigma) = " + String(uSigma.toHexString())).padding(.vertical)
                            Text("Runtime to unblind bsk to sk = " + String(getUSKTime))
                        }
                    }
                }
                // Identification
                if getSKCheck{
                    HStack {
                        Button("Normal Identification") {
                            print("Running Normal Identification\n")
                            let startTime = Date()
                            nIdentificationCheck = identifyUser(e: e!, N: N!, userIdentity: userID, userSecretKey: sigma)
                            normalIdentificationTime = Date().timeIntervalSince(startTime)
                            print("Completed running normal identification\n")
                            
                        }.frame(width: 150.0, height: 50.0).border(/*@START_MENU_TOKEN@*/Color.orange/*@END_MENU_TOKEN@*/, width: /*@START_MENU_TOKEN@*/2/*@END_MENU_TOKEN@*/)
                        if nIdentificationCheck {
                            Text("Normal Identification Runtime = " + String(normalIdentificationTime))
                        }
                    }
                    HStack {
                        Button("Blind Identification") {
                            print("Running Blind Identification\n")
                            let startTime = Date()
                            bIdentificationCheck = identifyUser(e: e!, N: N!, userIdentity: blindID, userSecretKey: bSigma)
                            blindIdentificationTime = Date().timeIntervalSince(startTime)
                            print("Completed running normal identification\n")
                            
                        }.frame(width: 150.0, height: 50.0).border(/*@START_MENU_TOKEN@*/Color.orange/*@END_MENU_TOKEN@*/, width: /*@START_MENU_TOKEN@*/2/*@END_MENU_TOKEN@*/)
                        if bIdentificationCheck {
                            Text("Blind Identification Runtime = " + String(blindIdentificationTime))
                        }
                    }
                }
            }
        }
        
    }
}

#Preview {
    ContentView()
}
