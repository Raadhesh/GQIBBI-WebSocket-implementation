//
//  myCryptoFunction.swift
//  GQIBBI URLSessionWebSocket
//
//  Created by Raadhesh Kannan on 06/04/2024.
//

import Foundation
import CryptoSwift

//MARK: using the next two para to convert hexString to Array<UInt8> format
extension StringProtocol {
    var hexa: [UInt8] {
        var startIndex = self.startIndex
        return (0..<count/2).compactMap { _ in
            let endIndex = index(after: startIndex)
            defer { startIndex = index(after: endIndex) }
            return UInt8(self[startIndex...endIndex], radix: 16)
        }
    }
}
extension DataProtocol {
    var data: Data { .init(self) }
    var hexa: String { map { .init(format: "%02x", $0) }.joined() }
}
/*
 
 "0f00ff".hexa                 // [15, 0, 255]
 "0f00ff".hexa.data            // 3 bytes
 "0f00ff".hexa.data.hexa       // "0f00ff"
 "0f00ff".hexa.data as NSData  // <0f00ff>
 
 */

// MARK: Conversion Between BigUInt and HexString
// Convert hexString to BigUInt
public func int_from_hex(hexString: String) -> BigUInteger {
//    return BigUInteger(hexString.hexaData)
    let tempData = Data(hex: hexString)
    
    if hexString == "10001"{    // MARK: Error in Swift 5 where when I convert 10001 (hex) to 1048577 (int) instead of 65537 (int)
        print("\n\nWrong int value from " + hexString + " = " + String(BigUInteger(tempData)) + " which is what we are getting for some reason!")
        let result = BigUInteger(65537)
        print("Correct int value from " + hexString + " = " + String(result) + "\n\n")
        return result
        
    }
    else {
        return BigUInteger(tempData)
    }
    
}
// Convert BigUInt to hexString
public func hex_from_int(intVal: BigUInteger) -> String {
    return intVal.serialize().bytes.toHexString()
}

// generate RSA parameters based on keySize.
public func setRSAParameters(keySize: Int) -> (Bool, BigUInteger, BigUInteger, BigUInteger) {
    let rsa_privateKey = try! RSA(keySize: keySize)    // generate rsa key
    return (true, rsa_privateKey.e, rsa_privateKey.d!, rsa_privateKey.n)
}

//Greatest Common Divisor Function
public func findGCD(num1: BigUInteger, num2: BigUInteger) -> BigUInteger {
    var x:BigUInteger = 0

   // Finding maximum number
   var y: BigUInteger = max(num1, num2)

   // Finding minimum number
   var z: BigUInteger = min(num1, num2)

   while z != 0 {
      x = y
      y = z
      z = x % y
   }
   return y
}

// Generate Random Val with conditions
public func generateRandomVal(N: BigUInteger) -> BigUInteger {
    var x:BigUInteger = BigUInteger.randomInteger(lessThan: N)
    while findGCD(num1: x, num2: N) != 1 && x > 0 {
        x = BigUInteger.randomInteger(lessThan: N)
    }
    return x
}

//return true if 2 BigInt values are equal
public func checkIfEqual(num1: BigUInteger, num2: BigUInteger) -> Bool {
    if num1 == num2 {
        return true
    } else {
        return false
    }
}

// Blind message using r value
public func blindFunc(randomVal: BigUInteger, messageBytes: Array<UInt8>, e: BigUInteger, N: BigUInteger) -> Array<UInt8> {
    let temp = randomVal.power(e, modulus: N)
    return BigUInteger(Data(messageBytes)).multiplied(by: temp).serialize().bytes
}

// Unblind message using r value
public func unBlindFunc(randomVal: BigUInteger, blindedMessageBytes: Array<UInt8>, e: BigUInteger, N: BigUInteger) -> Array<UInt8> {
    
    return (BigUInteger(Data(blindedMessageBytes)).multiplied(by: randomVal.inverse(N)!).power(1, modulus: N)).serialize().bytes
}

// Return secret key signed by the KGC with given string ID
public func signKGC(d: BigUInteger, N: BigUInteger, message: Array<UInt8>) -> Array<UInt8> {
    return BigUInteger(Data(message)).power(d, modulus: N).serialize().bytes
}

// Identification
public func identifyUser (e: BigUInteger, N: BigUInteger, userIdentity: Array<UInt8>, userSecretKey: Array<UInt8>) -> Bool {
    // Commitment
    let y = generateRandomVal(N: N)
    let Y = y.power(e, modulus: N)
    
    // Challenge
    let c = generateRandomVal(N: N)
    
    // Response
    let z = BigUInteger(Data(userSecretKey)).power(c, modulus: N).multiplied(by: y).power(1, modulus: N)
    
    // Check if User identity is valid
    let val1 = z.power(e, modulus: N)
    let val2 = BigUInteger(Data(userIdentity)).power(c, modulus: N).multiplied(by: Y).power(1, modulus: N)
    
    return checkIfEqual(num1: val1, num2: val2)
}
