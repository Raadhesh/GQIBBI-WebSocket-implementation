//
//  myWebSocketFunctions.swift
//  Runtimes OkRSA-IBI URLSessionWebSocketClient
//
//  Created by Raadhesh Kannan on 21/06/2024.
//

import Foundation

//MARK: File store functions
// Get the Document Directory URL where we store our runtime file
func getDocumentDirectory() -> URL {
    return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
}

//MARK: Time Interval Function
func myRuntime(begin:Date, end: Date) -> Double {
    let temp1:Double = Date().timeIntervalSince(begin)
    let temp2:Double = Date().timeIntervalSince(end)
    let res:Double = temp1 - temp2
    return res
}


//MARK: Conversion Between JSON String and Dictionary
// Dictionary output from jsonString input
func jsonStringToDictionary(jsonString: String) -> [String: Any]? {
    guard let jsonData = jsonString.data(using: .utf8) else {
        return nil
    }
    
    do {
        let dictionary = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any]
        return dictionary
    } catch {
        print("Error converting JSON string to dictionary: \(error.localizedDescription)")
        return nil
    }
}
// jsonString output from Dictionary Input
func dictionaryToJsonString(dictionary: [String: Any]) -> String? {
    do {
        let jsonData = try JSONSerialization.data(withJSONObject: dictionary, options: [])
        if let jsonString = String(data: jsonData, encoding: .utf8) {
            return jsonString
        }
    } catch {
        print("Error converting dictionary to JSON string: \(error.localizedDescription)")
    }
    return nil
}


//MARK: WebSocket Class - using native WebSocket library URLSessionWebSocket

class myWebSocket: NSObject, URLSessionWebSocketDelegate {
    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        print("WebSocket did connect\n")
        
    }
    
    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        print("Web Socket did disconnect\n")
    }
}

