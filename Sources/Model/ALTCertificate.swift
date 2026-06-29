//
//  ALTCertificate.swift
//  AltSign
//

import Foundation
import SwiftBridge


public final class ALTCertificate: NSObject {

    // MARK: Properties

    public var name: String
    public var serialNumber: String

    public var identifier: String?
    public var machineName: String?
    public var machineIdentifier: String?
    public var requesterEmail: String?

    public var data: Data?
    public var privateKey: Data?

    // MARK: PEM

    private static let pemPrefix = "-----BEGIN CERTIFICATE-----"
    private static let pemSuffix = "-----END CERTIFICATE-----"

    // MARK: Designated Init

    init(name: String, serialNumber: String, data: Data?) {
        self.name = name
        self.serialNumber = serialNumber
        self.data = data
        super.init()
    }

    // MARK: Response Init

    public convenience init?(responseDictionary: [String: Any]) {

        let identifier = responseDictionary["id"] as? String
        let attributes =
            (responseDictionary["attributes"] as? [String: Any])
            ?? responseDictionary

        var certData: Data?

        if let data = attributes["certContent"] as? Data {
            certData = data
        }
        else if let base64 = attributes["certificateContent"] as? String {
            certData = Data(base64Encoded: base64)
        }

        let machineName =
            (attributes["machineName"] as? NSNull) == nil
            ? attributes["machineName"] as? String
            : nil

        let machineIdentifier =
            (attributes["machineId"] as? NSNull) == nil
            ? attributes["machineId"] as? String
            : nil

        if let certData {
            self.init(data: certData)
        } else {
            guard
                let name = attributes["name"] as? String,
                let serial =
                    (attributes["serialNumber"]
                     ?? attributes["serialNum"]) as? String
            else { return nil }

            self.init(name: name, serialNumber: serial, data: nil)
        }

        self.identifier = identifier
        self.machineName = machineName
        self.machineIdentifier = machineIdentifier
        self.requesterEmail = attributes["requesterEmail"] as? String
    }

    // MARK: P12 Init

    public convenience init(
        p12Data: Data,
        password: String?
    ) throws {
        guard p12Data.isPKCS12 else {
            throw ALTCertificateError.invalidFormat
        }

        let result = try OpenSSLBridge.extractPKCS12(p12Data, password: password)

        var pemData = result.cert

        if let prefix = String(
            data: pemData.prefix(Self.pemPrefix.count),
            encoding: .utf8
        ),
        prefix != Self.pemPrefix {
            let base64 = pemData.base64EncodedString(
                options: .lineLength64Characters
            )
            let content = "\(Self.pemPrefix)\n\(base64)\n\(Self.pemSuffix)"
            pemData = content.data(using: .utf8)!
        }

        guard let parsed = OpenSSLBridge.parseCertificate(pemData) else {
            throw ALTCertificateError.extractionFailed
        }

        var serial = parsed.serial
        if let idx = serial.firstIndex(where: { $0 != "0" }) {
            serial = String(serial[idx...])
        } else {
            throw ALTCertificateError.extractionFailed
        }

        self.init(
            name: parsed.name,
            serialNumber: serial,
            data: pemData
        )
        self.privateKey = result.key
    }

    // MARK: PEM Init

    public convenience init?(data: Data) {

        var pemData = data

        if let prefix = String(
            data: data.prefix(Self.pemPrefix.count),
            encoding: .utf8
        ),
        prefix != Self.pemPrefix {

            let base64 = data.base64EncodedString(
                options: .lineLength64Characters
            )

            let content =
            "\(Self.pemPrefix)\n\(base64)\n\(Self.pemSuffix)"

            pemData = content.data(using: .utf8)!
        }

        guard let parsed =
            OpenSSLBridge.parseCertificate(pemData)
        else { return nil }

        var serial = parsed.serial

        if let idx = serial.firstIndex(where: { $0 != "0" }) {
            serial = String(serial[idx...])
        } else {
            return nil
        }

        self.init(
            name: parsed.name,
            serialNumber: serial,
            data: pemData
        )
    }

    // MARK: NSObject

    public override var description: String {
        "<\(NSStringFromClass(Swift.type(of: self))): \(Unmanaged.passUnretained(self).toOpaque()), Name: \(name), SN: \(serialNumber)>"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? ALTCertificate else {
            return false
        }
        return serialNumber == other.serialNumber
    }

    public override var hash: Int {
        serialNumber.hashValue
    }

    // MARK: P12 Export

    public func p12Data() -> Data? {
        encryptedP12Data(password: "")
    }

    public func encryptedP12Data(password: String) -> Data? {

        guard
            let certData = data,
            let keyData = privateKey
        else { return nil }

        return OpenSSLBridge.createPKCS12(
            cert: certData,
            key: keyData,
            password: password
        )
    }

    public func encryptedP12Data(withPassword password: String) -> Data? {
        return self.encryptedP12Data(password: password)
    }
}

public extension Data {
    public var isPKCS12: Bool {
        guard self.count > 6 else { return false }
        guard self[0] == 0x30 else { return false } // Must be SEQUENCE
        
        // Parse ASN.1 length
        var offset = 1
        let lengthByte = self[offset]
        if lengthByte & 0x80 == 0 {
            // Short form length (1 byte)
            offset += 1
        } else {
            // Long form length
            let numLengthBytes = Int(lengthByte & 0x7F)
            guard self.count > 1 + numLengthBytes else { return false }
            offset += 1 + numLengthBytes
        }
        
        guard self.count > offset else { return false }
        return self[offset] == 0x02 // First element of PFX SEQUENCE must be INTEGER (version)
    }
}

public enum ALTCertificateError: LocalizedError {
    case invalidFormat      // Wrong ASN.1 tag sequence (e.g. raw certificate passed)
    case decryptionFailed   // Wrong password (MAC verify/generation failure)
    case extractionFailed   // General parsing or null pointer failure
    
    public var errorDescription: String? {
        switch self {
        case .invalidFormat: return "The data is not in PKCS12 format."
        case .decryptionFailed: return "Decryption failed. Please check if the password is correct."
        case .extractionFailed: return "Failed to extract certificate or private key from PKCS12 archive."
        }
    }
}
