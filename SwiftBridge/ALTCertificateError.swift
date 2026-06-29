//
//  ALTCertificateError.swift
//  AltSign
//
//  Created by Magesh K.
//

import Foundation

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
