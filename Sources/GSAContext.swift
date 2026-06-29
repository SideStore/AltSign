//
//  GSAContext.swift
//  AltSign
//
//  Created by Riley Testut on 8/15/20.
//  Copyright © 2020 Riley Testut. All rights reserved.
//

import Foundation
import SwiftBridge

class GSAContext
{
    let username: String
    let password: String

    /// salt (obtained from server)
    var salt: Data?

    /// B (Public)
    var serverPublicKey: Data?

    /// K
    var sessionKey: Data?

    var dsid: String?

    /// A (Public)
    private(set) var publicKey: Data?

    /// x (derived with KDF)
    private(set) var derivedPasswordKey: Data?

    /// M1
    private(set) var verificationMessage: Data?

    #if !MARKETPLACE
    private lazy var srp = CoreCryptoBridge.SRP()
    #endif

    init(username: String, password: String)
    {
        self.username = username
        self.password = password
    }
}

extension GSAContext
{
    func start() -> Data?
    {
        guard self.publicKey == nil else { return nil }

        self.publicKey = self.makeAKey()
        return self.publicKey
    }

    func makeVerificationMessage(iterations: Int, isHexadecimal: Bool) -> Data?
    {
        guard self.verificationMessage == nil else { return nil }
        guard let salt = self.salt,
              let serverPublicKey = self.serverPublicKey else { return nil }

        guard let derivedPasswordKey =
            self.makeX(
                password: self.password,
                salt: salt,
                iterations: iterations,
                isHexadecimal: isHexadecimal
            )
        else { return nil }

        self.derivedPasswordKey = derivedPasswordKey

        self.verificationMessage =
            self.makeM1(
                username: self.username,
                derivedPasswordKey: derivedPasswordKey,
                salt: salt,
                serverPublicKey: serverPublicKey
            )

        return self.verificationMessage
    }

    func verifyServerVerificationMessage(_ serverVerificationMessage: Data) -> Bool
    {
        #if MARKETPLACE
        return false
        #else
        guard !serverVerificationMessage.isEmpty else { return false }
        let isValid = srp?.verifyServerProof(serverVerificationMessage) ?? false
        if isValid {
            self.sessionKey = srp?.sessionKey()
        }
        return isValid
        #endif
    }

    func makeChecksum(appName: String) -> Data?
    {
        #if MARKETPLACE
        return nil
        #else

        guard let sessionKey = self.sessionKey,
              let dsid = self.dsid else { return nil }

        return CoreCryptoBridge.hmacSHA256(
            key: sessionKey,
            strings: ["apptokens", dsid, appName]
        )

        #endif
    }
}

internal extension GSAContext
{
    func makeHMACKey(_ string: String) -> Data
    {
        #if MARKETPLACE
        return Data()
        #else

        guard let key = srp?.sessionKey() else {
            return Data()
        }

        return CoreCryptoBridge.hmacSHA256(
            key: key,
            strings: [string]
        ) ?? Data()

        #endif
    }
}

private extension GSAContext
{
    func makeAKey() -> Data?
    {
        #if MARKETPLACE
        return nil
        #else
        return srp?.startAuthentication()
        #endif
    }

    func makeX(
        password: String,
        salt: Data,
        iterations: Int,
        isHexadecimal: Bool
    ) -> Data?
    {
        #if MARKETPLACE
        return nil
        #else

        guard let digest =
            CoreCryptoBridge.sha256(password.data(using: .utf8)!)
        else { return nil }

        let inputDigest: Data =
            isHexadecimal ? digest.hexadecimal() : digest

        return CoreCryptoBridge.pbkdf2SHA256(
            password: inputDigest,
            salt: salt,
            rounds: iterations,
            outputLength: digest.count
        )

        #endif
    }

    func makeM1(
        username: String,
        derivedPasswordKey x: Data,
        salt: Data,
        serverPublicKey B: Data
    ) -> Data?
    {
        #if MARKETPLACE
        return nil
        #else

        return srp?.processChallenge(
            username: username,
            password: x,
            salt: salt,
            serverPublicKey: B
        )

        #endif
    }
}

extension Data {

    /// Converts ASCII hex string data ("a1b2...") → raw bytes
    func hexadecimal() -> Data {

        var result = Data(capacity: count / 2)

        var buffer: UInt8 = 0
        var highNibble = true

        for byte in self {

            let value: UInt8

            switch byte {
            case 48...57:  value = byte - 48        // 0-9
            case 65...70:  value = byte - 55        // A-F
            case 97...102: value = byte - 87        // a-f
            default: continue
            }

            if highNibble {
                buffer = value << 4
            } else {
                buffer |= value
                result.append(buffer)
            }

            highNibble.toggle()
        }

        return result
    }
}
