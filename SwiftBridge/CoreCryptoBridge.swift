//
//  CoreCryptoBridge.swift
//  AltSign
//

import Foundation
import NativeBridge

public enum CoreCryptoBridge {

    // MARK: - SRP

    public final class SRP {

        private let ctx: native_bridge_ccsrp_ctx

        public init?() {
            verboseLog("[AltSign] CoreCryptoBridge.SRP.init started")
            guard let c = native_bridge_ccsrp_client_new() else {
                debugLog("[AltSign] CoreCryptoBridge.SRP.init failed: native_bridge_ccsrp_client_new returned null")
                return nil
            }
            self.ctx = c
            verboseLog("[AltSign] CoreCryptoBridge.SRP.init completed successfully")
        }

        deinit {
            verboseLog("[AltSign] CoreCryptoBridge.SRP.deinit deallocating context")
            native_bridge_ccsrp_client_free(ctx)
        }

        /// controlled escape hatch
        public var rawHandle: OpaquePointer {
            OpaquePointer(ctx)
        }

        public func exchangeSize() -> Int {
            Int(native_bridge_ccsrp_exchange_size(ctx))
        }

        public func startAuthentication() -> Data? {
            let size = exchangeSize()
            verboseLog("[AltSign] CoreCryptoBridge.SRP.startAuthentication starting. Exchange size: \(size)")
            var A = Data(count: size)

            let result = A.withUnsafeMutableBytes {
                native_bridge_ccsrp_client_start_authentication(
                    ctx,
                    $0.baseAddress,
                    nil
                )
            }

            if result == 0 {
                verboseLog("[AltSign] CoreCryptoBridge.SRP.startAuthentication succeeded. Public key size: \(A.count) bytes")
                return A
            } else {
                debugLog("[AltSign] CoreCryptoBridge.SRP.startAuthentication failed with native error: \(result)")
                return nil
            }
        }

        public func processChallenge(
            username: String,
            password: Data,
            salt: Data,
            serverPublicKey: Data
        ) -> Data? {

            let size =
                Int(native_bridge_ccsrp_get_session_key_length(ctx))

            verboseLog("""
            [AltSign] CoreCryptoBridge.SRP.processChallenge starting:
              • Username: \(username)
              • Password size: \(password.count) bytes
              • Salt size: \(salt.count) bytes
              • Server Public Key size: \(serverPublicKey.count) bytes
              • Session Key Length: \(size)
            """)

            var M1 = Data(count: size)

            let result = M1.withUnsafeMutableBytes { m1Bytes in
                salt.withUnsafeBytes { saltBytes in
                    serverPublicKey.withUnsafeBytes { bBytes in
                        password.withUnsafeBytes { pwdBytes in
                            native_bridge_ccsrp_client_process_challenge(
                                ctx,
                                saltBytes.baseAddress,
                                salt.count,
                                bBytes.baseAddress,
                                serverPublicKey.count,
                                username,
                                pwdBytes.baseAddress,
                                password.count,
                                m1Bytes.baseAddress
                            )
                        }
                    }
                }
            }

            if result == 0 {
                verboseLog("[AltSign] CoreCryptoBridge.SRP.processChallenge succeeded. M1 size: \(M1.count) bytes")
                return M1
            } else {
                debugLog("[AltSign] CoreCryptoBridge.SRP.processChallenge failed with native error: \(result)")
                return nil
            }
        }

        public func verifyServerProof(_ proof: Data) -> Bool {
            verboseLog("[AltSign] CoreCryptoBridge.SRP.verifyServerProof started. Proof size: \(proof.count) bytes")
            let result = proof.withUnsafeBytes {
                native_bridge_ccsrp_client_verify_session(
                    ctx,
                    $0.baseAddress
                ) != 0
            }
            verboseLog("[AltSign] CoreCryptoBridge.SRP.verifyServerProof validation result: \(result)")
            return result
        }

        public func sessionKey() -> Data? {
            verboseLog("[AltSign] CoreCryptoBridge.SRP.sessionKey requested")
            guard let ptr =
                native_bridge_ccsrp_get_session_key(ctx)
            else {
                debugLog("[AltSign] CoreCryptoBridge.SRP.sessionKey failed: native returned null session key pointer")
                return nil
            }

            let len =
                Int(native_bridge_ccsrp_get_session_key_length(ctx))

            let key = Data(bytes: ptr, count: len)
            verboseLog("[AltSign] CoreCryptoBridge.SRP.sessionKey retrieved. Key size: \(key.count) bytes")
            return key
        }
    }


    // MARK: - HMAC (SHA256)

    public static func hmacSHA256(
        key: Data,
        strings: [String]
    ) -> Data? {

        verboseLog("[AltSign] CoreCryptoBridge.hmacSHA256 started. Key size: \(key.count) bytes, strings: \(strings)")

        guard let di = native_bridge_ccsha256_di(),
              let ctx = native_bridge_cchmac_create(di)
        else {
            debugLog("[AltSign] CoreCryptoBridge.hmacSHA256 failed: native_bridge_cchmac_create returned null")
            return nil
        }

        defer { native_bridge_cchmac_free(ctx) }

        key.withUnsafeBytes {
            native_bridge_cchmac_init(
                ctx,
                di,
                $0.baseAddress,
                key.count
            )
        }

        for s in strings {
            s.withCString {
                native_bridge_cchmac_update(
                    ctx,
                    di,
                    $0,
                    strlen($0)
                )
            }
        }

        var out = Data(count: 32)

        out.withUnsafeMutableBytes {
            native_bridge_cchmac_final(
                ctx,
                di,
                $0.baseAddress
            )
        }

        verboseLog("[AltSign] CoreCryptoBridge.hmacSHA256 succeeded. Output size: \(out.count) bytes")
        return out
    }


    // MARK: - PBKDF2

    public static func pbkdf2(
        digestInfo: UnsafeRawPointer,
        password: Data,
        salt: Data,
        rounds: Int,
        outputLength: Int
    ) -> Data? {

        verboseLog("[AltSign] CoreCryptoBridge.pbkdf2 started. Password size: \(password.count) bytes, salt size: \(salt.count) bytes, rounds: \(rounds), outputLength: \(outputLength)")

        var out = Data(count: outputLength)

        let result = out.withUnsafeMutableBytes { outBytes in
            password.withUnsafeBytes { pwdBytes in
                salt.withUnsafeBytes { saltBytes in

                    native_bridge_ccpbkdf2_hmac(
                        digestInfo,
                        pwdBytes.baseAddress?
                            .assumingMemoryBound(to: CChar.self),
                        password.count,
                        saltBytes.baseAddress,
                        salt.count,
                        UInt32(rounds),
                        outBytes.baseAddress,
                        outputLength
                    )
                }
            }
        }

        if result == 0 {
            verboseLog("[AltSign] CoreCryptoBridge.pbkdf2 succeeded. Output size: \(out.count) bytes")
            return out
        } else {
            debugLog("[AltSign] CoreCryptoBridge.pbkdf2 failed with native error: \(result)")
            return nil
        }
    }
    
    
    // MARK: - Digest (SHA256)

    public static func sha256(_ data: Data) -> Data? {
        verboseLog("[AltSign] CoreCryptoBridge.sha256 started. Data size: \(data.count) bytes")

        var out = Data(count: 32)

        let result = out.withUnsafeMutableBytes { outBytes in
            data.withUnsafeBytes { inBytes in
                native_bridge_ccdigest_sha256(
                    inBytes.baseAddress,
                    data.count,
                    outBytes.baseAddress
                )
            }
        }

        if result == 0 {
            verboseLog("[AltSign] CoreCryptoBridge.sha256 succeeded. Hash: \(out.hexEncodedString())")
            return out
        } else {
            debugLog("[AltSign] CoreCryptoBridge.sha256 failed with native error: \(result)")
            return nil
        }
    }
    
    
    public static func pbkdf2SHA256(
        password: Data,
        salt: Data,
        rounds: Int,
        outputLength: Int
    ) -> Data? {

        verboseLog("[AltSign] CoreCryptoBridge.pbkdf2SHA256 started")

        guard let di = native_bridge_ccsha256_di() else {
            debugLog("[AltSign] CoreCryptoBridge.pbkdf2SHA256 failed: native ccsha256_di returned null")
            return nil
        }

        return pbkdf2(
            digestInfo: di,
            password: password,
            salt: salt,
            rounds: rounds,
            outputLength: outputLength
        )
    }
    
    // MARK: - AES CBC
 
    public static func aesCBCDecrypt(
        key: Data,
        iv: Data,
        ciphertext: Data
    ) -> Data? {

        verboseLog("""
        [AltSign] CoreCryptoBridge.aesCBCDecrypt started:
          • Key size: \(key.count) bytes
          • IV size: \(iv.count) bytes
          • Ciphertext size: \(ciphertext.count) bytes
        """)

        var out = Data(count: ciphertext.count)
        var outLen = 0

        let result = out.withUnsafeMutableBytes { outBytes in
            ciphertext.withUnsafeBytes { inBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in

                        native_bridge_aes_cbc_pkcs7_decrypt(
                            keyBytes.baseAddress,
                            key.count,
                            ivBytes.baseAddress,
                            inBytes.baseAddress,
                            ciphertext.count,
                            outBytes.baseAddress,
                            &outLen
                        )
                    }
                }
            }
        }

        if result == 0 {
            let decrypted = out.prefix(outLen)
            verboseLog("[AltSign] CoreCryptoBridge.aesCBCDecrypt succeeded. Decrypted size: \(decrypted.count) bytes")
            return decrypted
        } else {
            debugLog("[AltSign] CoreCryptoBridge.aesCBCDecrypt failed with native error: \(result)")
            return nil
        }
    }
    
    // MARK: - AES GCM

    public static func aesGCMDecrypt(
        key: Data,
        nonce: Data,
        aad: Data,
        ciphertext: Data,
        tag: Data
    ) -> Data? {

        verboseLog("""
        [AltSign] CoreCryptoBridge.aesGCMDecrypt started:
          • Key size: \(key.count) bytes
          • Nonce size: \(nonce.count) bytes
          • AAD size: \(aad.count) bytes
          • Ciphertext size: \(ciphertext.count) bytes
          • Tag size: \(tag.count) bytes
        """)

        var out = Data(count: ciphertext.count)

        let result = out.withUnsafeMutableBytes { outBytes in
            ciphertext.withUnsafeBytes { ctBytes in
                key.withUnsafeBytes { keyBytes in
                    nonce.withUnsafeBytes { nonceBytes in
                        aad.withUnsafeBytes { aadBytes in
                            tag.withUnsafeBytes { tagBytes in

                                native_bridge_aes_gcm_decrypt(
                                    keyBytes.baseAddress,
                                    key.count,
                                    nonceBytes.baseAddress,
                                    nonce.count,
                                    aadBytes.baseAddress,
                                    aad.count,
                                    ctBytes.baseAddress,
                                    ciphertext.count,
                                    tagBytes.baseAddress,
                                    tag.count,
                                    outBytes.baseAddress
                                )
                            }
                        }
                    }
                }
            }
        }

        if result == 0 {
            verboseLog("[AltSign] CoreCryptoBridge.aesGCMDecrypt succeeded. Decrypted size: \(out.count) bytes")
            return out
        } else {
            debugLog("[AltSign] CoreCryptoBridge.aesGCMDecrypt failed with native error: \(result)")
            return nil
        }
    }
}

public extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
