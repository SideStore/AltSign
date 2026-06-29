//
//  Data+Encryption.swift
//  AltSign
//

import Foundation
import NativeBridge

extension Data {
    private func hex() -> Data {
        let hexString = map { String(format: "%02hhx", $0) }.joined()
        return Data(hexString.utf8)
    }

    func decryptedCBC(context: GSAContext) -> Data? {
        let key = context.makeHMACKey("extra data key:")
        let iv = context.makeHMACKey("extra data iv:")

        let contiguousKey = key.startIndex == 0 ? key : Data(key)
        let contiguousIv = iv.startIndex == 0 ? iv : Data(iv)
        let contiguousSelf = self.startIndex == 0 ? self : Data(self)

        var decryptedData = Data(count: contiguousSelf.count)
        var outputLength: size_t = 0

        let result = contiguousSelf.withUnsafeBytes { inputPtr in
            contiguousKey.withUnsafeBytes { keyPtr in
                contiguousIv.withUnsafeBytes { ivPtr in
                    decryptedData.withUnsafeMutableBytes { outPtr in
                        native_bridge_aes_cbc_pkcs7_decrypt(
                            keyPtr.baseAddress,
                            contiguousKey.count,
                            ivPtr.baseAddress,
                            inputPtr.baseAddress,
                            contiguousSelf.count,
                            outPtr.baseAddress,
                            &outputLength
                        )
                    }
                }
            }
        }

        guard result == 0 else { return nil }
        decryptedData.removeSubrange(outputLength..<decryptedData.count)
        return decryptedData
    }

    func decryptedGCM(context: GSAContext) -> Data? {
        guard let key = context.sessionKey else { return nil }

        let versionSize = 3
        let ivSize = 16
        let tagSize = 16

        let minSize = versionSize + ivSize + tagSize
        guard self.count > minSize else { return nil }

        let decryptedSize = self.count - minSize
        var decryptedData = Data(count: decryptedSize)

        let contiguousKey = key.startIndex == 0 ? key : Data(key)
        let contiguousSelf = self.startIndex == 0 ? self : Data(self)

        let result = contiguousSelf.withUnsafeBytes { rawBuffer -> Int32 in
            guard let baseAddress = rawBuffer.baseAddress else { return -1 }
            
            let versionPtr = baseAddress
            let ivPtr = baseAddress.advanced(by: versionSize)
            let cipherPtr = baseAddress.advanced(by: versionSize + ivSize)
            let tagPtr = baseAddress.advanced(by: contiguousSelf.count - tagSize)
            
            return contiguousKey.withUnsafeBytes { keyBytes in
                decryptedData.withUnsafeMutableBytes { outBytes in
                    native_bridge_aes_gcm_decrypt(
                        keyBytes.baseAddress,
                        contiguousKey.count,
                        ivPtr,
                        ivSize,
                        versionPtr,
                        versionSize,
                        cipherPtr,
                        decryptedSize,
                        tagPtr,
                        tagSize,
                        outBytes.baseAddress
                    )
                }
            }
        }

        guard result == 0 else { return nil }
        return decryptedData
    }
}
