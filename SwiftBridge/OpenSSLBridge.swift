import Foundation
import NativeBridge


public enum OpenSSLBridge {

    // MARK: CSR Subject

    public struct CSRSubject {
        public let country: String
        public let state: String
        public let locality: String
        public let organization: String
        public let commonName: String

        public init(
            country: String,
            state: String,
            locality: String,
            organization: String,
            commonName: String
        ) {
            self.country = country
            self.state = state
            self.locality = locality
            self.organization = organization
            self.commonName = commonName
        }
    }

    public enum Error: Swift.Error {
        case operationFailed(String)
    }

    // MARK: CSR Generation

    public static func generateCSR(
        subject: CSRSubject
    ) throws -> (csr: Data, privateKey: Data) {

        verboseLog("""
        [AltSign] OpenSSLBridge.generateCSR started:
          • Country: \(subject.country)
          • State: \(subject.state)
          • Locality: \(subject.locality)
          • Organization: \(subject.organization)
          • Common Name: \(subject.commonName)
        """)

        var csrPtr: UnsafeMutablePointer<UInt8>?
        var csrLen: Int32 = 0

        var keyPtr: UnsafeMutablePointer<UInt8>?
        var keyLen: Int32 = 0

        var errorPtr: UnsafeMutablePointer<CChar>?

        let ok: Int32 =
        subject.country.withCString { c in
            subject.state.withCString { st in
                subject.locality.withCString { l in
                    subject.organization.withCString { o in
                        subject.commonName.withCString { cn in

                            native_bridge_generate_csr(
                                c,
                                st,
                                l,
                                o,
                                cn,
                                &csrPtr,
                                &csrLen,
                                &keyPtr,
                                &keyLen,
                                &errorPtr
                            )
                        }
                    }
                }
            }
        }

        guard ok != 0 else {
            let message =
                errorPtr.map { String(cString: $0) }
                ?? "CSR generation failed"

            debugLog("[AltSign] OpenSSLBridge.generateCSR native failed with error: \(message)")
            if let errorPtr { native_bridge_free_string(errorPtr) }
            throw Error.operationFailed(message)
        }

        guard let csrPtr, let keyPtr else {
            debugLog("[AltSign] OpenSSLBridge.generateCSR native succeeded but returned null output pointers")
            throw Error.operationFailed("CSR output missing")
        }

        let csr = Data(bytes: csrPtr, count: Int(csrLen))
        let key = Data(bytes: keyPtr, count: Int(keyLen))

        native_bridge_free(csrPtr)
        native_bridge_free(keyPtr)

        verboseLog("[AltSign] OpenSSLBridge.generateCSR succeeded. Generated CSR size: \(csr.count) bytes, privateKey size: \(key.count) bytes")
        return (csr, key)
    }


    // MARK: PKCS12 Extract

    public static func extractPKCS12(
        _ data: Data,
        password: String?
    ) throws -> (cert: Data, key: Data) {

        verboseLog("[AltSign] OpenSSLBridge.extractPKCS12 started. Data size: \(data.count) bytes, hasPassword: \(password != nil)")

        var certPtr: UnsafeMutablePointer<UInt8>?
        var certLen: Int32 = 0

        var keyPtr: UnsafeMutablePointer<UInt8>?
        var keyLen: Int32 = 0

        let ok: Int32 = data.withUnsafeBytes { buf in
            native_bridge_pkcs12_extract(
                buf.bindMemory(to: UInt8.self).baseAddress,
                Int32(data.count),
                password,
                &certPtr,
                &certLen,
                &keyPtr,
                &keyLen
            )
        }

        guard ok == 1,
              let certPtr,
              let keyPtr else {
            if let certPtr { native_bridge_free(certPtr) }
            if let keyPtr { native_bridge_free(keyPtr) }
            
            debugLog("[AltSign] OpenSSLBridge.extractPKCS12 failed: native pkcs12 extraction returned error or null pointers. Data size: \(data.count) bytes, password: \(String(describing: password))")
            
            switch ok {
            case -1:
                throw ALTCertificateError.invalidFormat
            case -2:
                throw ALTCertificateError.decryptionFailed
            default:
                throw ALTCertificateError.extractionFailed
            }
        }

        let cert = Data(bytes: certPtr, count: Int(certLen))
        let key  = Data(bytes: keyPtr,  count: Int(keyLen))

        native_bridge_free(certPtr)
        native_bridge_free(keyPtr)

        verboseLog("[AltSign] OpenSSLBridge.extractPKCS12 succeeded. Extracted cert size: \(cert.count) bytes, key size: \(key.count) bytes")
        return (cert, key)
    }


    // MARK: Certificate Parse

    public static func parseCertificate(
        _ data: Data
    ) -> (name: String, serial: String)? {

        verboseLog("[AltSign] OpenSSLBridge.parseCertificate started. Cert size: \(data.count) bytes")

        var namePtr: UnsafeMutablePointer<CChar>?
        var serialPtr: UnsafeMutablePointer<CChar>?

        let ok: Int32 = data.withUnsafeBytes { buf in
            native_bridge_x509_parse(
                buf.bindMemory(to: UInt8.self).baseAddress,
                Int32(data.count),
                &namePtr,
                &serialPtr
            )
        }

        guard ok != 0,
              let namePtr,
              let serialPtr else {
            debugLog("[AltSign] OpenSSLBridge.parseCertificate failed: native x509 parsing returned error or null pointers")
            return nil
        }

        let name = String(cString: namePtr)
        let serial = String(cString: serialPtr)

        native_bridge_free(namePtr)
        native_bridge_free(serialPtr)

        verboseLog("[AltSign] OpenSSLBridge.parseCertificate succeeded. Name: \(name), Serial: \(serial)")
        return (name, serial)
    }


    // MARK: PKCS12 Create

    public static func createPKCS12(
        cert: Data,
        key: Data,
        password: String
    ) -> Data? {

        verboseLog("[AltSign] OpenSSLBridge.createPKCS12 started. Cert size: \(cert.count) bytes, Key size: \(key.count) bytes")

        var outPtr: UnsafeMutablePointer<UInt8>?
        var outLen: Int32 = 0

        let ok: Int32 = cert.withUnsafeBytes { cbuf in
            key.withUnsafeBytes { kbuf in
                native_bridge_pkcs12_create(
                    cbuf.bindMemory(to: UInt8.self).baseAddress,
                    Int32(cert.count),
                    kbuf.bindMemory(to: UInt8.self).baseAddress,
                    Int32(key.count),
                    password,
                    &outPtr,
                    &outLen
                )
            }
        }

        guard ok != 0, let outPtr else {
            debugLog("[AltSign] OpenSSLBridge.createPKCS12 failed: native pkcs12 creation returned error or null pointer")
            return nil
        }

        let result = Data(bytes: outPtr, count: Int(outLen))
        native_bridge_free(outPtr)

        verboseLog("[AltSign] OpenSSLBridge.createPKCS12 succeeded. Output PKCS12 size: \(result.count) bytes")
        return result
    }
}
