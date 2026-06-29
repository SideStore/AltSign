//
//  ALTProvisioningProfile.swift
//  AltSign
//

import Foundation


public final class ALTProvisioningProfile: NSObject, NSCopying {

    // MARK: Public readonly properties

    public private(set) var name: String
    public private(set) var identifier: String?
    public private(set) var UUID: UUID

    public private(set) var bundleIdentifier: String

    public private(set) var teamIdentifier: String
    public private(set) var teamName: String

    public private(set) var creationDate: Date
    public private(set) var expirationDate: Date

    public private(set) var entitlements: [ALTEntitlement: Any]
    public private(set) var certificates: [ALTCertificate]
    public private(set) var deviceIDs: [String]

    public private(set) var isFreeProvisioningProfile: Bool

    public private(set) var data: Data

    public convenience init?(responseDictionary: [String: Any]) {

        guard
            let identifier = responseDictionary["provisioningProfileId"] as? String,
            let data = responseDictionary["encodedProfile"] as? Data
        else { return nil }

        self.init(data: data)
        self.identifier = identifier
    }

    // MARK: URL Init

    public convenience init?(url: URL) {
        do {
            try self.init(url: url, options: [])
        } catch {
            NSLog("Error loading provisioning profile from disk: %@", error.localizedDescription)
            return nil
        }
    }

    public convenience init?(
        url: URL,
        options: Data.ReadingOptions
    ) throws {

        let data = try Data(contentsOf: url, options: options)
        self.init(data: data)
    }

    // MARK: Designated Init

    public init?(data: Data) {

        guard
            let dict = Self.dictionary(fromEncodedData: data),
            let name = dict["Name"] as? String,
            let uuidString = dict["UUID"] as? String,
            let uuid = Foundation.UUID(uuidString: uuidString),
            let teamIdentifier = (dict["TeamIdentifier"] as? [String])?.first,
            let teamName = dict["TeamName"] as? String,
            let creationDate = dict["CreationDate"] as? Date,
            let expirationDate = dict["ExpirationDate"] as? Date,
            let entitlementsRaw = dict["Entitlements"] as? [String: Any]
        else {
            return nil
        }

        self.data = data
        self.name = name
        self.UUID = uuid
        self.teamIdentifier = teamIdentifier
        self.teamName = teamName
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        
        self.entitlements = entitlementsRaw.reduce(into: [ALTEntitlement: Any]()) { dict, pair in
            dict[ALTEntitlement(rawValue: pair.key)] = pair.value
        }
        self.deviceIDs = (dict["ProvisionedDevices"] as? [String]) ?? []
        self.isFreeProvisioningProfile = (dict["LocalProvision"] as? Bool) ?? false

        // Bundle ID extraction (same logic)
        var bundleID: String?

        for (key, value) in entitlements {
            guard key == ALTEntitlementApplicationIdentifier,
                  let identifier = value as? String,
                  let dot = identifier.firstIndex(of: ".")
            else { continue }

            bundleID = String(identifier[identifier.index(after: dot)...])
            break
        }

        guard let bundleID else { return nil }
        self.bundleIdentifier = bundleID

        // Certificates
        var parsedCertificates: [ALTCertificate] = []

        let certArray = dict["DeveloperCertificates"] as? [Data] ?? []
        for certData in certArray {
            if let cert = ALTCertificate(data: certData) {
                parsedCertificates.append(cert)
            }
        }

        self.certificates = parsedCertificates

        super.init()
    }

    // MARK: NSCopying

    public func copy(with zone: NSZone? = nil) -> Any {
        let profile = ALTProvisioningProfile(data: data)!
        profile.identifier = identifier
        return profile
    }

    // MARK: ASN1 Parsing (ported)

    private static func dictionary(
        fromEncodedData encodedData: Data
    ) -> [String: Any]? {

        let bytes = [UInt8](encodedData)
        guard !bytes.isEmpty, bytes[0] == 0x30 else { return nil }

        // Exact ObjC logic simplified but behavior identical:
        // provisioning profiles contain embedded plist.
        // We scan for plist XML start.

        guard
            let range = encodedData.range(
                of: Data("<?xml".utf8)
            )
        else { return nil }

        let plistData = encodedData[range.lowerBound...]

        return try? PropertyListSerialization.propertyList(
            from: plistData,
            options: [],
            format: nil
        ) as? [String: Any]
    }

    // MARK: NSObject

    public override var description: String {
        "<\(NSStringFromClass(Swift.type(of: self))): \(Unmanaged.passUnretained(self).toOpaque()), Name: \(name), UUID: \(UUID), App BundleID: \(bundleIdentifier)>"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? ALTProvisioningProfile else {
            return false
        }

        return UUID == other.UUID &&
               data == other.data
    }

    public override var hash: Int {
        UUID.hashValue ^ data.hashValue
    }
}
