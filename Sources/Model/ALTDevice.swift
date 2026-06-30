//
//  ALTDevice.swift
//  AltSign
//

import Foundation

// MARK: - Device Type (NS_OPTIONS → OptionSet)

public struct ALTDeviceType: OptionSet {

    public let rawValue: Int

    public static let iPhone  = ALTDeviceType(rawValue: 1 << 1)
    public static let iphone  = iPhone
    public static let iPad    = ALTDeviceType(rawValue: 1 << 2)
    public static let ipad    = iPad
    public static let appleTV = ALTDeviceType(rawValue: 1 << 3)

    public static let none: ALTDeviceType = []
    public static let all: ALTDeviceType = [.iPhone, .iPad, .appleTV]

    public init(rawValue: Int) {
        self.rawValue = rawValue
    }
}

// MARK: - OS Version Helpers (C functions → Swift globals)

public let NSOperatingSystemVersionUnknown =
OperatingSystemVersion(majorVersion: 0, minorVersion: 0, patchVersion: 0)


public func NSOperatingSystemVersionFromString(
    _ string: String
) -> OperatingSystemVersion {

    let parts = string.split(separator: ".")

    let major = Int(parts[safe: 0] ?? "0") ?? 0
    let minor = Int(parts[safe: 1] ?? "0") ?? 0
    let patch = Int(parts[safe: 2] ?? "0") ?? 0

    return OperatingSystemVersion(
        majorVersion: major,
        minorVersion: minor,
        patchVersion: patch
    )
}


public func NSStringFromOperatingSystemVersion(
    _ version: OperatingSystemVersion
) -> String {

    var value = "\(version.majorVersion).\(version.minorVersion)"

    if version.patchVersion != 0 {
        value += ".\(version.patchVersion)"
    }

    return value
}


extension OperatingSystemVersion {
    public init(string: String) {
        self = NSOperatingSystemVersionFromString(string)
    }

    public var stringValue: String {
        return NSStringFromOperatingSystemVersion(self)
    }
}


public func ALTOperatingSystemNameForDeviceType(
    _ deviceType: ALTDeviceType
) -> String? {

    if deviceType.contains(.iPhone) || deviceType.contains(.iPad) {
        return "iOS"
    }

    if deviceType.contains(.appleTV) {
        return "tvOS"
    }

    return nil
}

// MARK: - ALTDevice


public final class ALTDevice: NSObject, NSCopying {

    // MARK: Properties

    public var name: String
    public var identifier: String
    public var type: ALTDeviceType
    public var osVersion: OperatingSystemVersion = NSOperatingSystemVersionUnknown

    // MARK: Init

    public init(
        name: String,
        identifier: String,
        type: ALTDeviceType
    ) {
        self.name = name
        self.identifier = identifier
        self.type = type
        super.init()
    }

    // MARK: Response Init

    @objc(initWithResponseDictionary:)
    public convenience init?(responseDictionary: [String: Any]) {

        guard
            let name = responseDictionary["name"] as? String,
            let identifier = responseDictionary["deviceNumber"] as? String
        else {
            return nil
        }

        let deviceClass =
            (responseDictionary["deviceClass"] as? String) ?? "iphone"

        let type: ALTDeviceType

        switch deviceClass {
        case "iphone": type = .iPhone
        case "ipad":   type = .iPad
        case "tvOS":   type = .appleTV
        default:       type = .none
        }

        self.init(name: name, identifier: identifier, type: type)
    }

    // MARK: NSObject

    public override var description: String {
        "<\(NSStringFromClass(Swift.type(of: self))): \(Unmanaged.passUnretained(self).toOpaque()), Name: \(name), UDID: \(identifier)>"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? ALTDevice else {
            return false
        }
        return identifier == other.identifier
    }

    public override var hash: Int {
        identifier.hashValue
    }

    // MARK: NSCopying

    public func copy(with zone: NSZone? = nil) -> Any {
        let device = ALTDevice(
            name: name,
            identifier: identifier,
            type: type
        )
        device.osVersion = osVersion
        return device
    }
}

// MARK: Safe Index

private extension Collection {
    subscript(safe index: Index) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
