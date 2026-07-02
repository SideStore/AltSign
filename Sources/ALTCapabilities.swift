
//
//  ALTCapabilities.swift
//  AltSign
//
//  Swift port of ALTCapabilities.h/.m
//

import Foundation

public struct ALTEntitlement: RawRepresentable, Hashable, ExpressibleByStringLiteral, CustomStringConvertible {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue
    }
    
    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }
    
    public init(stringLiteral value: String) {
        self.rawValue = value
    }
    
    public var description: String {
        return rawValue
    }
}

extension ALTEntitlement {
    public static let applicationIdentifier: ALTEntitlement = "application-identifier"
    public static let keychainAccessGroups: ALTEntitlement = "keychain-access-groups"
    public static let appGroups: ALTEntitlement = "com.apple.security.application-groups"
    public static let getTaskAllow: ALTEntitlement = "get-task-allow"
    public static let increasedMemoryLimit: ALTEntitlement = "com.apple.developer.kernel.increased-memory-limit"
    public static let teamIdentifier: ALTEntitlement = "com.apple.developer.team-identifier"
    public static let interAppAudio: ALTEntitlement = "inter-app-audio"
    public static let increasedDebuggingMemoryLimit: ALTEntitlement = "com.apple.developer.kernel.increased-debugging-memory-limit"
    public static let extendedVirtualAddressing: ALTEntitlement = "com.apple.developer.kernel.extended-virtual-addressing"
}

public typealias ALTCapability = String
public typealias ALTFeature = String

// MARK: Entitlements

public let ALTEntitlementApplicationIdentifier: ALTEntitlement = "application-identifier"
public let ALTEntitlementKeychainAccessGroups: ALTEntitlement = "keychain-access-groups"
public let ALTEntitlementAppGroups: ALTEntitlement = "com.apple.security.application-groups"
public let ALTEntitlementGetTaskAllow: ALTEntitlement = "get-task-allow"
public let ALTEntitlementIncreasedMemoryLimit: ALTEntitlement = "com.apple.developer.kernel.increased-memory-limit"
public let ALTEntitlementTeamIdentifier: ALTEntitlement = "com.apple.developer.team-identifier"
public let ALTEntitlementInterAppAudio: ALTEntitlement = "inter-app-audio"
public let ALTEntitlementIncreasedDebuggingMemoryLimit: ALTEntitlement = "com.apple.developer.kernel.increased-debugging-memory-limit"
public let ALTEntitlementExtendedVirtualAddressing: ALTEntitlement = "com.apple.developer.kernel.extended-virtual-addressing"

// MARK: Capabilities

public let ALTCapabilityIncreasedMemoryLimit: ALTCapability = "INCREASED_MEMORY_LIMIT"
public let ALTCapabilityIncreasedDebuggingMemoryLimit: ALTCapability = "INCREASED_MEMORY_LIMIT_DEBUGGING"
public let ALTCapabilityExtendedVirtualAddressing: ALTCapability = "EXTENDED_VIRTUAL_ADDRESSING"

// MARK: Features

public let ALTFeatureGameCenter: ALTFeature = "gameCenter"
public let ALTFeatureAppGroups: ALTFeature = "APG3427HIY"
public let ALTFeatureInterAppAudio: ALTFeature = "IAD53UNK2F"

// MARK: Feature ↔ Entitlement Mapping

@inlinable
public func ALTEntitlementForFeature(_ feature: ALTFeature) -> ALTEntitlement? {
    if feature == ALTFeatureAppGroups {
        return ALTEntitlementAppGroups
    } else if feature == ALTFeatureInterAppAudio {
        return ALTEntitlementInterAppAudio
    }
    return nil
}

@inlinable
public func ALTFeatureForEntitlement(_ entitlement: ALTEntitlement) -> ALTFeature? {
    if entitlement == ALTEntitlementAppGroups {
        return ALTFeatureAppGroups
    } else if entitlement == ALTEntitlementInterAppAudio {
        return ALTFeatureInterAppAudio
    }
    return nil
}

// MARK: Free Developer Entitlement Rules

@inlinable
public func ALTFreeDeveloperCanUseEntitlement(_ entitlement: ALTEntitlement) -> Bool {

    switch entitlement {
    case ALTEntitlementAppGroups,
         ALTEntitlementInterAppAudio,
         ALTEntitlementGetTaskAllow,
         ALTEntitlementIncreasedMemoryLimit,
         ALTEntitlementTeamIdentifier,
         ALTEntitlementKeychainAccessGroups,
         ALTEntitlementApplicationIdentifier:
         return true

    default:
        return false
    }
}

extension ALTFeature {
    public static let appGroups: ALTFeature = "APG3427HIY"
    public static let gameCenter: ALTFeature = "gameCenter"
    public static let interAppAudio: ALTFeature = "IAD53UNK2F"
    
    public init?(entitlement: ALTEntitlement) {
        guard let feature = ALTFeatureForEntitlement(entitlement) else { return nil }
        self = feature
    }
}
