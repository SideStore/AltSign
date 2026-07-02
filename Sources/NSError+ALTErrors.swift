//
//  NSError+ALTErrors.swift
//  AltSign
//

import Foundation

// MARK: Domains

public let AltSignErrorDomain = "AltSign.Error"
public let ALTAppleAPIErrorDomain = "AltStore.AppleDeveloperError"
public let ALTUnderlyingAppleAPIErrorDomain = "Apple.APIError"

// MARK: UserInfo Keys

public let ALTSourceFileErrorKey = "ALTSourceFile"
public let ALTSourceLineErrorKey = "ALTSourceLine"
public let ALTAppNameErrorKey    = NSError.UserInfoKey("appName")

// MARK: Error Enums

public enum ALTError: Int, Error {
    case unknown = 0
    case invalidApp
    case missingAppBundle
    case missingInfoPlist
    case missingProvisioningProfile
}

public enum ALTAppleAPIError: Int, Error {
    case unknown = 3000
    case invalidParameters
    case incorrectCredentials
    case appSpecificPasswordRequired
    case noTeams
    case invalidDeviceID
    case deviceAlreadyRegistered
    case invalidCertificateRequest
    case certificateDoesNotExist
    case invalidAppIDName
    case invalidBundleIdentifier
    case bundleIdentifierUnavailable
    case appIDDoesNotExist
    case maximumAppIDLimitReached
    case invalidAppGroup
    case appGroupDoesNotExist
    case invalidProvisioningProfileIdentifier
    case provisioningProfileDoesNotExist
    case requiresTwoFactorAuthentication
    case incorrectVerificationCode
    case authenticationHandshakeFailed
    case invalidAnisetteData
    case tooManyCertificates
}

extension ALTAppleAPIError {
    public static func unknown() -> ALTAppleAPIError {
        return .unknown
    }
}

// MARK: Install providers

extension NSError {
    public static func registerErrorProviders() {
        NSError.setUserInfoValueProvider(forDomain: AltSignErrorDomain) { error, key in
            let nsError = error as NSError

            if key == NSLocalizedDescriptionKey {
                if nsError.altsignLocalizedFailure != nil { return nil }
                return nsError.localizedFailureReason
            }

            if key == NSLocalizedFailureReasonErrorKey {
                return nsError.altLocalizedFailureReason
            }

            return nil
        }

        NSError.setUserInfoValueProvider(forDomain: ALTAppleAPIErrorDomain) { error, key in
            let nsError = error as NSError

            if key == NSLocalizedDescriptionKey {
                if nsError.altsignLocalizedFailure != nil { return nil }
                return nsError.localizedFailureReason
            }

            if key == NSLocalizedFailureReasonErrorKey {
                return nsError.altAppleAPILocalizedFailureReason
            }

            if key == NSLocalizedRecoverySuggestionErrorKey {
                return nsError.altAppleAPILocalizedRecoverySuggestion
            }

            return nil
        }
    }

    var altsignLocalizedFailure: String? {
        if let value = userInfo[NSLocalizedFailureErrorKey] as? String {
            return value
        }

        guard let provider =
            NSError.userInfoValueProvider(forDomain: domain)
        else { return nil }

        return provider(self, NSLocalizedFailureErrorKey) as? String
    }

    var altLocalizedFailureReason: String? {

        guard let code = ALTError(rawValue: self.code) else { return nil }

        switch code {
        case .unknown:
            return NSLocalizedString("An unknown error occured.", comment: "")
        case .invalidApp:
            return NSLocalizedString("The app is invalid.", comment: "")
        case .missingAppBundle:
            return NSLocalizedString("The provided .ipa does not contain an app bundle.", comment: "")
        case .missingInfoPlist:
            return NSLocalizedString("The provided app is missing its Info.plist.", comment: "")
        case .missingProvisioningProfile:
            return NSLocalizedString("Could not find matching provisioning profile.", comment: "")
        }
    }

    var altAppleAPILocalizedFailureReason: String? {

        guard let code = ALTAppleAPIError(rawValue: self.code) else { return nil }

        switch code {

        case .unknown:
            return NSLocalizedString("An unknown error occured.", comment: "")

        case .invalidParameters:
            return NSLocalizedString("The provided parameters are invalid.", comment: "")

        case .incorrectCredentials:
            return NSLocalizedString("Your Apple ID or password is incorrect.", comment: "")

        case .noTeams:
            return NSLocalizedString("You are not a member of any development teams.", comment: "")

        case .appSpecificPasswordRequired:
            return NSLocalizedString("An app-specific password is required. You can create one at appleid.apple.com.", comment: "")

        case .invalidDeviceID:
            return NSLocalizedString("This device's UDID is invalid.", comment: "")

        case .deviceAlreadyRegistered:
            return NSLocalizedString("This device is already registered with this team.", comment: "")

        case .invalidCertificateRequest:
            return NSLocalizedString("The certificate request is invalid.", comment: "")

        case .certificateDoesNotExist:
            return NSLocalizedString("There is no certificate with the requested serial number for this team.", comment: "")

        case .invalidAppIDName:
            if let appName = userInfo[ALTAppNameErrorKey as String] as? String {
                return String(
                    format: NSLocalizedString("The name “%@” contains invalid characters.", comment: ""),
                    appName
                )
            }
            return NSLocalizedString("The name of this app contains invalid characters.", comment: "")
            
        case .invalidBundleIdentifier:
            return NSLocalizedString("The bundle identifier for this app is invalid.", comment: "")

        case .bundleIdentifierUnavailable:
            return NSLocalizedString("Requested bundle identifier is unavailable for registration or already registered by another developer account.", comment: "")

        case .appIDDoesNotExist:
            return NSLocalizedString("There is no App ID with the requested identifier on this team.", comment: "")

        case .maximumAppIDLimitReached:
            return NSLocalizedString("You may only register 10 App IDs every 7 days.", comment: "")

        case .invalidAppGroup:
            return NSLocalizedString("The provided app group is invalid.", comment: "")

        case .appGroupDoesNotExist:
            return NSLocalizedString("App group does not exist", comment: "")

        case .invalidProvisioningProfileIdentifier:
            return NSLocalizedString("The identifier for the requested provisioning profile is invalid.", comment: "")

        case .provisioningProfileDoesNotExist:
            return NSLocalizedString("There is no provisioning profile with the requested identifier on this team.", comment: "")

        case .requiresTwoFactorAuthentication:
            return NSLocalizedString("This account requires signing in with two-factor authentication.", comment: "")

        case .incorrectVerificationCode:
            return NSLocalizedString("Incorrect verification code.", comment: "")

        case .authenticationHandshakeFailed:
            return NSLocalizedString("Failed to perform authentication handshake with server.", comment: "")

        case .invalidAnisetteData:
            return NSLocalizedString("The provided anisette data is invalid.", comment: "")
        
        case .tooManyCertificates:
            return NSLocalizedString("The maximum number of certificates for this account has been reached.", comment: "")
        }
    }

    var altAppleAPILocalizedRecoverySuggestion: String? {

        guard let code = ALTAppleAPIError(rawValue: self.code) else { return nil }

        switch code {

        case .incorrectCredentials:
            return NSLocalizedString(
                "Please make sure you entered both your Apple ID and password correctly and try again.",
                comment: ""
            )

        case .invalidAnisetteData:
            #if os(macOS)
            return NSLocalizedString(
                "Make sure this computer's date & time matches your iOS device and try again.",
                comment: ""
            )
            #else
            return NSLocalizedString(
                "Make sure your computer's date & time matches your iOS device and try again. You may need to re-install AltStore with AltServer if the problem persists.",
                comment: ""
            )
            #endif

        default:
            return nil
        }
    }
}


// MARK: - Swift CustomNSError & Initializer Compatibility

extension ALTError: CustomNSError {
    public static var errorDomain: String {
        return AltSignErrorDomain
    }

    public var errorCode: Int {
        return rawValue
    }

    public var errorUserInfo: [String: Any] {
        return [:]
    }

    public init(_ code: ALTError) {
        self = code
    }

    public static func invalidApp(reason: String) -> NSError {
        return NSError(domain: AltSignErrorDomain, code: ALTError.invalidApp.rawValue, userInfo: [NSLocalizedFailureReasonErrorKey: reason])
    }
}

extension ALTAppleAPIError: CustomNSError {
    public static var errorDomain: String {
        return ALTAppleAPIErrorDomain
    }

    public var errorCode: Int {
        return rawValue
    }

    public var errorUserInfo: [String: Any] {
        return [:]
    }

    public init(_ code: ALTAppleAPIError) {
        self = code
    }
}
