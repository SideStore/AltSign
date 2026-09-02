//
//  ALTAccount.swift
//  AltSign
//

import Foundation


public final class ALTAccount: NSObject {

    // MARK: Properties

    public var appleID: String
    public var identifier: String

    public var firstName: String
    public var lastName: String

    public var name: String {
        var components = PersonNameComponents()
        components.givenName = firstName
        components.familyName = lastName

        return PersonNameComponentsFormatter.localizedString(
            from: components,
            style: .default,
            options: []
        )
    }

    // MARK: Init

    @objc
    public override init() {
        self.appleID = ""
        self.identifier = ""
        self.firstName = ""
        self.lastName = ""
        super.init()
    }

    // MARK: Apple API Init

    @objc(initWithResponseDictionary:)
    public convenience init?(responseDictionary: [String: Any]) {

        guard
            let appleID = responseDictionary["email"] as? String,
            let identifierNumber = responseDictionary["personId"] as? NSNumber,
            let firstName =
                (responseDictionary["dsFirstName"]
                 ?? responseDictionary["firstName"]) as? String,
            let lastName =
                (responseDictionary["dsLastName"]
                 ?? responseDictionary["lastName"]) as? String
        else {
            return nil
        }

        self.init()

        self.appleID = appleID
        self.identifier = identifierNumber.stringValue
        self.firstName = firstName
        self.lastName = lastName
    }

    // MARK: NSObject

    public override var description: String {
        "<\(NSStringFromClass(Swift.type(of: self))): \(Unmanaged.passUnretained(self).toOpaque()), Name: \(name), Apple ID: \(appleID)>"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? ALTAccount else {
            return false
        }
        return identifier == other.identifier
    }

    public override var hash: Int {
        identifier.hashValue
    }
}
