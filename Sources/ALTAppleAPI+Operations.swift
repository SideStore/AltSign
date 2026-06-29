//
//  ALTAppleAPI+Operations.swift
//  AltSign
//
//  Created by Magesh K on 2026-06-28.
//

import Foundation

public extension ALTAppleAPI {
    
    static var shared: ALTAppleAPI {
        return sharedAPI
    }
    
    /* Teams */
    func processResponse(
        _ responseDictionary: [String: Any],
        parseHandler: (() -> Any?)?,
        resultCodeHandler: ((Int) -> Error?)?
    ) throws -> Any? {
        var error: Error? = nil
        let result = self.processResponse(responseDictionary, parseHandler: parseHandler, resultCodeHandler: resultCodeHandler, error: &error)
        if let error {
            throw error
        }
        return result
    }
    
    func fetchTeams(for account: ALTAccount, session: ALTAppleAPISession, completionHandler: @escaping ([ALTTeam]?, Error?) -> Void) {
        let url = URL(string: "listTeams.action", relativeTo: self.baseURL)!
        
        self.sendRequest(url: url, additionalParameters: nil, session: session, team: nil) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(nil, requestError)
                return
            }
            
            var error: Error? = nil
            let teams = self.processResponse(responseDictionary, parseHandler: {
                guard let array = responseDictionary["teams"] as? [[String: Any]] else { return nil }
                var list = [ALTTeam]()
                for dict in array {
                    guard let team = ALTTeam(account: account, responseDictionary: dict) else { return nil }
                    list.append(team)
                }
                return list
            }, resultCodeHandler: nil, error: &error) as? [ALTTeam]
            
            if let teams, teams.isEmpty {
                completionHandler(nil, NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.noTeams.rawValue, userInfo: nil))
            } else {
                completionHandler(teams, error)
            }
        }
    }
    
    /* Devices */
    func fetchDevices(for team: ALTTeam, types: ALTDeviceType, session: ALTAppleAPISession, completionHandler: @escaping ([ALTDevice]?, Error?) -> Void) {
        let url = URL(string: "ios/listDevices.action", relativeTo: self.baseURL)!
        
        self.sendRequest(url: url, additionalParameters: nil, session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(nil, requestError)
                return
            }
            
            var error: Error? = nil
            let devices = self.processResponse(responseDictionary, parseHandler: {
                guard let array = responseDictionary["devices"] as? [[String: Any]] else { return nil }
                var list = [ALTDevice]()
                for dict in array {
                    guard let device = ALTDevice(responseDictionary: dict) else { return nil }
                    if !types.contains(device.type) {
                        continue
                    }
                    list.append(device)
                }
                return list
            }, resultCodeHandler: nil, error: &error) as? [ALTDevice]
            
            completionHandler(devices, error)
        }
    }
    
    func registerDevice(name: String, identifier: String, type: ALTDeviceType, team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping (ALTDevice?, Error?) -> Void) {
        let url = URL(string: "ios/addDevice.action", relativeTo: self.baseURL)!
        
        var parameters = [
            "deviceNumber": identifier,
            "name": name
        ]
        
        if type.contains(.iphone) || type.contains(.ipad) {
            parameters["DTDK_Platform"] = "ios"
        } else if type.contains(.appleTV) {
            parameters["DTDK_Platform"] = "tvos"
            parameters["subPlatform"] = "tvOS"
        }
        
        self.sendRequest(url: url, additionalParameters: parameters, session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(nil, requestError)
                return
            }
            
            var error: Error? = nil
            let device = self.processResponse(responseDictionary, parseHandler: {
                guard let dict = responseDictionary["device"] as? [String: Any] else { return nil }
                return ALTDevice(responseDictionary: dict)
            }, resultCodeHandler: { resultCode in
                if resultCode == 35 {
                    if let userString = (responseDictionary["userString"] as? String)?.lowercased(), userString.contains("already exists") {
                        return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.deviceAlreadyRegistered.rawValue, userInfo: nil)
                    } else {
                        return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.invalidDeviceID.rawValue, userInfo: nil)
                    }
                }
                return nil
            }, error: &error) as? ALTDevice
            
            completionHandler(device, error)
        }
    }
    
    /* Certificates */
    func fetchCertificates(for team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping ([ALTCertificate]?, Error?) -> Void) {
        let url = URL(string: "certificates", relativeTo: self.servicesBaseURL)!
        let request = URLRequest(url: url)
        
        self.sendServicesRequest(request, additionalParameters: ["filter[certificateType]": "IOS_DEVELOPMENT,DEVELOPMENT"], session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(nil, requestError)
                return
            }
            
            var error: Error? = nil
            let certificates = self.processResponse(responseDictionary, parseHandler: {
                guard let array = responseDictionary["data"] as? [[String: Any]] else { return nil }
                var list = [ALTCertificate]()
                for dict in array {
                    guard let certificate = ALTCertificate(responseDictionary: dict) else { return nil }
                    list.append(certificate)
                }
                return list
            }, resultCodeHandler: nil, error: &error) as? [ALTCertificate]
            
            completionHandler(certificates, error)
        }
    }
    
    func addCertificate(machineName: String, to team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping (ALTCertificate?, Error?) -> Void) {
        guard let request = ALTCertificateRequest.makeRequest() else {
            completionHandler(nil, NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.invalidCertificateRequest.rawValue, userInfo: nil))
            return
        }
        
        let url = URL(string: "ios/submitDevelopmentCSR.action", relativeTo: self.baseURL)!
        guard let encodedCSR = String(data: request.data, encoding: .utf8) else {
            completionHandler(nil, NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.invalidCertificateRequest.rawValue, userInfo: nil))
            return
        }
        
        let parameters = [
            "csrContent": encodedCSR,
            "machineId": UUID().uuidString.uppercased(),
            "machineName": machineName
        ]
        
        self.sendRequest(url: url, additionalParameters: parameters, session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(nil, requestError)
                return
            }
            
            var error: Error? = nil
            let certificate = self.processResponse(responseDictionary, parseHandler: {
                guard let dict = responseDictionary["certRequest"] as? [String: Any] else { return nil }
                let cert = ALTCertificate(responseDictionary: dict)
                cert?.privateKey = request.privateKey
                return cert
            }, resultCodeHandler: { resultCode in
                if resultCode == 3250 {
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.invalidCertificateRequest.rawValue, userInfo: nil)
                }
                if resultCode == 7460 {
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.tooManyCertificates.rawValue, userInfo: nil)
                }
                return nil
            }, error: &error) as? ALTCertificate
            
            completionHandler(certificate, error)
        }
    }
    
    func revoke(_ certificate: ALTCertificate, for team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping (Bool, Error?) -> Void) {
        let url = URL(string: "certificates/\(certificate.identifier ?? "nil")", relativeTo: self.servicesBaseURL)!
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"
        
        self.sendServicesRequest(request, additionalParameters: nil, session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(false, requestError)
                return
            }
            
            var error: Error? = nil
            let result = self.processResponse(responseDictionary, parseHandler: {
                return responseDictionary
            }, resultCodeHandler: { resultCode in
                if resultCode == 7252 {
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.certificateDoesNotExist.rawValue, userInfo: nil)
                }
                return nil
            }, error: &error)
            
            completionHandler(result != nil, error)
        }
    }
    
    /* App IDs */
    func fetchAppIDs(for team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping ([ALTAppID]?, Error?) -> Void) {
        let url = URL(string: "ios/listAppIds.action", relativeTo: self.baseURL)!
        
        self.sendRequest(url: url, additionalParameters: nil, session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(nil, requestError)
                return
            }
            
            var error: Error? = nil
            let appIDs = self.processResponse(responseDictionary, parseHandler: {
                guard let array = responseDictionary["appIds"] as? [[String: Any]] else { return nil }
                var list = [ALTAppID]()
                for dict in array {
                    guard let appID = ALTAppID(responseDictionary: dict) else { return nil }
                    list.append(appID)
                }
                return list
            }, resultCodeHandler: nil, error: &error) as? [ALTAppID]
            
            completionHandler(appIDs, error)
        }
    }
    
    func addAppID(withName name: String, bundleIdentifier: String, team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping (ALTAppID?, Error?) -> Void) {
        let url = URL(string: "ios/addAppId.action", relativeTo: self.baseURL)!
        
        var allowedCharacters = CharacterSet.alphanumerics
        allowedCharacters.formUnion(CharacterSet.whitespaces)
        
        let foldedName = name.folding(options: .diacriticInsensitive, locale: nil)
        var sanitizedName = String(foldedName.unicodeScalars.filter { allowedCharacters.contains($0) })
        if sanitizedName.isEmpty {
            sanitizedName = "App"
        }
        
        let parameters = [
            "identifier": bundleIdentifier,
            "name": sanitizedName
        ]
        
        self.sendRequest(url: url, additionalParameters: parameters, session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(nil, requestError)
                return
            }
            
            var error: Error? = nil
            let appID = self.processResponse(responseDictionary, parseHandler: {
                guard let dict = responseDictionary["appId"] as? [String: Any] else { return nil }
                return ALTAppID(responseDictionary: dict)
            }, resultCodeHandler: { resultCode in
                switch resultCode {
                case 35:
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.invalidAppIDName.rawValue, userInfo: [(ALTAppNameErrorKey as String): sanitizedName])
                case 9120:
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.maximumAppIDLimitReached.rawValue, userInfo: nil)
                case 9401:
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.bundleIdentifierUnavailable.rawValue, userInfo: nil)
                case 9412:
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.invalidBundleIdentifier.rawValue, userInfo: nil)
                default:
                    return nil
                }
            }, error: &error) as? ALTAppID
            
            completionHandler(appID, error)
        }
    }
    
    func update(_ appID: ALTAppID, team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping (ALTAppID?, Error?) -> Void) {
        let url = URL(string: "ios/updateAppId.action", relativeTo: self.baseURL)!
        
        var parameters: [String: Any] = ["appIdId": appID.identifier]
        for (feature, value) in appID.features {
            parameters[feature] = value
        }
        
        var entitlements = appID.entitlements
        if team.type == .free {
            for (entitlement, _) in appID.entitlements {
                if !ALTFreeDeveloperCanUseEntitlement(entitlement) {
                    entitlements.removeValue(forKey: entitlement)
                }
            }
        }
        
        parameters["entitlements"] = entitlements
        
        self.sendRequest(url: url, plistParameters: parameters, session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(nil, requestError)
                return
            }
            
            var error: Error? = nil
            let updatedAppID = self.processResponse(responseDictionary, parseHandler: {
                guard let dict = responseDictionary["appId"] as? [String: Any] else { return nil }
                return ALTAppID(responseDictionary: dict)
            }, resultCodeHandler: { resultCode in
                switch resultCode {
                case 35:
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.invalidAppIDName.rawValue, userInfo: nil)
                case 9100:
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.appIDDoesNotExist.rawValue, userInfo: nil)
                case 9412:
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.invalidBundleIdentifier.rawValue, userInfo: nil)
                default:
                    return nil
                }
            }, error: &error) as? ALTAppID
            
            completionHandler(updatedAppID, error)
        }
    }
    
    func deleteAppID(_ appID: ALTAppID, for team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping (Bool, Error?) -> Void) {
        let url = URL(string: "ios/deleteAppId.action", relativeTo: self.baseURL)!
        
        self.sendRequest(url: url, additionalParameters: ["appIdId": appID.identifier], session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(false, requestError)
                return
            }
            
            var error: Error? = nil
            let value = self.processResponse(responseDictionary, parseHandler: {
                guard let result = responseDictionary["resultCode"] as? Int else { return nil }
                return result == 0 ? result as Any : nil
            }, resultCodeHandler: { resultCode in
                if resultCode == 9100 {
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.appIDDoesNotExist.rawValue, userInfo: nil)
                }
                return nil
            }, error: &error)
            
            completionHandler(value != nil, error)
        }
    }
    
    /* App Groups */
    func fetchAppGroups(for team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping ([ALTAppGroup]?, Error?) -> Void) {
        let url = URL(string: "ios/listApplicationGroups.action", relativeTo: self.baseURL)!
        
        self.sendRequest(url: url, additionalParameters: nil, session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(nil, requestError)
                return
            }
            
            var error: Error? = nil
            let groups = self.processResponse(responseDictionary, parseHandler: {
                guard let array = responseDictionary["applicationGroupList"] as? [[String: Any]] else { return nil }
                var list = [ALTAppGroup]()
                for dict in array {
                    guard let group = ALTAppGroup(responseDictionary: dict) else { return nil }
                    list.append(group)
                }
                return list
            }, resultCodeHandler: nil, error: &error) as? [ALTAppGroup]
            
            completionHandler(groups, error)
        }
    }
    
    func addAppGroup(withName name: String, groupIdentifier: String, team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping (ALTAppGroup?, Error?) -> Void) {
        let url = URL(string: "ios/addApplicationGroup.action", relativeTo: self.baseURL)!
        
        self.sendRequest(url: url, additionalParameters: ["identifier": groupIdentifier, "name": name], session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(nil, requestError)
                return
            }
            
            var error: Error? = nil
            let group = self.processResponse(responseDictionary, parseHandler: {
                guard let dict = responseDictionary["applicationGroup"] as? [String: Any] else { return nil }
                return ALTAppGroup(responseDictionary: dict)
            }, resultCodeHandler: { resultCode in
                if resultCode == 35 {
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.invalidAppGroup.rawValue, userInfo: nil)
                }
                return nil
            }, error: &error) as? ALTAppGroup
            
            completionHandler(group, error)
        }
    }
    
    func assign(_ appID: ALTAppID, to groups: [ALTAppGroup], team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping (Bool, Error?) -> Void) {
        let url = URL(string: "ios/assignApplicationGroupToAppId.action", relativeTo: self.baseURL)!
        
        let groupIDs = groups.map { $0.identifier }
        let parameters: [String: Any] = [
            "appIdId": appID.identifier,
            "applicationGroups": groupIDs
        ]
        
        self.sendRequest(url: url, plistParameters: parameters, session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(false, requestError)
                return
            }
            
            var error: Error? = nil
            let value = self.processResponse(responseDictionary, parseHandler: {
                guard let result = responseDictionary["resultCode"] as? Int else { return nil }
                return result == 0 ? result as Any : nil
            }, resultCodeHandler: { resultCode in
                switch resultCode {
                case 9115:
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.appIDDoesNotExist.rawValue, userInfo: nil)
                case 35:
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.appGroupDoesNotExist.rawValue, userInfo: nil)
                default:
                    return nil
                }
            }, error: &error)
            
            completionHandler(value != nil, error)
        }
    }
    
    /* Provisioning Profiles */
    func fetchProvisioningProfile(for appID: ALTAppID, deviceType: ALTDeviceType, team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping (ALTProvisioningProfile?, Error?) -> Void) {
        let url = URL(string: "ios/downloadTeamProvisioningProfile.action", relativeTo: self.baseURL)!
        
        var parameters = ["appIdId": appID.identifier]
        if deviceType.contains(.iphone) || deviceType.contains(.ipad) {
            parameters["DTDK_Platform"] = "ios"
        } else if deviceType.contains(.appleTV) {
            parameters["DTDK_Platform"] = "tvos"
            parameters["subPlatform"] = "tvOS"
        }
        
        self.sendRequest(url: url, additionalParameters: parameters, session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(nil, requestError)
                return
            }
            
            var error: Error? = nil
            let profile = self.processResponse(responseDictionary, parseHandler: {
                guard let dict = responseDictionary["provisioningProfile"] as? [String: Any] else { return nil }
                return ALTProvisioningProfile(responseDictionary: dict)
            }, resultCodeHandler: { resultCode in
                if resultCode == 8201 {
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.appIDDoesNotExist.rawValue, userInfo: nil)
                }
                return nil
            }, error: &error) as? ALTProvisioningProfile
            
            completionHandler(profile, error)
        }
    }
    
    func delete(_ provisioningProfile: ALTProvisioningProfile, for team: ALTTeam, session: ALTAppleAPISession, completionHandler: @escaping (Bool, Error?) -> Void) {
        let url = URL(string: "ios/deleteProvisioningProfile.action", relativeTo: self.baseURL)!
        
        let parameters = [
            "provisioningProfileId": provisioningProfile.identifier ?? "",
            "teamId": team.identifier
        ]
        
        self.sendRequest(url: url, additionalParameters: parameters, session: session, team: team) { responseDictionary, requestError in
            guard let responseDictionary else {
                completionHandler(false, requestError)
                return
            }
            
            var error: Error? = nil
            let value = self.processResponse(responseDictionary, parseHandler: {
                guard let result = responseDictionary["resultCode"] as? Int else { return nil }
                return result == 0 ? result as Any : nil
            }, resultCodeHandler: { resultCode in
                switch resultCode {
                case 35:
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.invalidProvisioningProfileIdentifier.rawValue, userInfo: nil)
                case 8101:
                    return NSError(domain: ALTAppleAPIErrorDomain, code: ALTAppleAPIError.provisioningProfileDoesNotExist.rawValue, userInfo: nil)
                default:
                    return nil
                }
            }, error: &error)
            
            completionHandler(value != nil, error)
        }
    }
    
    // MARK: - Helper plist request with [String: Any]
    
    func sendRequest(
        url requestURL: URL,
        plistParameters: [String: Any]?,
        session apiSession: ALTAppleAPISession,
        team: ALTTeam?,
        completionHandler: @escaping ([String: Any]?, Error?) -> Void
    ) {
        var parameters: [String: Any] = [
            "clientId": ALTClientID,
            "protocolVersion": ALTProtocolVersion,
            "requestId": UUID().uuidString.uppercased()
        ]

        if let team {
            parameters["teamId"] = team.identifier
        }

        plistParameters?.forEach { parameters[$0] = $1 }

        let bodyData: Data
        do {
            bodyData = try PropertyListSerialization.data(
                fromPropertyList: parameters,
                format: .xml,
                options: 0
            )
        } catch {
            completionHandler(
                nil,
                NSError(
                    domain: ALTAppleAPIErrorDomain,
                    code: ALTAppleAPIError.invalidParameters.rawValue,
                    userInfo: [NSUnderlyingErrorKey: error]
                )
            )
            return
        }

        let url = URL(
            string: "\(requestURL.absoluteString)?clientId=\(ALTClientID)"
        )!

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = bodyData

        let a = apiSession.anisetteData

        let headers: [String: String] = [
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Apple-I-Identity-Id": apiSession.dsid,
            "X-Apple-GS-Token": apiSession.authToken,
            "X-Apple-I-MD-M": a.machineID,
            "X-Apple-I-MD": a.oneTimePassword,
            "X-Apple-I-MD-LU": a.localUserID,
            "X-Apple-I-MD-RINFO": "\(a.routingInfo)",
            "X-Mme-Device-Id": a.deviceUniqueIdentifier,
            "X-MMe-Client-Info": a.deviceDescription,
            "X-Apple-I-Client-Time": dateFormatter.string(from: a.date),
            "X-Apple-Locale": a.locale.identifier,
            "X-Apple-I-Locale": a.locale.identifier,
            "X-Apple-I-TimeZone": a.timeZone.abbreviation(for: a.date) ?? ""
        ]

        headers.forEach {
            request.setValue($1, forHTTPHeaderField: $0)
        }

        session.dataTask(with: request) { data, _, error in
            guard let data else {
                completionHandler(nil, error)
                return
            }

            do {
                let plist = try PropertyListSerialization.propertyList(
                    from: data,
                    options: [],
                    format: nil
                )
                completionHandler(plist as? [String: Any], nil)
            } catch {
                completionHandler(
                    nil,
                    NSError(
                        domain: NSURLErrorDomain,
                        code: NSURLErrorBadServerResponse,
                        userInfo: [NSUnderlyingErrorKey: error]
                    )
                )
            }
        }.resume()
    }

    func sendRequest(
        with requestURL: URL,
        additionalParameters: [String: String]?,
        session apiSession: ALTAppleAPISession,
        team: ALTTeam?,
        completionHandler: @escaping ([String: Any]?, Error?) -> Void
    ) {
        self.sendRequest(
            url: requestURL,
            additionalParameters: additionalParameters,
            session: apiSession,
            team: team,
            completionHandler: completionHandler
        )
    }
}
