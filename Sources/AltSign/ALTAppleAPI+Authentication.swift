//
//  ALTAppleAPI+Authentication.swift
//  AltSign
//
//  Created by Riley Testut on 8/15/20.
//  Copyright © 2020 Riley Testut. All rights reserved.
//

import Foundation

@_exported import CAltSign
import CAltSign.Private

public extension ALTAppleAPIError
{
    static func unknown(userInfo: [String: Any] = [:], sourceFile: String = #fileID, sourceLine: UInt = #line) -> ALTAppleAPIError
    {
        var userInfo = userInfo
        userInfo[ALTSourceFileErrorKey] = sourceFile
        userInfo[ALTSourceLineErrorKey] = sourceLine
        
        let error = ALTAppleAPIError(.unknown, userInfo: userInfo)
        return error
    }
}

public extension ALTAppleAPI
{
    @objc func authenticate(appleID unsanitizedAppleID: String,
                            password: String,
                            anisetteData: ALTAnisetteData,
                            verificationHandler: ((@escaping (String?) -> Void) -> Void)?,
                            completionHandler: @escaping (ALTAccount?, ALTAppleAPISession?, Error?) -> Void) {
        // Authenticating only works with lowercase email address, even if Apple ID contains capital letters.
        let sanitizedAppleID = unsanitizedAppleID.lowercased()

        do {
            let clientDictionary = [
                "bootstrap": true,
                "icscrec": true,
                "pbe": false,
                "prkgen": true,
                "svct": "iCloud",
                "loc": Locale.current.identifier,
                "X-Apple-Locale": Locale.current.identifier,
                "X-Apple-I-MD": anisetteData.oneTimePassword,
                "X-Apple-I-MD-M": anisetteData.machineID,
                "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
                "X-Apple-I-MD-LU": anisetteData.localUserID,
                "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
                "X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber,
                "X-Apple-I-Client-Time": dateFormatter.string(from: anisetteData.date),
                "X-Apple-I-TimeZone": TimeZone.current.abbreviation() ?? "PST"
            ] as [String: Any]

            let context = GSAContext(username: sanitizedAppleID, password: password)
            guard let publicKey = context.start() else { throw ALTAppleAPIError(.authenticationHandshakeFailed) }

            let parameters = [
                "A2k": publicKey,
                "cpd": clientDictionary,
                "ps": ["s2k", "s2k_fo"],
                "o": "init",
                "u": sanitizedAppleID
            ] as [String: Any]

            sendAuthenticationRequest(parameters: parameters, anisetteData: anisetteData) { result in
                do {
                    let responseDictionary = try result.get()

                    guard let c = responseDictionary["c"] as? String,
                          let salt = responseDictionary["s"] as? Data,
                          let iterations = responseDictionary["i"] as? Int,
                          let serverPublicKey = responseDictionary["B"] as? Data
                    else { throw URLError(.badServerResponse) }

                    context.salt = salt
                    context.serverPublicKey = serverPublicKey

                    let sp = responseDictionary["sp"] as? String
                    let isHexadecimal = (sp == "s2k_fo")

                    guard let verificationMessage = context.makeVerificationMessage(iterations: iterations, isHexadecimal: isHexadecimal) else {
                        throw ALTAppleAPIError(.authenticationHandshakeFailed)
                    }

                    let parameters = [
                        "c": c,
                        "cpd": clientDictionary,
                        "M1": verificationMessage,
                        "o": "complete",
                        "u": sanitizedAppleID
                    ] as [String: Any]

                    self.sendAuthenticationRequest(parameters: parameters, anisetteData: anisetteData) { result in
                        do {
                            let responseDictionary = try result.get()

                            guard let serverVerificationMessage = responseDictionary["M2"] as? Data,
                                  let serverDictionary = responseDictionary["spd"] as? Data,
                                  let statusDictionary = responseDictionary["Status"] as? [String: Any]
                            else { throw URLError(.badServerResponse) }

                            guard context.verifyServerVerificationMessage(serverVerificationMessage) else { throw ALTAppleAPIError(.authenticationHandshakeFailed) }
                            guard let decryptedData = serverDictionary.decryptedCBC(context: context) else { throw ALTAppleAPIError(.authenticationHandshakeFailed) }

                            guard let decryptedDictionary = try PropertyListSerialization.propertyList(from: decryptedData, format: nil) as? [String: Any],
                                  let dsid = decryptedDictionary["adsid"] as? String,
                                  let idmsToken = decryptedDictionary["GsIdmsToken"] as? String
                            else { throw URLError(.badServerResponse) }

                            context.dsid = dsid

                            let authType = statusDictionary["au"] as? String
                            switch authType {
                            case "trustedDeviceSecondaryAuth":
                                guard let verificationHandler = verificationHandler else { throw ALTAppleAPIError(.requiresTwoFactorAuthentication) }

                                self.requestTrustedDeviceTwoFactorCode(dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData, verificationHandler: verificationHandler) { result in
                                    switch result {
                                    case let .failure(error): completionHandler(nil, nil, error)
                                    case .success:
                                        self.authenticate(appleID: unsanitizedAppleID, password: password, anisetteData: anisetteData, verificationHandler: verificationHandler, completionHandler: completionHandler)
                                    }
                                }

                            case "secondaryAuth":
                                guard let verificationHandler = verificationHandler else { throw ALTAppleAPIError(.requiresTwoFactorAuthentication) }

                                self.requestSMSTwoFactorCode(dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData, verificationHandler: verificationHandler) { result in
                                    switch result {
                                    case let .failure(error): completionHandler(nil, nil, error)
                                    case .success:
                                        self.authenticate(appleID: unsanitizedAppleID, password: password, anisetteData: anisetteData, verificationHandler: verificationHandler, completionHandler: completionHandler)
                                    }
                                }

                            default:
                                guard let sessionKey = decryptedDictionary["sk"] as? Data,
                                      let c = decryptedDictionary["c"] as? Data
                                else { throw URLError(.badServerResponse) }

                                context.sessionKey = sessionKey

                                let app = "com.apple.gs.xcode.auth"
                                guard let checksum = context.makeChecksum(appName: app) else { throw ALTAppleAPIError(.authenticationHandshakeFailed) }

                                let parameters = [
                                    "app": [app],
                                    "c": c,
                                    "checksum": checksum,
                                    "cpd": clientDictionary,
                                    "o": "apptokens",
                                    "t": idmsToken,
                                    "u": dsid
                                ] as [String: Any]

                                self.fetchAuthToken(app: app, parameters: parameters, context: context, anisetteData: anisetteData) { result in
                                    switch result {
                                    case let .failure(error): completionHandler(nil, nil, error)
                                    case let .success(token):

                                        let session = ALTAppleAPISession(dsid: dsid, authToken: token, anisetteData: anisetteData)
                                        self.fetchAccount(session: session) { result in
                                            switch result {
                                            case let .failure(error): completionHandler(nil, nil, error)
                                            case let .success(account): completionHandler(account, session, nil)
                                            }
                                        }
                                    }
                                }
                            }
                        } catch {
                            completionHandler(nil, nil, error)
                        }
                    }
                } catch {
                    completionHandler(nil, nil, error)
                }
            }
        } catch {
            completionHandler(nil, nil, error)
        }
    }
}

private extension ALTAppleAPI {
    func fetchAuthToken(app: String, parameters: [String: Any], context: GSAContext, anisetteData: ALTAnisetteData, completionHandler: @escaping (Result<String, Error>) -> Void) {
        sendAuthenticationRequest(parameters: parameters, anisetteData: anisetteData) { result in
            do {
                let responseDictionary = try result.get()

                guard let encryptedToken = responseDictionary["et"] as? Data else { throw URLError(.badServerResponse) }
                guard let token = encryptedToken.decryptedGCM(context: context) else { throw ALTAppleAPIError(.authenticationHandshakeFailed) }

                guard let tokensDictionary = try PropertyListSerialization.propertyList(from: token, format: nil) as? [String: Any] else {
                    throw URLError(.badServerResponse)
                }

                guard let appTokens = tokensDictionary["t"] as? [String: Any],
                      let tokens = appTokens[app] as? [String: Any],
                      let authToken = tokens["token"] as? String
                else { throw URLError(.badServerResponse) }

                completionHandler(.success(authToken))
            } catch {
                completionHandler(.failure(error))
            }
        }
    }

    func requestTrustedDeviceTwoFactorCode(dsid: String,
                                           idmsToken: String,
                                           anisetteData: ALTAnisetteData,
                                           verificationHandler: @escaping (@escaping (String?) -> Void) -> Void,
                                           completionHandler: @escaping (Result<Void, Error>) -> Void) {
        let requestURL = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
        let verifyURL = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!

        let request = makeTwoFactorCodeRequest(url: requestURL, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)

        let requestCodeTask = session.dataTask(with: request) { data, _, error in
            do {
                guard error == nil else { throw error! }

                func responseHandler(verificationCode: String?) {
                    do {
                        guard let verificationCode = verificationCode else { throw ALTAppleAPIError(.requiresTwoFactorAuthentication) }

                        var request = self.makeTwoFactorCodeRequest(url: verifyURL, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)
                        request.allHTTPHeaderFields?["security-code"] = verificationCode
                        
                        let verifyCodeTask = self.session.dataTask(with: request) { (data, response, error) in
                            do
                            {
                                guard let data = data else { throw error ?? ALTAppleAPIError.unknown() }
                                
                                guard let responseDictionary = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                                    throw URLError(.badServerResponse)
                                }

                                let errorCode = responseDictionary["ec"] as? Int ?? 0
                                guard errorCode != 0 else { return completionHandler(.success(())) }

                                switch errorCode {
                                case -21669: throw ALTAppleAPIError(.incorrectVerificationCode)
                                default:
                                    guard let errorDescription = responseDictionary["em"] as? String else { throw ALTAppleAPIError.unknown() }
                                    
                                    let localizedDescription = errorDescription + " (\(errorCode))"
                                    throw NSError(domain: ALTUnderlyingAppleAPIErrorDomain, code: errorCode, userInfo: [NSLocalizedDescriptionKey: localizedDescription])
                                }
                            } catch {
                                completionHandler(.failure(error))
                            }
                        }

                        verifyCodeTask.resume()
                    } catch {
                        completionHandler(.failure(error))
                    }
                }

                verificationHandler(responseHandler)
            } catch {
                completionHandler(.failure(error))
            }
        }

        requestCodeTask.resume()
    }

    func requestSMSTwoFactorCode(dsid: String,
                                 idmsToken: String,
                                 anisetteData: ALTAnisetteData,
                                 verificationHandler: @escaping (@escaping (String?) -> Void) -> Void,
                                 completionHandler: @escaping (Result<Void, Error>) -> Void) {
        let requestURL = URL(string: "https://gsa.apple.com/auth/verify/phone/put?mode=sms")!
        let verifyURL = URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put")!

        var request = makeTwoFactorCodeRequest(url: requestURL, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)
        request.httpMethod = "POST"

        do {
            let bodyXML = [
                "serverInfo": [
                    "phoneNumber.id": "1"
                ]
            ] as [String: Any]

            let bodyData = try PropertyListSerialization.data(fromPropertyList: bodyXML, format: .xml, options: 0)
            request.httpBody = bodyData
        } catch {
            completionHandler(.failure(error))
            return
        }

        let requestCodeTask = session.dataTask(with: request) { _, response, error in
            do {
                guard error == nil else { throw error! }

                func responseHandler(verificationCode: String?) {
                    do {
                        guard let verificationCode = verificationCode else { throw ALTAppleAPIError(.requiresTwoFactorAuthentication) }

                        var request = self.makeTwoFactorCodeRequest(url: verifyURL, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)
                        request.httpMethod = "POST"

                        let bodyXML = [
                            "securityCode.code": verificationCode,
                            "serverInfo": [
                                "mode": "sms",
                                "phoneNumber.id": "1"
                            ]
                        ] as [String: Any]

                        let bodyData = try PropertyListSerialization.data(fromPropertyList: bodyXML, format: .xml, options: 0)
                        request.httpBody = bodyData

                        let verifyCodeTask = self.session.dataTask(with: request) { _, response, error in
                            do {
                                guard error == nil else { throw error! }

                                guard let httpResponse = response as? HTTPURLResponse,
                                      httpResponse.statusCode == 200,
                                      httpResponse.allHeaderFields.keys.contains("X-Apple-PE-Token") // PE token is included in headers if we sent correct verification code.
                                else { throw ALTAppleAPIError(.incorrectVerificationCode) }

                                completionHandler(.success(()))
                            } catch {
                                completionHandler(.failure(error))
                            }
                        }

                        verifyCodeTask.resume()
                    } catch {
                        completionHandler(.failure(error))
                    }
                }

                verificationHandler(responseHandler)
            } catch {
                completionHandler(.failure(error))
            }
        }

        requestCodeTask.resume()
    }
    
    func fetchAccount(session: ALTAppleAPISession, completionHandler: @escaping (Result<ALTAccount, Error>) -> Void)
    {
        let url = URL(string: "viewDeveloper.action", relativeTo: self.baseURL)!
        
        self.sendRequest(with: url, additionalParameters: nil, session: session, team: nil) { (responseDictionary, requestError) in
            do
            {
                guard let responseDictionary = responseDictionary else { throw requestError ?? ALTAppleAPIError.unknown() }
                
                guard let account = try self.processResponse(responseDictionary, parseHandler: { () -> Any? in
                    guard let dictionary = responseDictionary["developer"] as? [String: Any] else { return nil }
                    let account = ALTAccount(responseDictionary: dictionary)
                    return account
                }, resultCodeHandler: nil) as? ALTAccount else {
                    throw ALTAppleAPIError.unknown()
                }

                completionHandler(.success(account))
            } catch {
                completionHandler(.failure(error))
            }
        }
    }
}

private extension ALTAppleAPI {
    func sendAuthenticationRequest(parameters requestParameters: [String: Any], anisetteData: ALTAnisetteData, completionHandler: @escaping (Result<[String: Any], Error>) -> Void) {
        do {
            let requestURL = URL(string: "https://gsa.apple.com/grandslam/GsService2")!

            let parameters = [
                "Header": ["Version": "1.0.1"],
                "Request": requestParameters
            ]

            let httpHeaders = [
                "Content-Type": "text/x-xml-plist",
                "X-MMe-Client-Info": anisetteData.deviceDescription,
                "Accept": "*/*",
                "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
            ]

            let bodyData = try PropertyListSerialization.data(fromPropertyList: parameters, format: .xml, options: 0)

            var request = URLRequest(url: requestURL)
            request.httpMethod = "POST"
            request.httpBody = bodyData
            httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }
            
            let dataTask = self.session.dataTask(with: request) { (data, response, error) in
                do
                {
                    guard let data = data else { throw error ?? ALTAppleAPIError.unknown() }
                    
                    guard let responseDictionary = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                          let dictionary = responseDictionary["Response"] as? [String: Any],
                          let status = dictionary["Status"] as? [String: Any]
                    else { throw URLError(.badServerResponse) }

                    let errorCode = status["ec"] as? Int ?? 0
                    guard errorCode != 0 else { return completionHandler(.success(dictionary)) }
                    
                    switch errorCode
                    {
                    case -20101, -22406: throw ALTAppleAPIError(.incorrectCredentials)
                    case -22421: throw ALTAppleAPIError(.invalidAnisetteData)
                    default:
                        guard let errorDescription = status["em"] as? String else { throw ALTAppleAPIError.unknown() }
                        
                        let localizedDescription = errorDescription + " (\(errorCode))"
                        throw NSError(domain: ALTUnderlyingAppleAPIErrorDomain, code: errorCode, userInfo: [NSLocalizedDescriptionKey: localizedDescription])
                    }
                } catch {
                    completionHandler(.failure(error))
                }
            }

            dataTask.resume()
        } catch {
            completionHandler(.failure(error))
        }
    }

    func makeTwoFactorCodeRequest(url: URL,
                                  dsid: String,
                                  idmsToken: String,
                                  anisetteData: ALTAnisetteData) -> URLRequest {
        let identityToken = dsid + ":" + idmsToken

        let identityTokenData = identityToken.data(using: .utf8)!
        let encodedIdentityToken = identityTokenData.base64EncodedString()

        let httpHeaders = [
            "Accept": "application/x-buddyml",
            "Accept-Language": "en-us",
            "Content-Type": "application/x-plist",
            "User-Agent": "Xcode",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Apple-Identity-Token": encodedIdentityToken,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": "\(anisetteData.routingInfo)",
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
            "X-MMe-Client-Info": anisetteData.deviceDescription,
            "X-Apple-I-Client-Time": dateFormatter.string(from: anisetteData.date),
            "X-Apple-Locale": anisetteData.locale.identifier,
            "X-Apple-I-TimeZone": anisetteData.timeZone.abbreviation() ?? "PST"
        ]

        var request = URLRequest(url: url)
        httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }

        return request
    }
}
