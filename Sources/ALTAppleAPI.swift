//
//  ALTAppleAPI.swift
//  AltSign
//
//  Direct Swift port of ALTAppleAPI.m
//

import Foundation
import SwiftBridge

// MARK: ALTAppleAPISession

public final class ALTAppleAPISession: NSObject {

    public var dsid: String
    public var authToken: String
    public var anisetteData: ALTAnisetteData

    public init(
        dsid: String,
        authToken: String,
        anisetteData: ALTAnisetteData
    ) {
        self.dsid = dsid
        self.authToken = authToken
        self.anisetteData = anisetteData
        super.init()
    }
}

// MARK: - ALTAppleAPI

public final class ALTAppleAPI: NSObject {

    // MARK: Constants

    let ALTAuthenticationProtocolVersion = "A1234"
    let ALTProtocolVersion = "QH65B2"
    let ALTAppIDKey = "ba2ec180e6ca6e6c6a542255453b24d6e6e5b2be0cc48bc1b0d8ad64cfe0228f"
    let ALTClientID = "XABBG36SBA"

    // MARK: Singleton

    public static let sharedAPI = ALTAppleAPI()



    // MARK: Private State

    let session: URLSession
    let dateFormatter: ISO8601DateFormatter
    public let baseURL: URL
    public let servicesBaseURL: URL

    private override init() {
        NSError.registerErrorProviders()
        session = URLSession(configuration: .ephemeral)
        dateFormatter = ISO8601DateFormatter()
        baseURL = URL(
            string: "https://developerservices2.apple.com/services/\(ALTProtocolVersion)/"
        )!
        servicesBaseURL = URL(
            string: "https://developerservices2.apple.com/services/v1/"
        )!
        super.init()
    }
}

// MARK: - Response Processing

extension ALTAppleAPI {

    func processResponse(
        _ responseDictionary: [String: Any],
        parseHandler: (() -> Any?)?,
        resultCodeHandler: ((Int) -> Error?)?,
        error: inout Error?
    ) -> Any? {

        if let parseHandler, let value = parseHandler() {
            return value
        }

        guard let result = responseDictionary["resultCode"] else {
            error = NSError(
                domain: NSURLErrorDomain,
                code: NSURLErrorBadServerResponse
            )
            return nil
        }

        let resultCode =
            (result as? NSNumber)?.intValue ??
            Int("\(result)") ?? -1

        if resultCode == 0 { return nil }

        var tempError = resultCodeHandler?(resultCode)

        if tempError == nil {

            let desc =
                (responseDictionary["userString"]
                 ?? responseDictionary["resultString"]) as? String ?? ""

            tempError = NSError(
                domain: ALTUnderlyingAppleAPIErrorDomain,
                code: resultCode,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "\(desc) (\(resultCode))"
                ]
            )
        }

        error = tempError
        return nil
    }
}

// MARK: - Requests (plist endpoints)

extension ALTAppleAPI {

    func sendRequest(
        url requestURL: URL,
        additionalParameters: [String: String]?,
        session apiSession: ALTAppleAPISession,
        team: ALTTeam?,
        completionHandler: @escaping ([String: Any]?, Error?) -> Void
    ) {

        var parameters: [String: String] = [
            "clientId": ALTClientID,
            "protocolVersion": ALTProtocolVersion,
            "requestId": UUID().uuidString.uppercased()
        ]

        if let team {
            parameters["teamId"] = team.identifier
        }

        additionalParameters?.forEach { parameters[$0] = $1 }

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

        verboseLog("[AltSign] sendRequest to: \(url.absoluteString)")
        verboseLog("[AltSign] sendRequest parameters: \(parameters)")

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
            "X-Apple-I-TimeZone": a.timeZone.abbreviation(for: a.date) ?? ""        ]

        headers.forEach {
            request.setValue($1, forHTTPHeaderField: $0)
        }

        session.dataTask(with: request) { data, _, error in
            if let error {
                verboseLog("[AltSign] sendRequest failed with error: \(error)")
            }
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
                verboseLog("[AltSign] sendRequest response: \(plist)")
                completionHandler(plist as? [String: Any], nil)
            } catch {
                verboseLog("[AltSign] sendRequest failed to parse response plist. Raw: \(String(data: data, encoding: .utf8) ?? "unable to decode")")
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
}

// MARK: - Services Requests (JSON endpoints)

extension ALTAppleAPI {

    func sendServicesRequest(
        _ originalRequest: URLRequest,
        additionalParameters: [String: String]?,
        session apiSession: ALTAppleAPISession,
        team: ALTTeam,
        completionHandler: @escaping ([String: Any]?, Error?) -> Void
    ) {

        var request = originalRequest

        var items = [
            URLQueryItem(name: "teamId", value: team.identifier)
        ]

        additionalParameters?.forEach {
            items.append(.init(name: $0, value: $1))
        }

        var comps = URLComponents()
        comps.queryItems = items
        let query = comps.query ?? ""

        verboseLog("[AltSign] sendServicesRequest to: \(request.url?.absoluteString ?? "unknown URL")")
        verboseLog("[AltSign] sendServicesRequest parameters: \(additionalParameters ?? [:])")

        let bodyData: Data
        do {
            bodyData = try JSONSerialization.data(
                withJSONObject: ["urlEncodedQueryParams": query]
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

        let methodOverride = request.httpMethod
        request.httpMethod = "POST"
        request.httpBody = bodyData
        request.setValue(
            methodOverride,
            forHTTPHeaderField: "X-HTTP-Method-Override"
        )

        let a = apiSession.anisetteData

        let headers: [String: String] = [
            "Content-Type": "application/vnd.api+json",
            "User-Agent": "Xcode",
            "Accept": "application/vnd.api+json",
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
            "X-Apple-I-TimeZone": a.timeZone.abbreviation(for: a.date) ?? ""        ]

        headers.forEach {
            request.setValue($1, forHTTPHeaderField: $0)
        }

        session.dataTask(with: request) { data, _, error in
            if let error {
                verboseLog("[AltSign] sendServicesRequest failed with error: \(error)")
            }
            guard let data else {
                completionHandler(nil, error)
                return
            }

            if data.isEmpty {
                verboseLog("[AltSign] sendServicesRequest response: (empty)")
                completionHandler([:], nil)
                return
            }

            do {
                let json = try JSONSerialization.jsonObject(with: data)
                verboseLog("[AltSign] sendServicesRequest response: \(json)")
                completionHandler(json as? [String: Any], nil)
            } catch {
                verboseLog("[AltSign] sendServicesRequest failed to parse response JSON. Raw: \(String(data: data, encoding: .utf8) ?? "unable to decode")")
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
}
