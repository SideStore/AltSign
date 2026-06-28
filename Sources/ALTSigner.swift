//
//  ALTSigner.swift
//  AltSign
//

import Foundation
import SwiftBridge


public final class ALTSigner: NSObject {

    // MARK: Properties

    public var team: ALTTeam
    public var certificate: ALTCertificate

    // MARK: Init

    public init(team: ALTTeam, certificate: ALTCertificate) {
        self.team = team
        self.certificate = certificate
        super.init()
    }

    // MARK: Public API (IDENTICAL SIGNATURE)

    public func signApp(
        at appURL: URL,
        provisioningProfiles profiles: [ALTProvisioningProfile],
        completionHandler: @escaping (Bool, Error?) -> Void
    ) -> Progress {

        debugLog("[AltSign] ALTSigner.signApp called at URL: \(appURL.path)")
        debugLog("[AltSign] Provisioning profiles provided: \(profiles.map { "\($0.name) (\($0.bundleIdentifier))" })")

        let progress = Progress(totalUnitCount: 1)

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.performSigning(
                    appURL: appURL,
                    profiles: profiles,
                    progress: progress
                )

                verboseLog("[AltSign] ALTSigner.signApp completed successfully for URL: \(appURL.path)")
                completionHandler(true, nil)
            } catch {
                verboseLog("[AltSign] ALTSigner.signApp failed with error: \(error)")
                completionHandler(false, error)
            }
        }

        return progress
    }
}

// MARK: - Core Signing Logic

private extension ALTSigner {

    func performSigning(
        appURL: URL,
        profiles: [ALTProvisioningProfile],
        progress: Progress
    ) throws {

        guard let application = ALTApplication(fileURL: appURL) else {
            debugLog("[AltSign] ALTSigner.performSigning error: Failed to parse ALTApplication at \(appURL.path)")
            throw NSError(
                domain: AltSignErrorDomain,
                code: ALTError.invalidApp.rawValue
            )
        }

        debugLog("[AltSign] ALTSigner.performSigning started for app: \(application.bundleIdentifier)")

        func profile(for app: ALTApplication) -> ALTProvisioningProfile? {
            for profile in profiles
            where profile.bundleIdentifier == app.bundleIdentifier {
                return profile
            }
            return profiles.first
        }

        var entitlementsByURL: [URL: String] = [:]

        func prepare(_ app: ALTApplication) throws {
            verboseLog("[AltSign] ALTSigner.prepare started for: \(app.bundleIdentifier)")

            guard let profile = profile(for: app) else {
                verboseLog("[AltSign] ALTSigner.prepare error: Missing provisioning profile for \(app.bundleIdentifier)")
                throw NSError(
                    domain: AltSignErrorDomain,
                    code: ALTError.missingProvisioningProfile.rawValue
                )
            }

            let profileURL =
                app.fileURL.appendingPathComponent("embedded.mobileprovision")

            verboseLog("[AltSign] Writing mobileprovision to: \(profileURL.path)")
            try profile.data.write(to: profileURL)

            var filtered = profile.entitlements
            verboseLog("[AltSign] Original profile entitlements: \(filtered)")

            for (key, _) in profile.entitlements {
                if app.entitlements[key] == nil {

                    if key == ALTEntitlementApplicationIdentifier ||
                       key == ALTEntitlementTeamIdentifier ||
                       key == ALTEntitlementGetTaskAllow {
                        continue
                    }

                    filtered.removeValue(forKey: key)
                }
            }

            verboseLog("[AltSign] Filtered entitlements for signing: \(filtered)")

            let stringKeyed = Dictionary(uniqueKeysWithValues: filtered.map { ($0.key.rawValue, $0.value) })
            let plist = try PropertyListSerialization.data(
                fromPropertyList: stringKeyed,
                format: .xml,
                options: 0
            )

            guard let string = String(data: plist, encoding: .utf8) else {
                verboseLog("[AltSign] ALTSigner.prepare error: Failed to convert plist data to XML string")
                throw NSError(
                    domain: AltSignErrorDomain,
                    code: ALTError.unknown.rawValue
                )
            }

            verboseLog("[AltSign] Prepared Entitlements XML:\n\(string)")

            entitlementsByURL[
                app.fileURL.resolvingSymlinksInPath()
            ] = string
        }

        try prepare(application)

        for ext in application.appExtensions {
            verboseLog("[AltSign] Found app extension: \(ext.bundleIdentifier) at \(ext.fileURL.path)")
            try prepare(ext)
        }

        // ---- LDID SIGNING VIA NATIVE BRIDGE ----

        guard let keyData = certificate.p12Data() else {
            debugLog("[AltSign] ALTSigner.performSigning error: Failed to get p12 certificate data")
            throw NSError(
                domain: AltSignErrorDomain,
                code: ALTError.unknown.rawValue
            )
        }
        
        verboseLog("[AltSign] Invoking LdidBridge.sign for appPath: \(application.fileURL.path)")
        try LdidBridge.sign(
            appPath: application.fileURL.path,
            keyData: keyData,
            entitlementProvider: { path in
                let url: URL

                if path.isEmpty {
                    url = application.fileURL
                } else {
                    url = application.fileURL
                        .appendingPathComponent(path)
                }

                let xml = entitlementsByURL[
                    url.resolvingSymlinksInPath()
                ] ?? ""
                verboseLog("[AltSign] Ldid entitlementProvider queried path: '\(path)', returning xml (length: \(xml.count))")
                return xml
            },
            progress: {
                progress.completedUnitCount += 1
            }
        )
    }
}
