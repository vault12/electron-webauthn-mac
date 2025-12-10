import Foundation
import Cocoa

@objc public class WebAuthnMac: NSObject {

    // MARK: - Error Helper

    private static func makeError(_ method: String, _ message: String) -> NSError {
        return NSError(domain: "WebAuthnMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "[WebAuthnMac.swift] \(method): \(message)"])
    }

    // MARK: - Create Credential

    @objc public static func createCredential(_ optionsDict: NSDictionary, completion: @escaping (NSDictionary?, NSError?) -> Void) {
        DispatchQueue.main.async {
            // Parse required fields
            guard let rpId = optionsDict["rpId"] as? String else {
                completion(nil, makeError("createCredential()", "rpId is required"))
                return
            }
            guard let userId = optionsDict["userId"] as? String else {
                completion(nil, makeError("createCredential()", "userId is required"))
                return
            }
            guard let name = optionsDict["name"] as? String else {
                completion(nil, makeError("createCredential()", "name is required"))
                return
            }
            guard let displayName = optionsDict["displayName"] as? String else {
                completion(nil, makeError("createCredential()", "displayName is required"))
                return
            }

            // Build options struct
            var options = PasskeyRegistrationOptions(
                rpId: rpId,
                userId: userId,
                name: name,
                displayName: displayName
            )

            // Parse optional fields
            if let authenticatorsArray = optionsDict["authenticators"] as? [String] {
                options.authenticators = authenticatorsArray.compactMap { str in
                    switch str {
                    case "platform": return .platform
                    case "securityKey": return .securityKey
                    default: return nil
                    }
                }
            }

            if let excludeCredentialsArray = optionsDict["excludeCredentials"] as? [[String: Any]] {
                options.excludeCredentials = excludeCredentialsArray.map { dict in
                    let id = dict["id"] as? String ?? ""
                    let transports = dict["transports"] as? [String]
                    return CredentialDescriptor(base64Id: id, transports: transports)
                }
            }

            if let userVerification = optionsDict["userVerification"] as? String {
                switch userVerification {
                case "required": options.userVerification = .required
                case "preferred": options.userVerification = .preferred
                case "discouraged": options.userVerification = .discouraged
                default: break
                }
            }

            if let attestation = optionsDict["attestation"] as? String {
                switch attestation {
                case "none": options.attestation = .none
                case "indirect": options.attestation = .indirect
                case "direct": options.attestation = .direct
                case "enterprise": options.attestation = .enterprise
                default: break
                }
            }

            if let largeBlobRequired = optionsDict["largeBlobRequired"] as? Bool {
                options.largeBlobRequired = largeBlobRequired
            }

            if let prfDict = optionsDict["prf"] as? [String: Any] {
                if prfDict["checkForSupport"] as? Bool == true {
                    options.prf = .checkForSupport
                } else if let evalDict = prfDict["eval"] as? [String: Any],
                          let firstBase64 = evalDict["first"] as? String,
                          let firstData = Data(base64Encoded: firstBase64) {
                    let secondData = (evalDict["second"] as? String).flatMap { Data(base64Encoded: $0) }
                    options.prf = .eval(first: firstData, second: secondData)
                }
            }

            // Create manager and perform request
            // Note: The manager is retained by the ASAuthorizationController and completion closures,
            // so we don't need to store it in a static variable (which would cause race conditions)
            let manager = PasskeyManager()

            if let window = NSApplication.shared.windows.first {
                manager.setPresentationAnchor(window)
            }

            manager.createCredential(
                options: options,
                onSuccess: { credential in
                    let result = credentialToDict(credential)
                    completion(result, nil)
                },
                onError: { error in
                    completion(nil, makeError("createCredential()", error.localizedDescription))
                }
            )
        }
    }

    // MARK: - Get Credential

    @objc public static func getCredential(_ optionsDict: NSDictionary, completion: @escaping (NSDictionary?, NSError?) -> Void) {
        DispatchQueue.main.async {
            // Parse required fields
            guard let rpId = optionsDict["rpId"] as? String else {
                completion(nil, makeError("getCredential()", "rpId is required"))
                return
            }

            // Build options struct
            var options = PasskeyAssertionOptions(rpId: rpId)

            // Parse optional fields
            if let authenticatorsArray = optionsDict["authenticators"] as? [String] {
                options.authenticators = authenticatorsArray.compactMap { str in
                    switch str {
                    case "platform": return .platform
                    case "securityKey": return .securityKey
                    default: return nil
                    }
                }
            }

            if let allowCredentialsArray = optionsDict["allowCredentials"] as? [[String: Any]] {
                options.allowCredentials = allowCredentialsArray.map { dict in
                    let id = dict["id"] as? String ?? ""
                    let transports = dict["transports"] as? [String]
                    return CredentialDescriptor(base64Id: id, transports: transports)
                }
            }

            if let userVerification = optionsDict["userVerification"] as? String {
                switch userVerification {
                case "required": options.userVerification = .required
                case "preferred": options.userVerification = .preferred
                case "discouraged": options.userVerification = .discouraged
                default: break
                }
            }

            if let largeBlobDict = optionsDict["largeBlobOperation"] as? [String: Any] {
                if largeBlobDict["read"] as? Bool == true {
                    options.largeBlobOperation = .read
                } else if let writeBase64 = largeBlobDict["write"] as? String,
                          let writeData = Data(base64Encoded: writeBase64) {
                    options.largeBlobOperation = .write(writeData)
                }
            }

            if let prfDict = optionsDict["prf"] as? [String: Any],
               let evalDict = prfDict["eval"] as? [String: Any],
               let firstBase64 = evalDict["first"] as? String,
               let firstData = Data(base64Encoded: firstBase64) {
                let secondData = (evalDict["second"] as? String).flatMap { Data(base64Encoded: $0) }
                options.prf = .eval(first: firstData, second: secondData)
            }

            // Create manager and perform request
            // Note: The manager is retained by the ASAuthorizationController and completion closures,
            // so we don't need to store it in a static variable (which would cause race conditions)
            let manager = PasskeyManager()

            if let window = NSApplication.shared.windows.first {
                manager.setPresentationAnchor(window)
            }

            manager.getCredential(
                options: options,
                onSuccess: { credential in
                    let result = assertionToDict(credential)
                    completion(result, nil)
                },
                onError: { error in
                    completion(nil, makeError("getCredential()", error.localizedDescription))
                }
            )
        }
    }

    // MARK: - Manage Passwords

    @objc public static func managePasswords() {
        DispatchQueue.main.async {
            let manager = PasskeyManager()
            manager.managePasswords()
        }
    }

    // MARK: - Response Conversion Helpers

    private static func credentialToDict(_ credential: RegistrationCredential) -> NSDictionary {
        var dict: [String: Any] = [:]

        switch credential {
        case .platform(let credentialID, let attestationObject, let clientDataJSON, let attachment, let largeBlobSupported, let prfEnabled, let prfFirst, let prfSecond):
            dict["type"] = "platform"
            dict["credentialID"] = credentialID
            dict["attestationObject"] = attestationObject
            dict["clientDataJSON"] = clientDataJSON
            if let attachment = attachment {
                dict["attachment"] = attachment
            }
            if let largeBlobSupported = largeBlobSupported {
                dict["largeBlobSupported"] = largeBlobSupported
            }
            if let prfEnabled = prfEnabled {
                dict["prfEnabled"] = prfEnabled
            }
            if let prfFirst = prfFirst {
                dict["prfFirst"] = prfFirst
            }
            if let prfSecond = prfSecond {
                dict["prfSecond"] = prfSecond
            }

        case .securityKey(let credentialID, let attestationObject, let clientDataJSON, let transports):
            dict["type"] = "securityKey"
            dict["credentialID"] = credentialID
            dict["attestationObject"] = attestationObject
            dict["clientDataJSON"] = clientDataJSON
            if let transports = transports {
                dict["transports"] = transports
            }
        }

        return dict as NSDictionary
    }

    private static func assertionToDict(_ credential: AssertionCredential) -> NSDictionary {
        var dict: [String: Any] = [:]

        switch credential {
        case .platform(let userID, let credentialID, let authenticatorData, let clientDataJSON, let signature, let attachment, let largeBlobResult, let prfEnabled, let prfFirst, let prfSecond):
            dict["type"] = "platform"
            dict["userID"] = userID
            dict["credentialID"] = credentialID
            dict["authenticatorData"] = authenticatorData
            dict["clientDataJSON"] = clientDataJSON
            dict["signature"] = signature
            if let attachment = attachment {
                dict["attachment"] = attachment
            }
            if let largeBlobResult = largeBlobResult {
                switch largeBlobResult {
                case .read(let data):
                    dict["largeBlobResult"] = [
                        "type": "read",
                        "data": data.base64EncodedString()
                    ]
                case .write(let success):
                    dict["largeBlobResult"] = [
                        "type": "write",
                        "success": success
                    ]
                }
            }
            if let prfEnabled = prfEnabled {
                dict["prfEnabled"] = prfEnabled
            }
            if let prfFirst = prfFirst {
                dict["prfFirst"] = prfFirst
            }
            if let prfSecond = prfSecond {
                dict["prfSecond"] = prfSecond
            }

        case .securityKey(let userID, let credentialID, let authenticatorData, let clientDataJSON, let signature, let appID):
            dict["type"] = "securityKey"
            dict["userID"] = userID
            dict["credentialID"] = credentialID
            dict["authenticatorData"] = authenticatorData
            dict["clientDataJSON"] = clientDataJSON
            dict["signature"] = signature
            if let appID = appID {
                dict["appID"] = appID
            }
        }

        return dict as NSDictionary
    }
}
