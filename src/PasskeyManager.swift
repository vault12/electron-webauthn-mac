//
//  PasskeyManager.swift
//  Copyright (c) 2025 Vault12, Inc.
//
//  Used in both electron-webauthn-mac addon and dev-mac-app

import Cocoa
import AuthenticationServices
import CryptoKit

/// Options for passkey registration (WebAuthn PublicKeyCredentialCreationOptions)
struct PasskeyRegistrationOptions {
    let rpId: String                                            // Relying party identifier (domain)
    let userId: String                                          // Stable user identifier (max 64 bytes recommended)
    let name: String                                            // User's name (used for both platform and security key authentication)
    let displayName: String                                     // User's display name (used for security key only)
    var authenticators: [AuthenticatorType] = AuthenticatorType.allCases  // Which authenticator types to offer (default: both)
    var excludeCredentials: [CredentialDescriptor]? = nil       // Optional list of existing credentials to prevent re-registration
    var userVerification: UserVerificationRequirement = .preferred  // User verification requirement (default: .preferred)
    var attestation: AttestationPreference = .none              // Attestation preference (default: .none)
    var largeBlobRequired: Bool = false                         // If true, requires largeBlob support; if false, uses system default (macOS 14.0+)
                                                                // ⚠️ Platform keys only - not supported on security keys
    var prf: PRFRegistrationRequest? = nil                      // Optional PRF extension request. Use `.checkForSupport` to only check for PRF
                                                                // availability on the authenticator, or `.eval` to compute PRF values.
                                                                // ⚠️ Platform keys only - not supported on security keys (macOS 15.0+)
}

/// Options for passkey assertion (WebAuthn PublicKeyCredentialRequestOptions)
struct PasskeyAssertionOptions {
    let rpId: String                                            // Relying party identifier (domain)
    var authenticators: [AuthenticatorType] = AuthenticatorType.allCases  // Which authenticator types to offer (default: both)
    var allowCredentials: [CredentialDescriptor]? = nil         // Optional list of credentials to allow (if nil, discovers available credentials)
    var userVerification: UserVerificationRequirement = .preferred   // User verification requirement (default: .preferred)
    var largeBlobOperation: LargeBlobOperationRequest? = nil    // Optional largeBlob read/write operation (macOS 14.0+, iOS 17.0+)
                                                                // ⚠️ Platform keys only - not supported on security keys
    var prf: PRFAssertionRequest? = nil                         // Optional PRF extension request. Use `.eval` to compute PRF values
                                                                // using the credential. ⚠️ Platform keys only - not supported on security keys (macOS 15.0+, iOS 18.0+)
}

/// WebAuthn registration credential data returned after successful passkey creation
enum RegistrationCredential {
    case platform(
        credentialID: String,           // Base64-encoded credential ID - unique identifier for this credential
        attestationObject: String,      // Base64-encoded CBOR (Concise Binary Object Representation) with:
                                        //   • authData: rpIdHash(32), flags(1), signCount(4), attestedCredentialData
                                        //     - attestedCredentialData: AAGUID(16), credIdLength(2), credId, publicKey(COSE)
                                        //   • fmt: attestation format (e.g., "none", "packed", "fido-u2f")
                                        //   • attStmt: attestation statement (signature, certificates)
        clientDataJSON: String,         // Base64-encoded JSON with challenge, origin, and type (webauthn.create)
        attachment: String?,            // Authenticator attachment type: "platform" or "crossPlatform" (macOS 13.5+)
        largeBlobSupported: Bool?,      // Whether authenticator supports largeBlob extension - platform keys only (macOS 14.0+)
        prfEnabled: Bool?,              // Whether PRF extension was used - platform keys only (macOS 15.0+, iOS 18.0+)
        prfFirst: String?,              // Base64-encoded first PRF output - platform keys only (if available)
        prfSecond: String?              // Base64-encoded second PRF output - platform keys only (if available)
    )
    case securityKey(
        credentialID: String,           // Base64-encoded credential ID - unique identifier for this credential
        attestationObject: String,      // Base64-encoded CBOR (Concise Binary Object Representation) with:
                                        //   • authData: rpIdHash(32), flags(1), signCount(4), attestedCredentialData
                                        //     - attestedCredentialData: AAGUID(16), credIdLength(2), credId, publicKey(COSE)
                                        //   • fmt: attestation format (e.g., "none", "packed", "fido-u2f")
                                        //   • attStmt: attestation statement (signature, certificates)
        clientDataJSON: String,         // Base64-encoded JSON with challenge, origin, and type (webauthn.create)
        transports: [String]?           // Supported transports: usb, nfc, ble, internal, hybrid (macOS 14.5+)
    )
}

/// WebAuthn assertion credential data returned after successful authentication
enum AssertionCredential {
    case platform(
        userID: String,                 // Base64-encoded user handle (user identifier from registration)
        credentialID: String,           // Base64-encoded credential ID that was used for authentication
        authenticatorData: String,      // Base64-encoded authenticator data (rpIdHash, flags, signCount, extensions)
        clientDataJSON: String,         // Base64-encoded JSON with challenge, origin, and type (webauthn.get)
        signature: String,              // Base64-encoded signature over authenticatorData and clientDataJSON hash
        attachment: String?,            // Authenticator attachment type: "platform" or "crossPlatform" (macOS 13.5+)
        largeBlobResult: LargeBlobOperationResult?, // LargeBlob result - platform keys only (macOS 14.0+)
        prfEnabled: Bool?,              // Whether PRF extension was used - platform keys only (macOS 15.0+, iOS 18.0+)
        prfFirst: String?,              // Base64-encoded first PRF output - platform keys only (if available)
        prfSecond: String?              // Base64-encoded second PRF output - platform keys only (if available)
    )
    case securityKey(
        userID: String,                 // Base64-encoded user handle (user identifier from registration)
        credentialID: String,           // Base64-encoded credential ID that was used for authentication
        authenticatorData: String,      // Base64-encoded authenticator data (rpIdHash, flags, signCount, extensions)
        clientDataJSON: String,         // Base64-encoded JSON with challenge, origin, and type (webauthn.get)
        signature: String,              // Base64-encoded signature over authenticatorData and clientDataJSON hash
        appID: Bool?                    // Whether legacy FIDO U2F appID extension was used (macOS 14.5+)
    )
}

/// WebAuthn largeBlob operation request for credential assertion
/// ⚠️ Platform keys only - not supported on security keys (macOS 14.0+, iOS 17.0+)
enum LargeBlobOperationRequest {
    case read                           // Read blob data from authenticator
    case write(Data)                    // Write blob data to authenticator
}

/// WebAuthn largeBlob operation result returned after assertion
/// ⚠️ Platform keys only - not supported on security keys (macOS 14.0+, iOS 17.0+)
enum LargeBlobOperationResult {
    case read(Data)                     // Blob data successfully read from authenticator
    case write(Bool)                    // Write operation result: true if successful, false otherwise
}

/// WebAuthn PRF (pseudo-random function) extension request for registration.
/// Use `.checkForSupport` to query whether the authenticator supports PRF during registration,
/// or `.eval(first:second:)` to request PRF outputs at registration time. These correspond to
/// `extensions.prf === true` and `extensions.prf.eval = { first, second? }` on the web side.
/// ⚠️ Platform keys only - not supported on security keys (macOS 15.0+, iOS 18.0+)
enum PRFRegistrationRequest {
    case checkForSupport
    case eval(first: Data, second: Data?)
}

/// WebAuthn PRF extension request for assertion (get). Only `.eval` is allowed because
/// checking support is not available for assertions. Corresponds to
/// `extensions.prf.eval = { first, second? }` on the web side.
/// ⚠️ Platform keys only - not supported on security keys (macOS 15.0+, iOS 18.0+)
enum PRFAssertionRequest {
    case eval(first: Data, second: Data?)
}

/// Authenticator type selection for WebAuthn operations
enum AuthenticatorType: CaseIterable {
    case platform       // Touch ID / iCloud Keychain (built-in) / QR Code
    case securityKey    // External FIDO2 security key (USB/NFC/BLE)
}

/// WebAuthn user verification requirement
enum UserVerificationRequirement {
    case required       // User verification is required (fail if not possible)
    case preferred      // User verification is preferred but not required
    case discouraged    // User verification should not be performed

    var asPreference: ASAuthorizationPublicKeyCredentialUserVerificationPreference {
        switch self {
        case .required: return .required
        case .preferred: return .preferred
        case .discouraged: return .discouraged
        }
    }
}

/// WebAuthn attestation conveyance preference for registration
enum AttestationPreference {
    case none           // No attestation required
    case indirect       // Attestation may be anonymized
    case direct         // Direct attestation from authenticator
    case enterprise     // Enterprise attestation (requires entitlement)

    @available(macOS 13.0, iOS 16.0, *)
    var asPreference: ASAuthorizationPublicKeyCredentialAttestationKind {
        switch self {
        case .none: return .none
        case .indirect: return .indirect
        case .direct: return .direct
        case .enterprise: return .enterprise
        }
    }
}

/// WebAuthn credential descriptor for excludeCredentials / allowCredentials
struct CredentialDescriptor {
    let id: Data                        // Credential ID
    let transports: [String]?           // Optional transports: usb, nfc, ble, internal, hybrid

    init(id: Data, transports: [String]? = nil) {
        self.id = id
        self.transports = transports
    }

    /// Convenience initializer from base64-encoded credential ID.
    /// - Note: Returns empty Data if base64 decoding fails. Consider using init(id:transports:) with validated Data instead.
    init(base64Id: String, transports: [String]? = nil) {
        self.id = Data(base64Encoded: base64Id) ?? Data()
        self.transports = transports
    }
}

final class PasskeyManager: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {

    private var presentationAnchor: ASPresentationAnchor?
    private var onRegistrationSuccess: ((RegistrationCredential) -> Void)?
    private var onAssertionSuccess: ((AssertionCredential) -> Void)?
    private var onError: ((Error) -> Void)?

    /// Self-retain to prevent deallocation while waiting for ASAuthorizationController callback.
    /// ASAuthorizationController holds a weak reference to its delegate, so we need to keep
    /// ourselves alive until the callback fires. Released in delegate callbacks.
    private var selfRetain: PasskeyManager?

    /// Creates a new passkey (both platform keychain and external security key).
    ///
    /// Note: Credential algorithm is hardcoded to ES256 (ECDSA P-256 with SHA-256) as it's the only
    /// algorithm supported by Apple's AuthenticationServices SDK for security keys.
    ///
    /// - Parameters:
    ///   - options: Registration options (rpId, userId, name, etc.)
    ///   - onSuccess: Called when registration completes successfully with parsed credential
    ///   - onError: Called when registration fails
    func createCredential(
        options: PasskeyRegistrationOptions,
        onSuccess: @escaping (RegistrationCredential) -> Void,
        onError: @escaping (Error) -> Void
    ) {
        let challenge = randomChallenge(length: 32)
        guard let userIDData = options.userId.data(using: .utf8) else {
            let error = NSError(
                domain: "PasskeyManager",
                code: -2,
                userInfo: [NSLocalizedDescriptionKey: "Failed to encode userId as UTF-8"]
            )
            onError(error)
            return
        }

        // Platform (Touch ID / iCloud Keychain) registration
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options.rpId)
        let platformRegistration = platformProvider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: options.name,
            userID: userIDData
        )

        // Configure user verification
        platformRegistration.userVerificationPreference = options.userVerification.asPreference

        // Configure attestation
        if #available(macOS 13.0, iOS 16.0, *) {
            platformRegistration.attestationPreference = options.attestation.asPreference
        }

        // Configure excludeCredentials (prevent re-registration)
        if let excludeCredentials = options.excludeCredentials, !excludeCredentials.isEmpty {
            platformRegistration.excludedCredentials = excludeCredentials.map {
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0.id)
            }
        }

        // Configure largeBlob support
        if options.largeBlobRequired {
            if #available(macOS 14.0, iOS 17.0, *) {
                platformRegistration.largeBlob = .supportRequired
            }
        }

        // Configure PRF support
        if let prf = options.prf {
            if #available(macOS 15.0, iOS 18.0, *) {
                switch prf {
                case .checkForSupport:
                    platformRegistration.prf = ASAuthorizationPublicKeyCredentialPRFRegistrationInput.checkForSupport
                case .eval(let first, let second):
                    let values = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues(
                        saltInput1: first,
                        saltInput2: second
                    )
                    platformRegistration.prf = .inputValues(values)
                }
            }
        }

        // External security key registration
        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: options.rpId)
        let securityKeyRegistration = securityKeyProvider.createCredentialRegistrationRequest(
            challenge: challenge,
            displayName: options.displayName,
            name: options.name,
            userID: userIDData
        )

        // Algorithm: ES256 (only algorithm supported by Apple SDK)
        securityKeyRegistration.credentialParameters = [
            ASAuthorizationPublicKeyCredentialParameters(algorithm: .ES256)
        ]

        // Configure user verification for security key
        securityKeyRegistration.userVerificationPreference = options.userVerification.asPreference

        // Configure attestation for security key
        if #available(macOS 13.0, iOS 16.0, *) {
            securityKeyRegistration.attestationPreference = options.attestation.asPreference
        }

        // Configure excludeCredentials for security key
        if let excludeCredentials = options.excludeCredentials, !excludeCredentials.isEmpty {
            securityKeyRegistration.excludedCredentials = excludeCredentials.map { desc in
                var transports: [ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport] = []
                if let transportStrings = desc.transports {
                    transports = transportStrings.compactMap { str in
                        switch str {
                        case "usb": return .usb
                        case "nfc": return .nfc
                        case "ble": return .bluetooth
                        // Note: "internal" and "hybrid" are not exposed by ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport
                        default: return nil
                        }
                    }
                }
                return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                    credentialID: desc.id,
                    transports: transports.isEmpty ? ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported : transports
                )
            }
        }

        self.onRegistrationSuccess = onSuccess
        self.onError = onError

        // Build requests array based on selected authenticator types
        var requests: [ASAuthorizationRequest] = []
        if options.authenticators.contains(.platform) {
            requests.append(platformRegistration)
        }
        if options.authenticators.contains(.securityKey) {
            requests.append(securityKeyRegistration)
        }

        guard !requests.isEmpty else {
            let error = NSError(
                domain: "PasskeyManager",
                code: -3,
                userInfo: [NSLocalizedDescriptionKey: "At least one authenticator type must be specified"]
            )
            onError(error)
            return
        }

        // Retain self until callback fires (ASAuthorizationController.delegate is weak)
        self.selfRetain = self

        let controller = ASAuthorizationController(authorizationRequests: requests)
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests(options: [.preferImmediatelyAvailableCredentials])
    }

    /// Authenticates using an existing passkey (platform or security key).
    /// - Parameters:
    ///   - options: Assertion options (rpId, allowCredentials, userVerification, etc.)
    ///   - onSuccess: Called when authentication completes successfully with parsed credential
    ///   - onError: Called when authentication fails
    func getCredential(
        options: PasskeyAssertionOptions,
        onSuccess: @escaping (AssertionCredential) -> Void,
        onError: @escaping (Error) -> Void
    ) {
        let challenge = randomChallenge(length: 32)

        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options.rpId)
        let platformAssertion = platformProvider.createCredentialAssertionRequest(challenge: challenge)

        // Configure user verification
        platformAssertion.userVerificationPreference = options.userVerification.asPreference

        // Configure allowCredentials (limit which credentials can be used)
        if let allowCredentials = options.allowCredentials, !allowCredentials.isEmpty {
            platformAssertion.allowedCredentials = allowCredentials.map {
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0.id)
            }
        }

        // Configure largeBlob operation
        if let op = options.largeBlobOperation {
            if #available(macOS 14.0, iOS 17.0, *) {
                switch op {
                case .read:
                    platformAssertion.largeBlob = .read
                case .write(let data):
                    platformAssertion.largeBlob = .write(data)
                }
            }
        }

        // Configure PRF for assertion. Only evaluation is supported for assertions.
        if let prf = options.prf {
            if #available(macOS 15.0, iOS 18.0, *) {
                switch prf {
                case .eval(let first, let second):
                    let values: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues(
                        saltInput1: first,
                        saltInput2: second
                    )
                    platformAssertion.prf = .inputValues(values)
                }
            }
        }

        // External security key assertion (largeBlob and PRF not supported on security keys at this time)
        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: options.rpId)
        let securityKeyAssertion = securityKeyProvider.createCredentialAssertionRequest(challenge: challenge)

        // Configure user verification for security key
        securityKeyAssertion.userVerificationPreference = options.userVerification.asPreference

        // Configure allowCredentials for security key
        if let allowCredentials = options.allowCredentials, !allowCredentials.isEmpty {
            securityKeyAssertion.allowedCredentials = allowCredentials.map { desc in
                var transports: [ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport] = []
                if let transportStrings = desc.transports {
                    transports = transportStrings.compactMap { str in
                        switch str {
                        case "usb": return .usb
                        case "nfc": return .nfc
                        case "ble": return .bluetooth
                        // Note: "internal" and "hybrid" are not exposed by ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport
                        default: return nil
                        }
                    }
                }
                return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                    credentialID: desc.id,
                    transports: transports.isEmpty ? ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported : transports
                )
            }
        }

        self.onAssertionSuccess = onSuccess
        self.onError = onError

        // Build requests array based on selected authenticator types
        var requests: [ASAuthorizationRequest] = []
        if options.authenticators.contains(.platform) {
            requests.append(platformAssertion)
        }
        if options.authenticators.contains(.securityKey) {
            requests.append(securityKeyAssertion)
        }

        guard !requests.isEmpty else {
            let error = NSError(
                domain: "PasskeyManager",
                code: -3,
                userInfo: [NSLocalizedDescriptionKey: "At least one authenticator type must be specified"]
            )
            onError(error)
            return
        }

        // Retain self until callback fires (ASAuthorizationController.delegate is weak)
        self.selfRetain = self

        let controller = ASAuthorizationController(authorizationRequests: requests)
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests(options: [.preferImmediatelyAvailableCredentials])
    }

    /// Opens the Passwords app or System Settings → Passwords so the user can manage passkeys.
    func managePasswords() {
        // 1) Try the dedicated Passwords app (macOS 15+)
        let passwordsBundleIDs = ["com.apple.Passwords", "com.apple.passwords"]
        for bid in passwordsBundleIDs {
            if let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bid) {
                NSWorkspace.shared.open(appURL)
                return
            }
        }
        let possibleAppPaths = [
            "/System/Applications/Passwords.app",
            "/Applications/Passwords.app"
        ]
        for path in possibleAppPaths {
            if FileManager.default.fileExists(atPath: path) {
                let appURL = URL(fileURLWithPath: path)
                if NSWorkspace.shared.open(appURL) { return }
            }
        }

        // 2) Legacy: open System Settings → Passwords pane
        let candidates = [
            "x-apple.systempreferences:com.apple.Passwords-Settings.extension", // Ventura/Sonoma+
            "x-apple.systempreferences:com.apple.Passwords" // older fallback
        ]
        for scheme in candidates {
            if let url = URL(string: scheme), NSWorkspace.shared.open(url) {
                return
            }
        }

        // 3) Final fallback: open System Settings app
        if let appURL = URL(string: "file:///System/Applications/System%20Settings.app") {
            NSWorkspace.shared.open(appURL)
        }
    }

    func setPresentationAnchor(_ anchor: ASPresentationAnchor) {
        self.presentationAnchor = anchor
    }

    // MARK: - Private Helpers

    private func randomChallenge(length: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }

    /// Encodes a `SymmetricKey` into a Base64 string. Useful for PRF outputs.
    private func symmetricKeyToBase64(_ key: SymmetricKey) -> String {
        return key.withUnsafeBytes { Data($0).base64EncodedString() }
    }

    // MARK: - ASAuthorizationControllerDelegate

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        switch authorization.credential {
        case let cred as ASAuthorizationPlatformPublicKeyCredentialRegistration:
            var attachment: String? = nil
            var largeBlobSupported: Bool? = nil
            var prfEnabled: Bool? = nil
            var prfFirst: String? = nil
            var prfSecond: String? = nil
            if #available(macOS 13.5, *) {
                attachment = cred.attachment == .platform ? "platform" : "crossPlatform"
            }
            if #available(macOS 14.0, iOS 17.0, *) {
                largeBlobSupported = cred.largeBlob?.isSupported
            }
            if #available(macOS 15.0, iOS 18.0, *) {
                if let prfOutput = cred.prf {
                    prfEnabled = prfOutput.isSupported
                    if let firstKey = prfOutput.first {
                        prfFirst = symmetricKeyToBase64(firstKey)
                    }
                    if let secondKey = prfOutput.second {
                        prfSecond = symmetricKeyToBase64(secondKey)
                    }
                }
            }
            let credential = RegistrationCredential.platform(
                credentialID: cred.credentialID.base64EncodedString(),
                attestationObject: cred.rawAttestationObject?.base64EncodedString() ?? "",
                clientDataJSON: cred.rawClientDataJSON.base64EncodedString(),
                attachment: attachment,
                largeBlobSupported: largeBlobSupported,
                prfEnabled: prfEnabled,
                prfFirst: prfFirst,
                prfSecond: prfSecond
            )
            onRegistrationSuccess?(credential)

        case let cred as ASAuthorizationSecurityKeyPublicKeyCredentialRegistration:
            var transports: [String]? = nil
            if #available(macOS 14.5, *) {
                transports = cred.transports.map { $0.rawValue }
            }
            let credential = RegistrationCredential.securityKey(
                credentialID: cred.credentialID.base64EncodedString(),
                attestationObject: cred.rawAttestationObject?.base64EncodedString() ?? "",
                clientDataJSON: cred.rawClientDataJSON.base64EncodedString(),
                transports: transports
            )
            onRegistrationSuccess?(credential)

        case let cred as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            var attachment: String? = nil
            var largeBlobResult: LargeBlobOperationResult? = nil
            var prfEnabled: Bool? = nil
            var prfFirst: String? = nil
            var prfSecond: String? = nil
            if #available(macOS 13.5, *) {
                attachment = cred.attachment == .platform ? "platform" : "crossPlatform"
            }
            if #available(macOS 14.0, iOS 17.0, *) {
                if let largeBlobOutput = cred.largeBlob {
                    switch largeBlobOutput.result {
                    case .read(data: let data):
                        if let data = data {
                            largeBlobResult = .read(data)
                        }
                    case .write(success: let success):
                        largeBlobResult = .write(success)
                    default:
                        break
                    }
                }
            }
            if #available(macOS 15.0, iOS 18.0, *) {
                let prfOutput = cred.prf
                if let firstKey = prfOutput?.first {
                    prfFirst = symmetricKeyToBase64(firstKey)
                }
                if let secondKey = prfOutput?.second {
                    prfSecond = symmetricKeyToBase64(secondKey)
                }
                prfEnabled = (prfFirst != nil || prfSecond != nil)

            }
            let credential = AssertionCredential.platform(
                userID: cred.userID.base64EncodedString(),
                credentialID: cred.credentialID.base64EncodedString(),
                authenticatorData: cred.rawAuthenticatorData.base64EncodedString(),
                clientDataJSON: cred.rawClientDataJSON.base64EncodedString(),
                signature: cred.signature.base64EncodedString(),
                attachment: attachment,
                largeBlobResult: largeBlobResult,
                prfEnabled: prfEnabled,
                prfFirst: prfFirst,
                prfSecond: prfSecond
            )
            onAssertionSuccess?(credential)

        case let cred as ASAuthorizationSecurityKeyPublicKeyCredentialAssertion:
            var appID: Bool? = nil
            if #available(macOS 14.5, *) {
                appID = cred.appID
            }
            // Note: securityKey does not support largeBlob or PRF in current SDK
            let credential = AssertionCredential.securityKey(
                userID: cred.userID.base64EncodedString(),
                credentialID: cred.credentialID.base64EncodedString(),
                authenticatorData: cred.rawAuthenticatorData.base64EncodedString(),
                clientDataJSON: cred.rawClientDataJSON.base64EncodedString(),
                signature: cred.signature.base64EncodedString(),
                appID: appID
            )
            onAssertionSuccess?(credential)

        default:
            let error = NSError(
                domain: "PasskeyManager",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Unhandled credential type: \(type(of: authorization.credential))"]
            )
            onError?(error)
        }

        self.onRegistrationSuccess = nil
        self.onAssertionSuccess = nil
        self.onError = nil
        self.selfRetain = nil  // Release self-retain
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        onError?(error)
        onRegistrationSuccess = nil
        onAssertionSuccess = nil
        onError = nil
        selfRetain = nil  // Release self-retain
    }

    // MARK: - ASAuthorizationControllerPresentationContextProviding
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        if let anchor = presentationAnchor {
            return anchor
        }
        if let window = NSApplication.shared.keyWindow {
            return window
        }
        if let window = NSApplication.shared.windows.first {
            return window
        }
        // Last resort: create a new window (shouldn't normally happen in a proper app)
        return NSWindow()
    }
}
