//
//  ViewController.swift
//  WebAuthnPlayground
//
//  Copyright (c) 2025 Vault12, Inc.
//

import Cocoa
import AuthenticationServices
import CryptoKit

final class ViewController: NSViewController {

    @IBOutlet weak var resultTextView: NSClipView!
    @IBOutlet weak var clearTextField: NSTextField!
    @IBOutlet weak var cipherTextField: NSTextField!
    private let rpId = "example.com"
    private let prfSalt = "WebAuthnPlayground-PRF-Salt-v1".data(using: .utf8)!
    private lazy var passkeyManager = PasskeyManager()

    @IBAction func authorizePressed(_ sender: NSButton) {
        authorize()
    }

    @IBAction func largeBlobWritePressed(_ sender: NSButton) {
        let testData = "Test blob data from macOS".data(using: .utf8)!
        authorize(largeBlobOperation: LargeBlobOperationRequest.write(testData))
    }

    @IBAction func largeBlobReadPressed(_ sender: NSButton) {
        authorize(largeBlobOperation: LargeBlobOperationRequest.read)
    }

    @IBAction func encryptPrfPressed(_ sender: NSButton) {
        let plaintext = clearTextField.stringValue
        guard !plaintext.isEmpty else {
            showResult("❌ Enter text to encrypt in the Clear Text field")
            return
        }

        passkeyManager.setPresentationAnchor(view.window ?? NSApplication.shared.windows.first!)
        passkeyManager.getCredential(
            options: PasskeyAssertionOptions(rpId: rpId, prf: .eval(first: prfSalt, second: nil)),
            onSuccess: { [weak self] credential in
                guard let self = self else { return }

                switch credential {
                case .platform(_, _, _, _, _, _, _, _, let prfFirst, _):
                    guard let prfKeyBase64 = prfFirst,
                          let prfKeyData = Data(base64Encoded: prfKeyBase64) else {
                        self.showResult("❌ PRF not supported or no key returned")
                        return
                    }

                    do {
                        let ciphertext = try self.encryptAESGCM(plaintext: plaintext, keyData: prfKeyData)
                        DispatchQueue.main.async {
                            self.cipherTextField.stringValue = ciphertext
                        }
                        let prfPreview = String(prfKeyBase64.prefix(16)) + "..."
                        self.showResult("""
                        🔐 ENCRYPTION SUCCESS

                        Plaintext: \(plaintext)

                        Ciphertext (Base64): \(ciphertext)

                        📊 PRF Details:
                        • Salt: \(self.prfSalt.base64EncodedString())
                        • PRF Key (first 16 chars): \(prfPreview)
                        • Key Size: \(prfKeyData.count) bytes
                        """)
                    } catch {
                        self.showResult("❌ Encryption failed: \(error.localizedDescription)")
                    }

                case .securityKey:
                    self.showResult("❌ PRF not supported on security keys")
                }
            },
            onError: { [weak self] error in
                self?.showResult("❌ PRF Error: \(error.localizedDescription)")
            }
        )
    }

    @IBAction func decryptPrfPressed(_ sender: NSButton) {
        let ciphertext = cipherTextField.stringValue
        guard !ciphertext.isEmpty else {
            showResult("❌ No ciphertext to decrypt in the Cipher Text field")
            return
        }

        passkeyManager.setPresentationAnchor(view.window ?? NSApplication.shared.windows.first!)
        passkeyManager.getCredential(
            options: PasskeyAssertionOptions(rpId: rpId, prf: .eval(first: prfSalt, second: nil)),
            onSuccess: { [weak self] credential in
                guard let self = self else { return }

                switch credential {
                case .platform(_, _, _, _, _, _, _, _, let prfFirst, _):
                    guard let prfKeyBase64 = prfFirst,
                          let prfKeyData = Data(base64Encoded: prfKeyBase64) else {
                        self.showResult("❌ PRF not supported or no key returned")
                        return
                    }

                    do {
                        let plaintext = try self.decryptAESGCM(ciphertext: ciphertext, keyData: prfKeyData)
                        DispatchQueue.main.async {
                            self.clearTextField.stringValue = plaintext
                        }
                        let prfPreview = String(prfKeyBase64.prefix(16)) + "..."
                        self.showResult("""
                        🔓 DECRYPTION SUCCESS

                        Ciphertext (Base64): \(ciphertext)

                        Plaintext: \(plaintext)

                        📊 PRF Details:
                        • Salt: \(self.prfSalt.base64EncodedString())
                        • PRF Key (first 16 chars): \(prfPreview)
                        • Key Size: \(prfKeyData.count) bytes
                        """)
                    } catch {
                        self.showResult("❌ Decryption failed: \(error.localizedDescription)")
                    }

                case .securityKey:
                    self.showResult("❌ PRF not supported on security keys")
                }
            },
            onError: { [weak self] error in
                self?.showResult("❌ PRF Error: \(error.localizedDescription)")
            }
        )
    }

    private func authorize(largeBlobOperation: LargeBlobOperationRequest? = nil) {
        passkeyManager.setPresentationAnchor(view.window ?? NSApplication.shared.windows.first!)
        passkeyManager.getCredential(
            options: PasskeyAssertionOptions(rpId: rpId, authenticators: [.platform, .securityKey], userVerification: .required, largeBlobOperation: largeBlobOperation),
            onSuccess: { [weak self] credential in
                guard let self = self else { return }

                switch credential {
                case .platform(let userID, let credentialID, let authenticatorData, let clientDataJSON, let signature, let attachment, let largeBlobResult, _, _, _):
                    print("=== AUTHENTICATION SUCCESS (Platform) ===")
                    print("User ID:", userID)
                    print("Credential ID:", credentialID)
                    print("Authenticator Data:", authenticatorData)
                    print("Client Data JSON:", clientDataJSON)
                    print("Signature:", signature)
                    if let attachment = attachment {
                        print("Attachment:", attachment)
                    }
                    let authDataInfo = self.parseAuthenticatorData(authenticatorData)
                    let formattedClientData = self.formatClientDataJSON(clientDataJSON)
                    let attachmentLine = attachment != nil ? "\n\nAttachment: \(attachment!)" : ""
                    var largeBlobLine = ""
                    var largeBlobDetailLine = ""
                    if let largeBlobResult = largeBlobResult {
                        switch largeBlobResult {
                        case .read(let data):
                            let base64 = data.base64EncodedString()
                            let stringValue = String(data: data, encoding: .utf8) ?? "(non-UTF8 data)"
                            print("Large Blob Read (Base64):", base64)
                            print("Large Blob Read (String):", stringValue)
                            largeBlobLine = "\n\nLarge Blob Read:\n  String: \(stringValue)\n  Base64: \(base64)"
                            largeBlobDetailLine = "\n• Large Blob Read: \(data.count) bytes\n• String: \(stringValue)"
                        case .write(let success):
                            print("Large Blob Write Success:", success)
                            largeBlobLine = "\n\nLarge Blob Write: \(success ? "✅ Success" : "❌ Failed")"
                            largeBlobDetailLine = "\n• Large Blob Write: \(success ? "✅" : "❌")"
                        }
                    }
                    let result = """
                    ✅ AUTHENTICATION SUCCESS (Platform)

                    User ID: \(userID)

                    Credential ID: \(credentialID)

                    Authenticator Data: \(authenticatorData)

                    Client Data JSON: \(clientDataJSON)

                    Signature: \(signature)\(attachmentLine)\(largeBlobLine)

                    📊 Authenticator Data Details:
                    • RP ID Hash: \(authDataInfo.rpIdHash)
                    • User Present: \(authDataInfo.userPresent ? "✅" : "❌")
                    • User Verified: \(authDataInfo.userVerified ? "✅" : "❌")
                    • Sign Count: \(authDataInfo.signCount)\(attachment != nil ? "\n• Attachment: \(attachment!)" : "")\(largeBlobDetailLine)

                    📊 Client Data JSON (decoded):
                    \(formattedClientData)
                    """
                    self.showResult(result)

                case .securityKey(let userID, let credentialID, let authenticatorData, let clientDataJSON, let signature, let appID):
                    print("=== AUTHENTICATION SUCCESS (Security Key) ===")
                    print("User ID:", userID)
                    print("Credential ID:", credentialID)
                    print("Authenticator Data:", authenticatorData)
                    print("Client Data JSON:", clientDataJSON)
                    print("Signature:", signature)
                    if let appID = appID {
                        print("AppID Extension:", appID)
                    }

                    let authDataInfo = self.parseAuthenticatorData(authenticatorData)
                    let formattedClientData = self.formatClientDataJSON(clientDataJSON)
                    let appIDLine = appID != nil ? "\n\nAppID Extension: \(appID! ? "true" : "false")" : ""
                    let result = """
                    ✅ AUTHENTICATION SUCCESS (Security Key)

                    User ID: \(userID)

                    Credential ID: \(credentialID)

                    Authenticator Data: \(authenticatorData)

                    Client Data JSON: \(clientDataJSON)

                    Signature: \(signature)\(appIDLine)

                    📊 Authenticator Data Details:
                    • RP ID Hash: \(authDataInfo.rpIdHash)
                    • User Present: \(authDataInfo.userPresent ? "✅" : "❌")
                    • User Verified: \(authDataInfo.userVerified ? "✅" : "❌")
                    • Sign Count: \(authDataInfo.signCount)\(appID != nil ? "\n• AppID Extension: \(appID! ? "✅" : "❌")" : "")

                    📊 Client Data JSON (decoded):
                    \(formattedClientData)
                    """
                    self.showResult(result)
                }
            },
            onError: { [weak self] error in
                print("Authorization error:", error.localizedDescription)
                self?.showResult("Error: \(error.localizedDescription)")
            }
        )
    }

    @IBAction func registerPressed(_ sender: NSButton) {
        register()
    }

    /// Creates a new passkey for the RP ID (both platform keychain and external security key).
    private func register() {
        // Use a stable user handle from your backend (max 64 bytes recommended).
        let userId = "demo-user-\(UUID().uuidString)"
        let name = "Demo User"
        let displayName = "Demo User Display Name"

        passkeyManager.setPresentationAnchor(view.window ?? NSApplication.shared.windows.first!)
        passkeyManager.createCredential(
            options: PasskeyRegistrationOptions(rpId: rpId, userId: userId, name: name, displayName: displayName, authenticators: [.platform, .securityKey], userVerification: .required, attestation: .none),
            onSuccess: { [weak self] credential in
                guard let self = self else { return }

                switch credential {
                case .platform(let credentialID, let attestationObject, let clientDataJSON, let attachment, let largeBlobSupported, _, _, _):
                    print("=== REGISTRATION SUCCESS (Platform) ===")
                    print("Credential ID:", credentialID)
                    print("Attestation Object:", attestationObject)
                    print("Client Data JSON:", clientDataJSON)
                    if let attachment = attachment {
                        print("Attachment:", attachment)
                    }
                    if let largeBlobSupported = largeBlobSupported {
                        print("Large Blob Supported:", largeBlobSupported)
                    }

                    let attestInfo = self.parseAttestationObject(attestationObject)
                    let formattedClientData = self.formatClientDataJSON(clientDataJSON)
                    let attachmentLine = attachment != nil ? "\n\nAttachment: \(attachment!)" : ""
                    let largeBlobLine = largeBlobSupported != nil ? "\n\nLarge Blob Supported: \(largeBlobSupported! ? "✅" : "❌")" : ""
                    let largeBlobStr = largeBlobSupported != nil ? "\n• Large Blob Supported: \(largeBlobSupported! ? "✅" : "❌")" : ""
                    let result = """
                    ✅ REGISTRATION SUCCESS (Platform)

                    Credential ID: \(credentialID)

                    Attestation Object: \(attestationObject)

                    Client Data JSON: \(clientDataJSON)\(attachmentLine)\(largeBlobLine)

                    📊 Attestation Object Details:
                    • RP ID Hash: \(attestInfo.rpIdHash)
                    • User Present: \(attestInfo.userPresent ? "✅" : "❌")
                    • User Verified: \(attestInfo.userVerified ? "✅" : "❌")
                    • Attested Credential: \(attestInfo.hasAttestedCredential ? "✅" : "❌")
                    • Sign Count: \(attestInfo.signCount)
                    • Public Key Length: \(attestInfo.publicKeyLength) bytes\(attachment != nil ? "\n• Attachment: \(attachment!)" : "")\(largeBlobStr)
                    • Format (fmt): \(attestInfo.fmt)
                    • Attestation Statement: \(attestInfo.attStmt)

                    📊 Attested Credential Data:
                    • AAGUID: \(attestInfo.aaguid)
                    • Credential ID Length: \(attestInfo.credentialIdLength) bytes

                    📊 Client Data JSON (decoded):
                    \(formattedClientData)
                    """
                    self.showResult(result)

                case .securityKey(let credentialID, let attestationObject, let clientDataJSON, let transports):
                    print("=== REGISTRATION SUCCESS (Security Key) ===")
                    print("Credential ID:", credentialID)
                    print("Attestation Object:", attestationObject)
                    print("Client Data JSON:", clientDataJSON)
                    if let transports = transports {
                        print("Transports:", transports.joined(separator: ", "))
                    }

                    let attestInfo = self.parseAttestationObject(attestationObject)
                    let formattedClientData = self.formatClientDataJSON(clientDataJSON)
                    let transportsLine = transports != nil ? "\n\nTransports: \(transports!.joined(separator: ", "))" : ""
                    let transportsStr = transports != nil ? "\n• Transports: \(transports!.joined(separator: ", "))" : ""
                    let result = """
                    ✅ REGISTRATION SUCCESS (Security Key)

                    Credential ID: \(credentialID)

                    Attestation Object: \(attestationObject)

                    Client Data JSON: \(clientDataJSON)\(transportsLine)

                    📊 Attestation Object Details:
                    • RP ID Hash: \(attestInfo.rpIdHash)
                    • User Present: \(attestInfo.userPresent ? "✅" : "❌")
                    • User Verified: \(attestInfo.userVerified ? "✅" : "❌")
                    • Attested Credential: \(attestInfo.hasAttestedCredential ? "✅" : "❌")
                    • Sign Count: \(attestInfo.signCount)
                    • Public Key Length: \(attestInfo.publicKeyLength) bytes\(transportsStr)
                    • Format (fmt): \(attestInfo.fmt)
                    • Attestation Statement: \(attestInfo.attStmt)

                    📊 Attested Credential Data:
                    • AAGUID: \(attestInfo.aaguid)
                    • Credential ID Length: \(attestInfo.credentialIdLength) bytes

                    📊 Client Data JSON (decoded):
                    \(formattedClientData)
                    """
                    self.showResult(result)
                }
            },
            onError: { [weak self] error in
                print("Registration error:", error.localizedDescription)
                self?.showResult("Error: \(error.localizedDescription)")
            }
        )
    }

    @IBAction func deletePasskeyPressed(_ sender: NSButton) {
        // Apple does not provide a public API to programmatically delete passkeys from iCloud Keychain.
        // Open System Settings → Passwords so the user can remove the passkey for this RP ID manually.
        showResult("Opening Passwords. Remove the passkey for \"\(rpId)\" to reset the demo.")
        passkeyManager.managePasswords()
    }

    private func showResult(_ text: String) {
        DispatchQueue.main.async { [weak self] in
            guard let textView = self?.resultTextView?.documentView as? NSTextView else { return }
            textView.string = text
            // Scroll to top
            textView.scrollToBeginningOfDocument(nil)
        }
    }

    // MARK: - WebAuthn Data Parsing

    private struct AuthDataInfo {
        let rpIdHash: String
        let userPresent: Bool
        let userVerified: Bool
        let signCount: UInt32
    }

    private struct AttestationInfo {
        let rpIdHash: String
        let userPresent: Bool
        let userVerified: Bool
        let hasAttestedCredential: Bool
        let signCount: UInt32
        let publicKeyLength: Int
        let fmt: String
        let attStmt: String
        let aaguid: String
        let credentialIdLength: Int
    }

    private func parseAuthenticatorData(_ base64String: String) -> AuthDataInfo {
        guard let data = Data(base64Encoded: base64String), data.count >= 37 else {
            return AuthDataInfo(rpIdHash: "Invalid", userPresent: false, userVerified: false, signCount: 0)
        }

        // rpIdHash: first 32 bytes (full hex representation)
        let rpIdHash = data.subdata(in: 0..<32).map { String(format: "%02x", $0) }.joined()

        // flags: byte 32
        let flags = data[32]
        let userPresent = (flags & 0x01) != 0  // bit 0: User Present
        let userVerified = (flags & 0x04) != 0 // bit 2: User Verified

        // signCount: bytes 33-36 (big-endian UInt32)
        let signCount = data.subdata(in: 33..<37).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

        return AuthDataInfo(
            rpIdHash: rpIdHash,
            userPresent: userPresent,
            userVerified: userVerified,
            signCount: signCount
        )
    }

    private func parseAttestationObject(_ base64String: String) -> AttestationInfo {
        guard let data = Data(base64Encoded: base64String) else {
            return AttestationInfo(rpIdHash: "Invalid", userPresent: false, userVerified: false, hasAttestedCredential: false, signCount: 0, publicKeyLength: 0, fmt: "N/A", attStmt: "N/A", aaguid: "N/A", credentialIdLength: 0)
        }

        // Parse fmt (attestation format) - typically "none", "packed", "fido-u2f", etc.
        var fmt = "unknown"
        let fmtMarker = Data([0x63, 0x66, 0x6d, 0x74]) // "fmt" in CBOR
        if let fmtRange = data.range(of: fmtMarker), fmtRange.upperBound < data.count {
            let fmtStart = fmtRange.upperBound
            if data[fmtStart] == 0x64 { // text string of length 4
                let fmtEnd = fmtStart + 5
                if fmtEnd <= data.count {
                    fmt = String(data: data.subdata(in: (fmtStart + 1)..<fmtEnd), encoding: .utf8) ?? "unknown"
                }
            } else if data[fmtStart] == 0x68 { // text string of length 8
                let fmtEnd = fmtStart + 9
                if fmtEnd <= data.count {
                    fmt = String(data: data.subdata(in: (fmtStart + 1)..<fmtEnd), encoding: .utf8) ?? "unknown"
                }
            }
        }

        // Check for attStmt
        let attStmtMarker = Data([0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74]) // "attStmt" in CBOR
        let attStmt = data.range(of: attStmtMarker) != nil ? "present" : "absent"

        // Try to find authData bytes (typically after "authData" key in CBOR)
        let authDataMarker = Data([0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61]) // "authData" in CBOR

        if let range = data.range(of: authDataMarker) {
            let afterMarker = range.upperBound
            if afterMarker + 1 < data.count {
                let lengthByte = data[afterMarker]
                var authDataStart = afterMarker + 1

                // Handle CBOR byte string length encoding
                if lengthByte >= 0x58 && lengthByte <= 0x5b {
                    let lengthSize = Int(lengthByte - 0x57)
                    authDataStart += lengthSize
                }

                if authDataStart + 55 <= data.count { // Need at least 55 bytes for AAGUID + credIdLength
                    let authData = data.subdata(in: authDataStart..<data.count)

                    let rpIdHash = authData.subdata(in: 0..<32).map { String(format: "%02x", $0) }.joined()
                    let flags = authData[32]
                    let userPresent = (flags & 0x01) != 0
                    let userVerified = (flags & 0x04) != 0
                    let hasAttestedCredential = (flags & 0x40) != 0

                    let signCount = authData.subdata(in: 33..<37).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

                    // attestedCredentialData starts at byte 37
                    var aaguid = "N/A"
                    var credIdLength = 0
                    var publicKeyLength = 0

                    if hasAttestedCredential && authData.count >= 55 {
                        // AAGUID: bytes 37-52 (16 bytes)
                        aaguid = authData.subdata(in: 37..<53).map { String(format: "%02x", $0) }.joined()

                        // Credential ID Length: bytes 53-54 (2 bytes, big-endian)
                        credIdLength = Int(authData.subdata(in: 53..<55).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })

                        // Public key starts after: 37 (start) + 16 (AAGUID) + 2 (length) + credIdLength
                        let publicKeyStart = 55 + credIdLength
                        publicKeyLength = max(0, authData.count - publicKeyStart)
                    } else {
                        publicKeyLength = max(0, authData.count - 37)
                    }

                    return AttestationInfo(
                        rpIdHash: rpIdHash,
                        userPresent: userPresent,
                        userVerified: userVerified,
                        hasAttestedCredential: hasAttestedCredential,
                        signCount: signCount,
                        publicKeyLength: publicKeyLength,
                        fmt: fmt,
                        attStmt: attStmt,
                        aaguid: aaguid,
                        credentialIdLength: credIdLength
                    )
                }
            }
        }

        return AttestationInfo(rpIdHash: "N/A", userPresent: false, userVerified: false, hasAttestedCredential: false, signCount: 0, publicKeyLength: 0, fmt: fmt, attStmt: attStmt, aaguid: "N/A", credentialIdLength: 0)
    }

    private func formatClientDataJSON(_ base64String: String) -> String {
        guard let data = Data(base64Encoded: base64String),
              let jsonString = String(data: data, encoding: .utf8),
              let jsonData = jsonString.data(using: .utf8),
              let jsonObject = try? JSONSerialization.jsonObject(with: jsonData),
              let prettyData = try? JSONSerialization.data(withJSONObject: jsonObject, options: [.prettyPrinted, .sortedKeys]),
              let prettyString = String(data: prettyData, encoding: .utf8) else {
            return "Invalid JSON"
        }

        return prettyString
    }

    // MARK: - AES-GCM Encryption/Decryption

    private func encryptAESGCM(plaintext: String, keyData: Data) throws -> String {
        let key = SymmetricKey(data: keyData)
        let plaintextData = plaintext.data(using: .utf8)!
        let sealedBox = try AES.GCM.seal(plaintextData, using: key)
        return sealedBox.combined!.base64EncodedString()
    }

    private func decryptAESGCM(ciphertext: String, keyData: Data) throws -> String {
        guard let ciphertextData = Data(base64Encoded: ciphertext) else {
            throw NSError(domain: "ViewController", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid base64 ciphertext"])
        }
        let key = SymmetricKey(data: keyData)
        let sealedBox = try AES.GCM.SealedBox(combined: ciphertextData)
        let decryptedData = try AES.GCM.open(sealedBox, using: key)
        guard let plaintext = String(data: decryptedData, encoding: .utf8) else {
            throw NSError(domain: "ViewController", code: -2, userInfo: [NSLocalizedDescriptionKey: "Decrypted data is not valid UTF-8"])
        }
        return plaintext
    }

}
