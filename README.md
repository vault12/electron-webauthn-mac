# electron-webauthn-mac

<p align="center">
  <img src="https://github.com/user-attachments/assets/af771649-da55-4c97-8ce8-55e25f9fe490"
    alt="Electron Webauthn Mac">
</p>

<p align="center">
  <strong>Native WebAuthn/Passkey support for Electron on macOS</strong>
</p>

<p align="center">
  <a href="https://www.electronjs.org"><img src="https://img.shields.io/badge/electron-addon-blue?logo=electron&logoColor=white" alt="Electron Addon" /></a>
  <a href="https://github.com/vault12/electron-webauthn-mac/releases"><img src="https://img.shields.io/npm/v/electron-webauthn-mac" alt="NPM Release" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License" /></a>
  <a href="http://makeapullrequest.com"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome" /></a>
  <a href="https://www.npmjs.com/package/electron-webauthn-mac"><img src="https://img.shields.io/npm/dm/electron-webauthn-mac" alt="Downloads" /></a>
  <a href="https://www.typescriptlang.org"><img src="https://img.shields.io/badge/typescript-supported-blue?logo=typescript&logoColor=white" alt="Typescript" /></a>
</p>

---

## Contents

- [Why This Addon?](#why-this-addon)
- [Features](#features)
- [Quick Start](#quick-start)
- [Example Electron App](#example-electron-app)
- [Configuring Entitlements and Domain Association](#configuring-entitlements-and-domain-association)
- [Provisioning Profile Setup](#provisioning-profile-setup)
- [API Reference](#api-reference)
- [macOS Platform Quirks](#macos-platform-quirks)
- [Troubleshooting](#troubleshooting)
- [Plugin Development](#plugin-development)
- [License](#license)

## Why This Addon?

The [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) `navigator.credentials` is the standard way to implement passkey authentication in web applications. However, in [Electron](https://www.electronjs.org) applications running on macOS, this API is currently broken and non-functional due to platform-specific limitations (see [electron/electron#24573](https://github.com/electron/electron/issues/24573)).

This addon serves as a native implementation and polyfill for macOS, providing direct access to Apple's [AuthenticationServices](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys) framework. It allows Electron applications to use passkey authentication on macOS while maintaining the option to use the standard Web Authentication API on other platforms.

## Features

- **Platform & security key authenticators**: Support for Touch ID, iCloud Keychain, cross-device QR pairing, and external FIDO2 keys
- **PRF extension**: Derive symmetric keys from passkeys for client-side encryption (platform authenticators only)
- **LargeBlob extension**: Store and retrieve arbitrary data on the authenticator (platform authenticators only)
- **System integration**: Open macOS password manager directly from your Electron app
- **TypeScript support**: Full type definitions included

## Quick Start

### 1. Install the addon

```bash
npm install electron-webauthn-mac
```

### 2. Use the API

Basic example:

```javascript
const webauthn = require('electron-webauthn-mac');

// Create a new passkey
async function registerUser() {
  try {
    const credential = await webauthn.createCredential({
      rpId: 'example.com', userId: 'user123', name: 'John', displayName: 'John Doe'
    });
    console.log('Created credential:', credential);
  } catch (error) {
    console.error('Registration failed:', error);
  }
}

// Authenticate with an existing passkey
async function authenticateUser() {
  try {
    const assertion = await webauthn.getCredential({ rpId: 'example.com' });
    console.log('Authentication successful:', assertion);
  } catch (error) {
    console.error('Authentication failed:', error);
  }
}
```

> [!TIP]
> For cross-platform implementation, use the following pattern:
> ```javascript
> async function createPasskey(userId, userName, rpId) {
>   if (process.platform === 'darwin') { // Use native addon on macOS
>     const webauthn = require('electron-webauthn-mac');
>     return await webauthn.createCredential({ ... });
>   } else { // Use standard Web Authentication API on other platforms
>     return await navigator.credentials.create({ ... });
>   }
> }
> ```

> [!NOTE]
> **TypeScript** definitions are included. Import types directly:
>
> ```typescript
> import type {
>   CreateCredentialOptions, GetCredentialOptions,
>   RegistrationCredential, AssertionCredential
> } from 'electron-webauthn-mac';
> ```

### 3. Configure the entitlements and domain association

Unlike browser-based WebAuthn, macOS requires your app to prove it has association with the domain used as `rpId`. Follow the steps in [Configuring Entitlements and Domain Association](#configuring-entitlements-and-domain-association) to set this up. See [Why is domain association required?](#why-is-domain-association-required) for details.

### 4. Sign and run the app

Your Electron app must be code-signed to embed the entitlements from step 3 into the final `.app` bundle. Follow [Provisioning Profile Setup](#provisioning-profile-setup) to install the required provisioning profile. Running with `npm start` or `electron .` will launch the app, but passkey operations will fail because the unsigned process lacks an application identifier.

Use a tool like [electron-builder](https://www.electron.build/) to build a signed `.app` bundle. See the [Example Electron App](#example-electron-app) for a working configuration.

## Example Electron App

<img width="300" height="213" align="right" alt="Example Electron app" src="https://github.com/user-attachments/assets/cd630eac-7405-4353-a3a0-163e673d36dd" />


The repository includes an [example Electron application](example-electron-app/) demonstrating the addon usage. It shows how to expose the addon from the main process to the renderer thread using Electron's `contextBridge` and `ipcMain`/`ipcRenderer`.

> [!IMPORTANT]
> Before running the example app, complete [Configure the entitlements and domain association](#3-configure-the-entitlements-and-domain-association) and [Sign and run the app](#4-sign-and-run-the-app) from Quick Start.

```bash
cd example-electron-app
npm install
npm run build:mac
open dist/mac-arm64/WebAuthnDemo.app
```

## Configuring Entitlements and Domain Association

For WebAuthn to work with your domain (`rpId`), you must establish an association between your app and the domain. This is done by hosting an `apple-app-site-association` file on your server. See [Apple's Associated Domains documentation](https://developer.apple.com/documentation/xcode/supporting-associated-domains) for details.

### 1. Find Your Team ID and Bundle ID

- **Team ID**: Found in [Apple Developer Portal](https://developer.apple.com/account) → Membership Details
- **Bundle ID**: Your app's bundle identifier (e.g., `com.yourcompany.yourapp`)

### 2. Create the Association File

Host an associated domain file on your website (with a URL such as `https://example.com/.well-known/apple-app-site-association`) with the following content:

```js
{
  "webcredentials": {
    "apps": [ "TEAM_ID.BUNDLE_ID" ] // Example: "A1B2C3D4E5.com.example.myapp"
  }
}
```

### 3. Confirm Server Requirements

The file must be:
- Served over **HTTPS** (valid SSL certificate required)
- Content-Type: `application/json`
- Accessible **without redirects** at the exact path `/.well-known/apple-app-site-association`
- No `.json` extension in the URL

### 4. Add Entitlements

In your Electron app's entitlements file, add:

```xml
<!-- Replace with your Team ID and Bundle ID -->
<key>com.apple.application-identifier</key>
<string>TEAM_ID.BUNDLE_ID</string>
<!-- Replace example.com with your domain name -->
<key>com.apple.developer.associated-domains</key>
<array>
  <string>webcredentials:example.com</string>
</array>
```

> [!NOTE]
> The domain in `rpId` must exactly match the domain in your associated domains entitlement and the domain hosting the `apple-app-site-association` file.

### 5. Verification

After deployment, you can verify your association file:
1. Visit `https://example.com/.well-known/apple-app-site-association` in a browser
2. Use an external validator like [Branch.io AASA Validator](https://branch.io/resources/aasa-validator/) or similar tools

## Provisioning Profile Setup

Apps using the `com.apple.developer.associated-domains` entitlement require a **provisioning profile** installed on the development machine. Without it, macOS will reject the app at launch.

**Creating the profile:**

1. Go to [Apple Developer Portal → Identifiers](https://developer.apple.com/account/resources/identifiers/list)
2. Create or edit an App ID matching your bundle identifier
3. Enable the **Associated Domains** capability
4. Go to [Profiles](https://developer.apple.com/account/resources/profiles/list) → create a **macOS App Development** profile for this App ID
5. Download the `.provisionprofile` file and double-click to install

## API Reference

* [`createCredential(options)`](#create-credential)
* [`getCredential(options)`](#get-credential)
* [`managePasswords()`](#manage-passwords)

<a name="create-credential"></a>

### `createCredential(options)`

Creates a new passkey credential using Touch ID, iCloud Keychain, or an external security key.

**Options:**
| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `rpId` | string | ✅ | Relying Party identifier (your domain, e.g., "example.com") |
| `userId` | string | ✅ | Stable user identifier (max 64 bytes recommended) |
| `name` | string | ✅ | User's name (used for both platform and security key authentication) |
| `displayName` | string | ✅ | User's display name (used for security key only) |
| `authenticators` | string[] | | Which authenticator types to offer: `['platform', 'securityKey']` (default: both) |
| `excludeCredentials` | object[] | | Existing credentials to prevent re-registration |
| `userVerification` | string | | `'required'`, `'preferred'` (default), or `'discouraged'` |
| `attestation` | string | | `'none'` (default), `'indirect'`, `'direct'`, or `'enterprise'` |
| `largeBlobRequired` | boolean | | Require largeBlob support (macOS 14.0+, platform keys only) |
| `prf` | object | | PRF extension request (macOS 15.0+, platform keys only) |

**Returns:** `Promise<RegistrationCredential>`

**Platform credential response** (Touch ID / iCloud Keychain):
```javascript
{
  type: "platform",
  credentialID: string,           // Base64-encoded credential ID
  attestationObject: string,      // Base64-encoded CBOR attestation
  clientDataJSON: string,         // Base64-encoded client data
  attachment?: string,            // "platform" or "crossPlatform" (macOS 13.5+)
  largeBlobSupported?: boolean,   // Whether largeBlob is supported (macOS 14.0+)
  prfEnabled?: boolean,           // Whether PRF extension is supported (macOS 15.0+)
  prfFirst?: string,              // Base64-encoded first PRF output (if requested)
  prfSecond?: string              // Base64-encoded second PRF output (if requested)
}
```

**Security key credential response** (external FIDO2 key):
```javascript
{
  type: "securityKey",
  credentialID: string,           // Base64-encoded credential ID
  attestationObject: string,      // Base64-encoded CBOR attestation
  clientDataJSON: string,         // Base64-encoded client data
  transports?: string[]           // ["usb", "nfc", "ble", "internal", "hybrid"] (macOS 14.5+)
}
```

---

<a name="get-credential"></a>

### `getCredential(options)`

Authenticates a user using an existing passkey.

**Options:**
| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `rpId` | string | ✅ | Relying Party identifier (your domain) |
| `authenticators` | string[] | | Which authenticator types to offer: `['platform', 'securityKey']` (default: both) |
| `allowCredentials` | object[] | | Specific credentials to allow (if not set, discovers available) |
| `userVerification` | string | | `'required'`, `'preferred'` (default), or `'discouraged'` |
| `largeBlobOperation` | object | | `{ read: true }` or `{ write: "base64data" }` (macOS 14.0+, platform keys only) |
| `prf` | object | | `{ eval: { first: "base64", second?: "base64" } }` (macOS 15.0+, platform keys only) |

**Returns:** `Promise<AssertionCredential>`

**Platform credential response** (Touch ID / iCloud Keychain):
```javascript
{
  type: "platform",
  userID: string,                 // Base64-encoded user handle
  credentialID: string,           // Base64-encoded credential ID
  authenticatorData: string,      // Base64-encoded authenticator data
  clientDataJSON: string,         // Base64-encoded client data
  signature: string,              // Base64-encoded signature
  attachment?: string,            // "platform" or "crossPlatform" (macOS 13.5+)
  largeBlobResult?: object,       // { type: 'read', data } or { type: 'write', success } (macOS 14.0+)
  prfEnabled?: boolean,           // Whether PRF extension was used (macOS 15.0+)
  prfFirst?: string,              // Base64-encoded first PRF output
  prfSecond?: string              // Base64-encoded second PRF output
}
```

**Security key credential response** (external FIDO2 key):
```javascript
{
  type: "securityKey",
  userID: string,                 // Base64-encoded user handle
  credentialID: string,           // Base64-encoded credential ID
  authenticatorData: string,      // Base64-encoded authenticator data
  clientDataJSON: string,         // Base64-encoded client data
  signature: string,              // Base64-encoded signature
  appID?: boolean                 // Whether legacy FIDO U2F appID was used (macOS 14.5+)
}
```

---

<a name="manage-passwords"></a>

### `managePasswords()`

Opens the macOS system password manager (_Settings → Passwords_).

**Parameters:** None

**Returns:** `void`

## macOS Platform Quirks

### How It Works

The addon provides native WebAuthn/Passkey functionality using:
- **Swift**: Core passkey logic using AuthenticationServices framework (`src/PasskeyManager.swift`)
- **Objective-C**: Bridge between Swift and C++
- **C++**: N-API bindings for Node.js integration
- **JavaScript/TypeScript**: User-friendly wrapper API with full type definitions

> [!NOTE]
> All credentials use **ES256** algorithm (ECDSA P-256 with SHA-256) — the only algorithm supported by Apple's AuthenticationServices.

### Why is domain association required?

Passkeys are tied to a specific domain (like `example.com`). When you authenticate with a passkey, macOS needs to verify that the app requesting access actually owns that domain — otherwise, a malicious app could impersonate your bank and steal your credentials.

Apple enforces this through a two-way trust mechanism:
1. **Your server proves it trusts the app** — by hosting a file at `https://example.com/.well-known/apple-app-site-association` that lists your app's bundle identifier
2. **Your app declares which domain it represents** — via the `com.apple.developer.associated-domains` entitlement embedded during code signing

When both sides match, macOS allows your app to create and use passkeys for that domain. Without this setup, passkey operations will fail with "Application is not associated with domain" errors.

> [!NOTE]
> In browsers, `localhost` is exempt from domain verification for development convenience. Native macOS code has no such exception — domain association is always required, even for local testing. You'll need a real domain with HTTPS to develop and test passkey functionality with this addon.

### Platform vs Security Key authenticators

Apple's AuthenticationServices framework distinguishes between two authenticator types (see [Apple's documentation](https://developer.apple.com/documentation/authenticationservices/public-private-key-authentication)):

| Type | What it is | Examples |
|------|------------|----------|
| **Platform** | Built-in or tightly integrated with the device | Touch ID, Face ID, iCloud Keychain, cross-device via QR code |
| **Security Key** | External FIDO2 hardware tokens | YubiKey, Titan Key, etc (via USB, NFC, or Bluetooth) |

As of 2025, PRF and LargeBlob extensions are only available for **platform** authenticators.

### Differences from Browser WebAuthn

This addon differs from the standard browser-based Web Authentication API (`navigator.credentials`) due to Apple's `AuthenticationServices` framework limitations:

| Parameter | Browser WebAuthn | This Addon |
|-----------|------------------|------------|
| `challenge` | Server-generated, passed to API | Auto-generated internally (32 bytes via `SecRandomCopyBytes`). Retrieve from `clientDataJSON` if needed. |
| `rp.name` | Human-readable RP name shown to user | Not supported — macOS shows `rpId` domain instead |
| `timeout` | Configurable operation timeout | Not supported — system manages timeouts internally |
| `pubKeyCredParams` | Multiple algorithms supported | ES256 only (hardcoded by Apple) |
| PRF, LargeBlob | Available on all authenticators | Platform authenticators only — see [Platform vs Security Key](#platform-vs-security-key-authenticators) |

## Troubleshooting

### "The calling process does not have an application identifier. Make sure it is properly configured."

The app is not running as a signed `.app` bundle. Follow [Sign and run the app](#4-sign-and-run-the-app) to build and code-sign your application.

### "Application is not associated with domain" or "No credentials available"

The `rpId` domain is not associated with your app. Follow [Configuring Entitlements and Domain Association](#configuring-entitlements-and-domain-association) and verify that your Team ID and Bundle ID match in both the server-hosted file and your app's entitlements.

### App builds but shows "could not be opened" alert on launch

Your app uses restricted entitlements (`associated-domains`) but no matching provisioning profile is installed. macOS blocks such apps with a generic "could not be opened" dialog (system logs show "No matching profile found"). Follow [Provisioning Profile Setup](#provisioning-profile-setup) to create and install a development profile for your bundle ID.

### PRF or LargeBlob extensions are not working

These extensions are only supported for platform authenticators (Touch ID / iCloud Keychain), not security keys. Use `authenticators: ['platform']` to restrict to platform keys when using these extensions.

## Plugin Development

### Prerequisites

- macOS 13.0+ (Ventura or later)
- Xcode 15+ with Command Line Tools (`xcode-select --install`)
- Node.js 18+ with npm
- Apple Developer account (for code signing)

### Project Structure

```
electron-webauthn-mac/
├── src/                       # Swift/Objective-C/C++ source code
│   └── PasskeyManager.swift   # Core WebAuthn logic (used by addon and dev app)
├── js/                        # JavaScript wrapper + TypeScript definitions
├── include/                   # Header file
├── native/                    # Prebuilt .node binary (generated)
├── binding.gyp                # node-gyp build configuration
├── example-electron-app/      # Example Electron application
└── dev-mac-app/               # Native macOS dev app (Xcode project)
```

### Building the Addon

```bash
npm install
npm run build
```

This compiles the Swift code, builds the native addon, and copies the `.node` binary to `native/`.

### WebAuthn Playground (Development App)

For faster iteration during development, use the native macOS dev app:

```bash
open dev-mac-app/WebAuthnPlayground.xcodeproj
# Build and run in Xcode (⌘R)
```

**Why a separate native app?**

Building through Electron requires code signing and bundling — which is slow. The native app provides:

- **Instant iteration** — build and run directly from Xcode in seconds
- **Full debugger access** — set breakpoints in Swift code, inspect variables
- **API playground** — quickly test new AuthenticationServices features
- **Shared codebase** — both Electron example and Playground projects use the same `PasskeyManager.swift` from `src/`

The playground includes buttons for all WebAuthn operations: registration, authentication, PRF encryption/decryption, and largeBlob read/write.

> [!TIP]
> When developing new features, prototype them in the playground first, then integrate into the Electron addon once verified.

### Publishing

```bash
npm run build        # Builds and copies .node to native/
npm publish          # prepublishOnly runs build automatically
```

## License

This project is released under the [MIT License](http://opensource.org/licenses/MIT).

---

<p align="center">
  Made with ❤️ by the <a href="https://github.com/vault12">Vault12 Team</a>
</p>
