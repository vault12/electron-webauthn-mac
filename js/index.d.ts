// ============================================================================
// Authenticator Types
// ============================================================================

/**
 * Authenticator type selection for WebAuthn operations
 * - 'platform': Touch ID / iCloud Keychain (built-in) / QR Code
 * - 'securityKey': External FIDO2 security key (USB/NFC/BLE)
 */
export type AuthenticatorType = 'platform' | 'securityKey';

/**
 * User verification requirement
 * - 'required': User verification is required (fail if not possible)
 * - 'preferred': User verification is preferred but not required (default)
 * - 'discouraged': User verification should not be performed
 */
export type UserVerificationRequirement = 'required' | 'preferred' | 'discouraged';

/**
 * Attestation conveyance preference for registration
 * - 'none': No attestation required (default, most privacy-preserving)
 * - 'indirect': Attestation may be anonymized
 * - 'direct': Direct attestation from authenticator (reveals device info)
 * - 'enterprise': Enterprise attestation (requires Apple entitlement)
 */
export type AttestationPreference = 'none' | 'indirect' | 'direct' | 'enterprise';

/**
 * Credential descriptor for excludeCredentials / allowCredentials
 */
export interface CredentialDescriptor {
  /** Base64-encoded credential ID */
  id: string;
  /** Optional transports: 'usb', 'nfc', 'ble', 'internal', 'hybrid' */
  transports?: string[];
}

// ============================================================================
// PRF Extension
// ============================================================================

/**
 * PRF (pseudo-random function) extension request for registration.
 *
 * Use `{ checkForSupport: true }` to query whether the authenticator supports PRF during registration.
 * Use `{ eval: { first, second? } }` to request PRF outputs at registration time.
 *
 * These correspond to `extensions.prf === true` and `extensions.prf.eval = { first, second? }` on the web side.
 *
 * ⚠️ **Platform keys only** - not supported on security keys
 *
 * @remarks macOS 15.0+ / iOS 18.0+
 */
export type PRFRegistrationRequest =
  | { checkForSupport: true }
  | { eval: { first: string; second?: string } };

/**
 * PRF extension request for assertion (get).
 *
 * Only `eval` is allowed because checking support is not available for assertions.
 * Corresponds to `extensions.prf.eval = { first, second? }` on the web side.
 *
 * ⚠️ **Platform keys only** - not supported on security keys
 *
 * @remarks macOS 15.0+ / iOS 18.0+
 */
export interface PRFAssertionRequest {
  eval: {
    /** Base64-encoded first salt input */
    first: string;
    /** Base64-encoded second salt input (optional) */
    second?: string;
  };
}

// ============================================================================
// LargeBlob Extension
// ============================================================================

/**
 * LargeBlob operation request for credential assertion
 * - `{ read: true }`: Read blob data from authenticator
 * - `{ write: string }`: Write Base64-encoded blob data to authenticator
 *
 * ⚠️ **Platform keys only** - not supported on security keys
 *
 * @remarks macOS 14.0+ / iOS 17.0+
 */
export type LargeBlobOperationRequest =
  | { read: true }
  | { write: string };

/**
 * LargeBlob operation result returned after assertion
 * - `{ type: 'read', data: string }`: Base64-encoded blob data successfully read
 * - `{ type: 'write', success: boolean }`: Write operation result
 *
 * ⚠️ **Platform keys only** - not supported on security keys
 *
 * @remarks macOS 14.0+ / iOS 17.0+
 */
export type LargeBlobOperationResult =
  | { type: 'read'; data: string }
  | { type: 'write'; success: boolean };

// ============================================================================
// Options
// ============================================================================

/**
 * Options for createCredential (WebAuthn PublicKeyCredentialCreationOptions)
 */
export interface CreateCredentialOptions {
  /** Relying party identifier (domain) */
  rpId: string;
  /** Stable user identifier (max 64 bytes recommended) */
  userId: string;
  /** User's name (used for both platform and security key authentication) */
  name: string;
  /** User's display name (used for security key only) */
  displayName: string;
  /** Which authenticator types to offer (default: both ['platform', 'securityKey']) */
  authenticators?: AuthenticatorType[];
  /** Optional list of existing credentials to prevent re-registration */
  excludeCredentials?: CredentialDescriptor[];
  /** User verification requirement (default: 'preferred') */
  userVerification?: UserVerificationRequirement;
  /** Attestation preference (default: 'none') */
  attestation?: AttestationPreference;
  /**
   * If true, requires largeBlob support; if false, uses system default.
   * ⚠️ Platform keys only - not supported on security keys
   * @remarks macOS 14.0+
   */
  largeBlobRequired?: boolean;
  /**
   * PRF extension request. Use `{ checkForSupport: true }` to check for PRF availability,
   * or `{ eval: { first, second? } }` to compute PRF values.
   * ⚠️ Platform keys only - not supported on security keys
   * @remarks macOS 15.0+
   */
  prf?: PRFRegistrationRequest;
}

/**
 * Options for getCredential (WebAuthn PublicKeyCredentialRequestOptions)
 */
export interface GetCredentialOptions {
  /** Relying party identifier (domain) */
  rpId: string;
  /** Which authenticator types to offer (default: both ['platform', 'securityKey']) */
  authenticators?: AuthenticatorType[];
  /** Optional list of credentials to allow (if not set, discovers available credentials) */
  allowCredentials?: CredentialDescriptor[];
  /** User verification requirement (default: 'preferred') */
  userVerification?: UserVerificationRequirement;
  /**
   * LargeBlob read/write operation.
   * ⚠️ Platform keys only - not supported on security keys
   * @remarks macOS 14.0+ / iOS 17.0+
   */
  largeBlobOperation?: LargeBlobOperationRequest;
  /**
   * PRF extension request. Use `{ eval: { first, second? } }` to compute PRF values.
   * ⚠️ Platform keys only - not supported on security keys
   * @remarks macOS 15.0+ / iOS 18.0+
   */
  prf?: PRFAssertionRequest;
}

// ============================================================================
// Credentials (Response Types)
// ============================================================================

/**
 * Platform registration credential (Touch ID / iCloud Keychain)
 */
export interface PlatformRegistrationCredential {
  type: 'platform';
  /** Base64-encoded credential ID - unique identifier for this credential */
  credentialID: string;
  /**
   * Base64-encoded CBOR (Concise Binary Object Representation) with:
   * - authData: rpIdHash(32), flags(1), signCount(4), attestedCredentialData
   *   - attestedCredentialData: AAGUID(16), credIdLength(2), credId, publicKey(COSE)
   * - fmt: attestation format (e.g., "none", "packed", "fido-u2f")
   * - attStmt: attestation statement (signature, certificates)
   */
  attestationObject: string;
  /** Base64-encoded JSON with challenge, origin, and type (webauthn.create) */
  clientDataJSON: string;
  /**
   * Authenticator attachment type: 'platform' or 'crossPlatform'
   * @remarks macOS 13.5+
   */
  attachment?: string;
  /**
   * Whether authenticator supports largeBlob extension (platform keys only)
   * @remarks macOS 14.0+
   */
  largeBlobSupported?: boolean;
  /**
   * Whether pseudo-random function extension is supported (platform keys only)
   * @remarks macOS 15.0+ / iOS 18.0+
   */
  prfEnabled?: boolean;
  /** Base64-encoded first PRF output (if available, platform keys only) */
  prfFirst?: string;
  /** Base64-encoded second PRF output (if available, platform keys only) */
  prfSecond?: string;
}

/**
 * Security key registration credential (external FIDO2 key)
 */
export interface SecurityKeyRegistrationCredential {
  type: 'securityKey';
  /** Base64-encoded credential ID - unique identifier for this credential */
  credentialID: string;
  /**
   * Base64-encoded CBOR (Concise Binary Object Representation) with:
   * - authData: rpIdHash(32), flags(1), signCount(4), attestedCredentialData
   *   - attestedCredentialData: AAGUID(16), credIdLength(2), credId, publicKey(COSE)
   * - fmt: attestation format (e.g., "none", "packed", "fido-u2f")
   * - attStmt: attestation statement (signature, certificates)
   */
  attestationObject: string;
  /** Base64-encoded JSON with challenge, origin, and type (webauthn.create) */
  clientDataJSON: string;
  /**
   * Supported transports: 'usb', 'nfc', 'ble', 'internal', 'hybrid'
   * @remarks macOS 14.5+
   */
  transports?: string[];
}

/** Registration credential (union type) */
export type RegistrationCredential =
  | PlatformRegistrationCredential
  | SecurityKeyRegistrationCredential;

/**
 * Platform assertion credential (Touch ID / iCloud Keychain)
 */
export interface PlatformAssertionCredential {
  type: 'platform';
  /** Base64-encoded user handle (user identifier from registration) */
  userID: string;
  /** Base64-encoded credential ID that was used for authentication */
  credentialID: string;
  /** Base64-encoded authenticator data (rpIdHash, flags, signCount, extensions) */
  authenticatorData: string;
  /** Base64-encoded JSON with challenge, origin, and type (webauthn.get) */
  clientDataJSON: string;
  /** Base64-encoded signature over authenticatorData and clientDataJSON hash */
  signature: string;
  /**
   * Authenticator attachment type: 'platform' or 'crossPlatform'
   * @remarks macOS 13.5+
   */
  attachment?: string;
  /**
   * LargeBlob operation result (read data or write status).
   * Only available for platform authenticators.
   * @remarks macOS 14.0+
   */
  largeBlobResult?: LargeBlobOperationResult;
  /**
   * Whether pseudo-random function extension was used.
   * Only available for platform authenticators.
   * @remarks macOS 15.0+ / iOS 18.0+
   */
  prfEnabled?: boolean;
  /** Base64-encoded first PRF output (if available, platform keys only) */
  prfFirst?: string;
  /** Base64-encoded second PRF output (if available, platform keys only) */
  prfSecond?: string;
}

/**
 * Security key assertion credential (external FIDO2 key)
 */
export interface SecurityKeyAssertionCredential {
  type: 'securityKey';
  /** Base64-encoded user handle (user identifier from registration) */
  userID: string;
  /** Base64-encoded credential ID that was used for authentication */
  credentialID: string;
  /** Base64-encoded authenticator data (rpIdHash, flags, signCount, extensions) */
  authenticatorData: string;
  /** Base64-encoded JSON with challenge, origin, and type (webauthn.get) */
  clientDataJSON: string;
  /** Base64-encoded signature over authenticatorData and clientDataJSON hash */
  signature: string;
  /**
   * Whether legacy FIDO U2F appID extension was used
   * @remarks macOS 14.5+
   */
  appID?: boolean;
}

/** Assertion credential (union type) */
export type AssertionCredential =
  | PlatformAssertionCredential
  | SecurityKeyAssertionCredential;

// ============================================================================
// Main Export
// ============================================================================

export interface WebAuthnMacAddon {
  /**
   * Creates a new passkey credential (platform or security key).
   *
   * Note: The pubKeyCredParams (credential algorithm) is hardcoded to ES256 (ECDSA P-256 with SHA-256)
   * as it's the only algorithm supported by Apple's AuthenticationServices SDK for security keys.
   * This corresponds to algorithm -7 (COSE_ALGORITHM_ES256) in the WebAuthn specification.
   *
   * @param options - Registration options
   * @returns Registration credential data
   */
  createCredential(options: CreateCredentialOptions): Promise<RegistrationCredential>;

  /**
   * Authenticates using an existing passkey (platform or security key).
   * @param options - Assertion options
   * @returns Assertion credential data
   */
  getCredential(options: GetCredentialOptions): Promise<AssertionCredential>;

  /**
   * Opens the Passwords app or System Settings → Passwords so the user can manage passkeys.
   */
  managePasswords(): void;
}

declare const addon: WebAuthnMacAddon;
export default addon;
