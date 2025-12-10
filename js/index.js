class WebAuthnMacAddon {
  constructor() {
    if (process.platform !== 'darwin') {
      throw new Error('[electron-webauthn-mac] This module is only available on macOS')
    }
    const native = require('../native/webauthn_mac_addon.node')
    this.addon = new native.WebAuthnMacAddon()
  }

  /**
   * Creates a new passkey credential (platform or security key)
   * @param {CreateCredentialOptions} options - Registration options
   * @returns {Promise<RegistrationCredential>}
   */
  async createCredential(options) {
    if (!options?.rpId) throw new Error('[electron-webauthn-mac] createCredential(): rpId is required')
    if (!options?.userId) throw new Error('[electron-webauthn-mac] createCredential(): userId is required')
    if (!options?.name) throw new Error('[electron-webauthn-mac] createCredential(): name is required')
    if (!options?.displayName) throw new Error('[electron-webauthn-mac] createCredential(): displayName is required')

    return this.addon.createCredential(options)
  }

  /**
   * Authenticates using an existing passkey (platform or security key)
   * @param {GetCredentialOptions} options - Assertion options
   * @returns {Promise<AssertionCredential>}
   */
  async getCredential(options) {
    if (!options?.rpId) throw new Error('[electron-webauthn-mac] getCredential(): rpId is required')

    return this.addon.getCredential(options)
  }

  /**
   * Opens the macOS system password manager (Settings > Passwords)
   */
  managePasswords() {
    return this.addon.managePasswords()
  }
}

if (process.platform === 'darwin') {
  module.exports = new WebAuthnMacAddon()
} else {
  module.exports = {}
}
