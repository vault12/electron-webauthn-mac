// Comprehensive demo of electron-webauthn-mac features

const RP_ID = 'example.com';

// Utility: Display results
function displayResult(elementId, message, isError = false) {
  const element = document.getElementById(elementId);
  if (element) {
    element.className = `results ${isError ? 'error' : 'success'}`;
    const formatted = typeof message === 'object' ? JSON.stringify(message, null, 2) : message;
    element.textContent = `[${new Date().toLocaleTimeString()}] ${isError ? '❌ ERROR' : '✅ SUCCESS'}:\n${formatted}`;
  }
}

// Utility: Generate random user ID
function generateUserId() {
  return `user-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// Utility: Base64 encode string
function base64Encode(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

// Utility: Base64 decode string
function base64Decode(str) {
  return decodeURIComponent(escape(atob(str)));
}


document.addEventListener('DOMContentLoaded', () => {

  // ============================================================================
  // 1. BASIC OPERATIONS
  // ============================================================================

  document.getElementById('basicRegister')?.addEventListener('click', async () => {
    try {
      const result = await window.exposedAddon.createCredential({
        rpId: RP_ID,
        userId: generateUserId(),
        name: 'Demo User',
        displayName: 'Demo User'
      });

      displayResult('basicResults', result);
    } catch (error) {
      displayResult('basicResults', error.message || error, true);
    }
  });

  document.getElementById('basicAuthenticate')?.addEventListener('click', async () => {
    try {
      const result = await window.exposedAddon.getCredential({
        rpId: RP_ID
      });

      displayResult('basicResults', result);
    } catch (error) {
      displayResult('basicResults', error.message || error, true);
    }
  });

  document.getElementById('managePasswords')?.addEventListener('click', async () => {
    try {
      await window.exposedAddon.managePasswords();
      displayResult('basicResults', 'Passwords app opened');
    } catch (error) {
      displayResult('basicResults', error.message || error, true);
    }
  });

  // ============================================================================
  // 2. ADVANCED REGISTRATION OPTIONS
  // ============================================================================

  document.getElementById('advRegister')?.addEventListener('click', async () => {
    try {
      const platformChecked = document.getElementById('platformAuth').checked;
      const securityKeyChecked = document.getElementById('securityKeyAuth').checked;

      const authenticators = [];
      if (platformChecked) authenticators.push('platform');
      if (securityKeyChecked) authenticators.push('securityKey');

      if (authenticators.length === 0) {
        throw new Error('Select at least one authenticator type');
      }

      const options = {
        rpId: RP_ID,
        userId: document.getElementById('advUserId').value || generateUserId(),
        name: document.getElementById('advUserName').value || 'Advanced User',
        displayName: document.getElementById('advUserName').value || 'Advanced User',
        authenticators,
        userVerification: document.getElementById('userVerification').value,
        attestation: document.getElementById('attestation').value
      };

      if (document.getElementById('largeBlobRequired').checked) {
        options.largeBlobRequired = true;
      }

      const result = await window.exposedAddon.createCredential(options);

      displayResult('advRegisterResults', result);
    } catch (error) {
      displayResult('advRegisterResults', error.message || error, true);
    }
  });

  // ============================================================================
  // 3. PRF EXTENSION (Pseudo-Random Function)
  // ============================================================================

  document.getElementById('prfRegister')?.addEventListener('click', async () => {
    try {
      // Register with PRF support check
      const result = await window.exposedAddon.createCredential({
        rpId: RP_ID,
        userId: generateUserId(),
        name: 'PRF Test User',
        displayName: 'PRF Test User',
        authenticators: ['platform'], // PRF only works with platform authenticators
        prf: {
          checkForSupport: true
        }
      });

      displayResult('prfRegisterResults', result);
    } catch (error) {
      displayResult('prfRegisterResults', error.message || error, true);
    }
  });

  document.getElementById('prfDerive')?.addEventListener('click', async () => {
    try {
      // Use custom salt if provided, otherwise use default
      const saltInput = document.getElementById('prfSalt').value.trim();
      const salt = saltInput || base64Encode('default-prf-salt-for-demo');

      const result = await window.exposedAddon.getCredential({
        rpId: RP_ID,
        authenticators: ['platform'], // PRF only works with platform
        prf: {
          eval: {
            first: salt
          }
        }
      });

      displayResult('prfDeriveResults', result);
    } catch (error) {
      displayResult('prfDeriveResults', error.message || error, true);
    }
  });

  // ============================================================================
  // 4. LARGE BLOB EXTENSION
  // ============================================================================

  document.getElementById('blobWrite')?.addEventListener('click', async () => {
    try {
      const dataToStore = document.getElementById('blobWriteData').value;
      if (!dataToStore) {
        throw new Error('Enter data to store');
      }

      // Base64 encode the data
      const encodedData = base64Encode(dataToStore);

      const result = await window.exposedAddon.getCredential({
        rpId: RP_ID,
        authenticators: ['platform'], // Large blob only works with platform
        largeBlobOperation: {
          write: encodedData
        }
      });

      displayResult('blobWriteResults', result);
    } catch (error) {
      displayResult('blobWriteResults', error.message || error, true);
    }
  });

  document.getElementById('blobRead')?.addEventListener('click', async () => {
    const decodedField = document.getElementById('blobReadDecoded');
    decodedField.value = '';

    try {
      const result = await window.exposedAddon.getCredential({
        rpId: RP_ID,
        authenticators: ['platform'], // Large blob only works with platform
        largeBlobOperation: {
          read: true
        }
      });

      // Decode base64 data if present
      if (result.largeBlobResult?.data) {
        try {
          decodedField.value = base64Decode(result.largeBlobResult.data);
        } catch (e) {
          decodedField.value = '(failed to decode base64)';
        }
      }

      displayResult('blobReadResults', result);
    } catch (error) {
      displayResult('blobReadResults', error.message || error, true);
    }
  });

});
