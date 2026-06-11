import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # type: ignore
import logging

logger = logging.getLogger(__name__)

class CredentialVault:
    """
    [v2.3.0] Enterprise Credential Vault
    Provides AES-GCM Envelope Encryption for Agentless Service Accounts.
    """
    def __init__(self):
        # Master key is NEVER stored in the DB. Loaded from secure environment.
        raw_key = os.getenv("VAULT_MASTER_KEY")
        if raw_key:
            self._master_key = base64.b64decode(raw_key)
        else:
            # Fallback for dev/testing. IN PRODUCTION this must halt the startup.
            logger.warning("[SECURITY] VAULT_MASTER_KEY not set! Using ephemeral dev key. Credentials will be lost on restart.")
            self._master_key = AESGCM.generate_key(bit_length=256)
            
        self._aesgcm = AESGCM(self._master_key)

    def encrypt_credential(self, plaintext: str) -> str:
        """Encrypts a plaintext password or SSH private key."""
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return base64.b64encode(nonce + ct).decode('utf-8')

    def decrypt_credential(self, ciphertext_b64: str) -> str:
        """Decrypts a vault credential back to plaintext."""
        try:
            raw_data = base64.b64decode(ciphertext_b64)
            nonce, ct = raw_data[:12], raw_data[12:]
            plaintext = self._aesgcm.decrypt(nonce, ct, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            logger.error(f"[SECURITY] Failed to decrypt vault credential: {e}")
            raise ValueError("Vault Decryption Failed. Potential Master Key mismatch or corrupted DB.")

credential_vault = CredentialVault()
