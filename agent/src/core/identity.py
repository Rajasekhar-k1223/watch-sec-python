import os
import uuid
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509

logger = logging.getLogger(__name__)

class AgentIdentity:
    def __init__(self, cert_dir="certs"):
        self.cert_dir = cert_dir
        self.key_path = os.path.join(self.cert_dir, "private.key")
        self.cert_path = os.path.join(self.cert_dir, "mtls.crt")
        os.makedirs(self.cert_dir, exist_ok=True)
        
    def generate_hardware_fingerprint(self) -> str:
        """Layer 2: Generates a stable hardware fingerprint."""
        # Mocking hardware fingerprint for prototype.
        # In prod, this would read SMBIOS UUID, CPU ID, and MAC Address.
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, "monitorix.local.machine"))

    def load_or_generate_keypair(self):
        """Layer 2: Generates ECDSA keypair if missing."""
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            logger.info("[IDENTITY] Loaded existing ECDSA keypair.")
        else:
            logger.info("[IDENTITY] Generating new ECDSA P-256 keypair...")
            self.private_key = ec.generate_private_key(ec.SECP256R1())
            
            # Secure storage: In prod this would be written to TPM/SecureEnclave
            with open(self.key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            os.chmod(self.key_path, 0o600)

    def generate_csr(self, tenant_id: str) -> bytes:
        """Layer 2: Generates a Certificate Signing Request."""
        hw_hash = self.generate_hardware_fingerprint()
        agent_id = f"AGT-{hw_hash[:8].upper()}"
        
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, tenant_id),
        ])).sign(self.private_key, hashes.SHA256())
        
        return csr.public_bytes(serialization.Encoding.PEM)

    def has_valid_cert(self) -> bool:
        return os.path.exists(self.cert_path)
