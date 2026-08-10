import os
import datetime
import uuid
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

CA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "storage", "ca")
CA_CERT_PATH = os.path.join(CA_DIR, "rootCA.pem")
CA_KEY_PATH = os.path.join(CA_DIR, "rootCA.key")

def _ensure_ca_exists():
    if not os.path.exists(CA_DIR):
        os.makedirs(CA_DIR, exist_ok=True)
        
    if os.path.exists(CA_CERT_PATH) and os.path.exists(CA_KEY_PATH):
        return

    # Generate our key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Generate a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Monitorix Sovereign Edge"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Monitorix Root CA"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valid for 10 years
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256())

    # Write private key
    with open(CA_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Write certificate
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def get_ca_cert_pem() -> str:
    _ensure_ca_exists()
    with open(CA_CERT_PATH, "r") as f:
        return f.read()

def sign_agent_csr(csr_pem_str: str, days_valid: int = 90) -> tuple:
    """
    Signs a given CSR with the internal Root CA.
    Returns (certificate_pem, serial_number)
    """
    _ensure_ca_exists()
    
    # Load CA Key
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
        
    # Load CA Cert
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
        
    # Load CSR
    csr = x509.load_pem_x509_csr(csr_pem_str.encode("utf-8"))
    
    if not csr.is_signature_valid:
        raise ValueError("Invalid CSR signature")
        
    # Build certificate
    serial_number = x509.random_serial_number()
    builder = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        serial_number
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    )
    
    # Sign certificate
    cert = builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256()
    )
    
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"), str(serial_number)
