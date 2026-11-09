import os
import stat
import datetime
import hashlib
import ipaddress
from typing import Tuple, List, Optional, Dict, Any
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Base CA storage path
CA_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "storage", "ca"))
ROOT_CA_DIR = os.path.join(CA_BASE_DIR, "root")
INTERMEDIATE_CA_DIR = os.path.join(CA_BASE_DIR, "intermediate")
SERVER_DIR = os.path.join(CA_BASE_DIR, "server")
CRL_DIR = os.path.join(CA_BASE_DIR, "crl")

# File paths
ROOT_KEY_PATH = os.path.join(ROOT_CA_DIR, "rootCA.key")
ROOT_CERT_PATH = os.path.join(ROOT_CA_DIR, "rootCA.pem")

INTERMEDIATE_KEY_PATH = os.path.join(INTERMEDIATE_CA_DIR, "intermediateCA.key")
INTERMEDIATE_CERT_PATH = os.path.join(INTERMEDIATE_CA_DIR, "intermediateCA.pem")
CA_CHAIN_PATH = os.path.join(INTERMEDIATE_CA_DIR, "ca_chain.pem")

SERVER_KEY_PATH = os.path.join(SERVER_DIR, "server.key")
SERVER_CERT_PATH = os.path.join(SERVER_DIR, "server.pem")
SERVER_FULLCHAIN_PATH = os.path.join(SERVER_DIR, "server_fullchain.pem")

CRL_PEM_PATH = os.path.join(CRL_DIR, "crl.pem")
CRL_DER_PATH = os.path.join(CRL_DIR, "crl.der")

def _set_private_file_permissions(filepath: str):
    """Sets strict 0600 permissions on private key files."""
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

def _set_public_file_permissions(filepath: str):
    """Sets standard 0644 permissions on public certificates."""
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    except Exception:
        pass

def _ensure_directories():
    """Ensures all CA directory structures exist with restricted permissions."""
    for d in [ROOT_CA_DIR, INTERMEDIATE_CA_DIR, SERVER_DIR, CRL_DIR]:
        if not os.path.exists(d):
            os.makedirs(d, mode=0o700, exist_ok=True)

def _ensure_root_ca():
    """Initializes the offline Root CA if it does not already exist."""
    _ensure_directories()
    if os.path.exists(ROOT_KEY_PATH) and os.path.exists(ROOT_CERT_PATH):
        return

    # Generate Root CA RSA 4096-bit private key
    root_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    root_subject = root_issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Monitorix Sovereign Edge"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Security Architecture Group"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Monitorix Sovereign Root CA"),
    ])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_issuer)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years validity
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    with open(ROOT_KEY_PATH, "wb") as f:
        f.write(root_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    _set_private_file_permissions(ROOT_KEY_PATH)

    with open(ROOT_CERT_PATH, "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    _set_public_file_permissions(ROOT_CERT_PATH)

def _ensure_intermediate_ca():
    """Initializes the Intermediate Agent Ingestion CA signed by the Root CA."""
    _ensure_root_ca()
    if os.path.exists(INTERMEDIATE_KEY_PATH) and os.path.exists(INTERMEDIATE_CERT_PATH) and os.path.exists(CA_CHAIN_PATH):
        return

    # Load Root CA
    with open(ROOT_KEY_PATH, "rb") as f:
        root_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ROOT_CERT_PATH, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())

    # Generate Intermediate CA RSA 4096-bit private key
    intermediate_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    intermediate_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Monitorix Sovereign Edge"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Agent Ingestion PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Monitorix Agent Ingestion Intermediate CA"),
    ])

    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(intermediate_subject)
        .issuer_name(root_cert.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1825))  # 5 years validity
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    # Persist Intermediate Key
    with open(INTERMEDIATE_KEY_PATH, "wb") as f:
        f.write(intermediate_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    _set_private_file_permissions(INTERMEDIATE_KEY_PATH)

    # Persist Intermediate Cert
    inter_pem_bytes = intermediate_cert.public_bytes(serialization.Encoding.PEM)
    with open(INTERMEDIATE_CERT_PATH, "wb") as f:
        f.write(inter_pem_bytes)
    _set_public_file_permissions(INTERMEDIATE_CERT_PATH)

    # Build and persist full CA chain: Intermediate + Root
    root_pem_bytes = root_cert.public_bytes(serialization.Encoding.PEM)
    chain_bytes = inter_pem_bytes + b"\n" + root_pem_bytes
    with open(CA_CHAIN_PATH, "wb") as f:
        f.write(chain_bytes)
    _set_public_file_permissions(CA_CHAIN_PATH)

    # Generate initial empty CRL
    generate_crl([])

def _ensure_server_certificate():
    """Generates and signs the gRPC Gateway server certificate if not present."""
    _ensure_intermediate_ca()
    if os.path.exists(SERVER_KEY_PATH) and os.path.exists(SERVER_CERT_PATH) and os.path.exists(SERVER_FULLCHAIN_PATH):
        return

    # Load Intermediate CA
    with open(INTERMEDIATE_KEY_PATH, "rb") as f:
        inter_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(INTERMEDIATE_CERT_PATH, "rb") as f:
        inter_cert = x509.load_pem_x509_certificate(f.read())

    # Generate Server RSA 2048-bit key
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Monitorix Sovereign Edge"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Gateway Infrastructure"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"grpc-gateway"),
    ])

    # Comprehensive Subject Alternative Names
    san_list = [
        x509.DNSName(u"grpc-gateway"),
        x509.DNSName(u"watch-sec-grpc-gateway"),
        x509.DNSName(u"localhost"),
        x509.DNSName(u"monitorix.co.in"),
        x509.DNSName(u"agent-apis.elsea.co.in"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("0.0.0.0")),
    ]

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(inter_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))  # 1 year validity
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key()),
            critical=False,
        )
        .sign(inter_key, hashes.SHA256())
    )

    with open(SERVER_KEY_PATH, "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    _set_private_file_permissions(SERVER_KEY_PATH)

    server_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    with open(SERVER_CERT_PATH, "wb") as f:
        f.write(server_pem)
    _set_public_file_permissions(SERVER_CERT_PATH)

    # Server fullchain: Server Cert + Intermediate Cert + Root Cert
    with open(CA_CHAIN_PATH, "rb") as f:
        ca_chain = f.read()
    with open(SERVER_FULLCHAIN_PATH, "wb") as f:
        f.write(server_pem + b"\n" + ca_chain)
    _set_public_file_permissions(SERVER_FULLCHAIN_PATH)

def initialize_pki():
    """Initializes the full hierarchical PKI infrastructure."""
    _ensure_root_ca()
    _ensure_intermediate_ca()
    _ensure_server_certificate()

def get_root_ca_cert_pem() -> str:
    _ensure_root_ca()
    with open(ROOT_CERT_PATH, "r") as f:
        return f.read()

def get_intermediate_ca_cert_pem() -> str:
    _ensure_intermediate_ca()
    with open(INTERMEDIATE_CERT_PATH, "r") as f:
        return f.read()

def get_ca_cert_pem() -> str:
    """Returns the trusted CA chain PEM (Intermediate + Root)."""
    _ensure_intermediate_ca()
    with open(CA_CHAIN_PATH, "r") as f:
        return f.read()

def get_server_credentials() -> Tuple[bytes, bytes]:
    """Returns (server_private_key_bytes, server_cert_fullchain_bytes) for gRPC SSL."""
    _ensure_server_certificate()
    with open(SERVER_KEY_PATH, "rb") as f:
        key_bytes = f.read()
    with open(SERVER_FULLCHAIN_PATH, "rb") as f:
        cert_bytes = f.read()
    return key_bytes, cert_bytes

def sign_agent_csr(
    csr_pem_str: str,
    tenant_id: int = 1,
    agent_id: Optional[str] = None,
    days_valid: int = 90
) -> Tuple[str, str, str]:
    """
    Signs an agent Certificate Signing Request (CSR) with the Intermediate CA.
    Enforces:
      - Valid CSR signature.
      - Subject: CN=<agent_id>, O=Monitorix Sovereign Edge, OU=Tenant-<tenant_id>.
      - SAN: DNS:<agent_id>, URI:spiffe://monitorix/tenant/<tenant_id>/agent/<agent_id>.
      - KeyUsage: digitalSignature, keyEncipherment.
      - ExtendedKeyUsage: clientAuth.
      - Cryptographic random serial number.
    Returns:
      (certificate_pem, serial_number_str, public_key_sha256_hex)
    """
    _ensure_intermediate_ca()

    with open(INTERMEDIATE_KEY_PATH, "rb") as f:
        inter_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(INTERMEDIATE_CERT_PATH, "rb") as f:
        inter_cert = x509.load_pem_x509_certificate(f.read())

    # Load and validate CSR
    csr = x509.load_pem_x509_csr(csr_pem_str.encode("utf-8"))
    if not csr.is_signature_valid:
        raise ValueError("Invalid CSR signature: cryptographic verification failed")

    # Extract or verify agent_id from CSR CN
    csr_common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    extracted_cn = csr_common_names[0].value if csr_common_names else ""
    effective_agent_id = agent_id or extracted_cn
    if not effective_agent_id:
        raise ValueError("CSR must contain a Common Name (agent_id)")

    now = datetime.datetime.now(datetime.timezone.utc)
    serial_number = x509.random_serial_number()

    # Subject specification
    agent_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Monitorix Sovereign Edge"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Tenant-{tenant_id}"),
        x509.NameAttribute(NameOID.COMMON_NAME, str(effective_agent_id)),
    ])

    # Subject Alternative Names
    san_list = [
        x509.DNSName(str(effective_agent_id)),
        x509.UniformResourceIdentifier(f"spiffe://monitorix/tenant/{tenant_id}/agent/{effective_agent_id}"),
    ]

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(agent_subject)
        .issuer_name(inter_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key()),
            critical=False,
        )
    )

    cert = cert_builder.sign(inter_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # Compute SHA-256 fingerprint of the public key
    pub_der = csr.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_sha256 = hashlib.sha256(pub_der).hexdigest()

    return cert_pem, str(serial_number), pub_sha256

def generate_crl(revoked_entries: List[Dict[str, Any]]) -> str:
    """
    Builds and signs an X.509 CRL v2 containing revoked certificate serial numbers.
    Each entry is a dict: {'serial_number': int, 'revocation_date': datetime, 'reason': str}
    """
    _ensure_intermediate_ca()

    with open(INTERMEDIATE_KEY_PATH, "rb") as f:
        inter_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(INTERMEDIATE_CERT_PATH, "rb") as f:
        inter_cert = x509.load_pem_x509_certificate(f.read())

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(inter_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
    )

    reason_map = {
        "key_compromise": x509.ReasonFlags.key_compromise,
        "ca_compromise": x509.ReasonFlags.ca_compromise,
        "affiliation_changed": x509.ReasonFlags.affiliation_changed,
        "superseded": x509.ReasonFlags.superseded,
        "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
        "certificate_hold": x509.ReasonFlags.certificate_hold,
    }

    for item in revoked_entries:
        s_num = int(item["serial_number"])
        r_date = item.get("revocation_date", now)
        if isinstance(r_date, datetime.datetime) and r_date.tzinfo is None:
            r_date = r_date.replace(tzinfo=datetime.timezone.utc)
        r_reason_str = str(item.get("reason", "key_compromise")).lower()
        r_reason = reason_map.get(r_reason_str, x509.ReasonFlags.key_compromise)

        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(s_num)
            .revocation_date(r_date)
            .add_extension(x509.CRLReason(r_reason), critical=False)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(inter_key, hashes.SHA256())
    crl_pem = crl.public_bytes(serialization.Encoding.PEM)
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    with open(CRL_PEM_PATH, "wb") as f:
        f.write(crl_pem)
    _set_public_file_permissions(CRL_PEM_PATH)

    with open(CRL_DER_PATH, "wb") as f:
        f.write(crl_der)
    _set_public_file_permissions(CRL_DER_PATH)

    return crl_pem.decode("utf-8")

def get_crl_pem() -> str:
    """Returns the current CRL in PEM format."""
    _ensure_directories()
    if not os.path.exists(CRL_PEM_PATH):
        return generate_crl([])
    with open(CRL_PEM_PATH, "r") as f:
        return f.read()
