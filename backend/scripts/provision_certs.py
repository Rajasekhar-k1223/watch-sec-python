import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_mtls_infrastructure(output_dir="certs"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 1. Generate Root CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Monitorix Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Monitorix Enterprise"),
    ])
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_subject
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256())

    # Save CA
    with open(os.path.join(output_dir, "ca.crt"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(output_dir, "ca.key"), "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 2. Generate Agent Certificate
    agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    agent_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"monitorix-agent-001"),
    ])
    agent_cert = x509.CertificateBuilder().subject_name(
        agent_subject
    ).issuer_name(
        ca_subject
    ).public_key(
        agent_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_key, hashes.SHA256())

    # Save Agent Cert
    with open(os.path.join(output_dir, "agent.crt"), "wb") as f:
        f.write(agent_cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(output_dir, "agent.key"), "wb") as f:
        f.write(agent_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"mTLS Infrastructure generated in {output_dir}/")
    print("Files created: ca.crt, ca.key, agent.crt, agent.key")

if __name__ == "__main__":
    generate_mtls_infrastructure()
