import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_ca_cert(cert_path, key_path):
    """Génère la clé privée et le certificat pour l'Autorité de Certification (CA)."""
    print("Génération de la clé privée de la CA...")
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print("Génération du certificat de la CA...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Osiris DFIR Platform"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Osiris Root CA"),
    ])

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )

    certificate = cert_builder.sign(private_key, hashes.SHA256(), default_backend())

    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"Certificat CA généré : {cert_path}")
    return private_key, certificate

def generate_signed_cert(hostname, cert_path, key_path, ca_key, ca_cert):
    """Génère une clé privée et un certificat signé par notre CA."""
    print(f"Génération de la clé et du certificat pour {hostname}...")
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Osiris DFIR Platform"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
    )

    certificate = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())

    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"Certificat généré pour {hostname}: {cert_path}")


if __name__ == "__main__":
    # Créer les répertoires
    HIVE_CERTS_DIR = "hive/certs"
    AGENT_CERTS_DIR = "agent/certs"
    os.makedirs(HIVE_CERTS_DIR, exist_ok=True)
    os.makedirs(AGENT_CERTS_DIR, exist_ok=True)

    # 1. Générer la CA
    ca_key, ca_cert = generate_ca_cert(
        cert_path=os.path.join(HIVE_CERTS_DIR, "ca.crt"),
        key_path=os.path.join(HIVE_CERTS_DIR, "ca.key")
    )

    # 2. Générer le certificat du serveur (Hive)
    generate_signed_cert(
        hostname="localhost", # Important: doit correspondre à l'adresse du serveur
        cert_path=os.path.join(HIVE_CERTS_DIR, "server.crt"),
        key_path=os.path.join(HIVE_CERTS_DIR, "server.key"),
        ca_key=ca_key,
        ca_cert=ca_cert,
    )

    # 3. Générer le certificat de l'agent
    generate_signed_cert(
        hostname="osiris.agent", # Nom symbolique pour l'agent
        cert_path=os.path.join(AGENT_CERTS_DIR, "client.crt"),
        key_path=os.path.join(AGENT_CERTS_DIR, "client.key"),
        ca_key=ca_key,
        ca_cert=ca_cert,
    )
    
    # 4. Copier le certificat CA pour l'agent
    print("\nCopie du certificat CA pour l'agent...")
    with open(os.path.join(AGENT_CERTS_DIR, "ca.crt"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("\n✅ Configuration des certificats terminée.") 