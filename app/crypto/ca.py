from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


PROJECT_ROOT = Path(__file__).resolve().parents[2]

ROOT_CA_DIR = PROJECT_ROOT / "storage" / "root_ca"
INTERMEDIATE_CA_DIR = PROJECT_ROOT / "storage" / "intermediate_ca"
TRUSTED_ROOTS_DIR = PROJECT_ROOT / "storage" / "trusted_roots"

ROOT_KEY_PATH = ROOT_CA_DIR / "root_ca_key.pem"
ROOT_CERT_PATH = ROOT_CA_DIR / "root_ca_cert.pem"

INTERMEDIATE_KEY_PATH = (
    INTERMEDIATE_CA_DIR / "intermediate_ca_key.pem"
)
INTERMEDIATE_CERT_PATH = (
    INTERMEDIATE_CA_DIR / "intermediate_ca_cert.pem"
)

TRUSTED_ROOT_PATH = (
    TRUSTED_ROOTS_DIR / "root_ca_cert.pem"
)


def ensure_directories():
    """Ensure required PKI storage directories exist."""

    ROOT_CA_DIR.mkdir(parents=True, exist_ok=True)
    INTERMEDIATE_CA_DIR.mkdir(parents=True, exist_ok=True)
    TRUSTED_ROOTS_DIR.mkdir(parents=True, exist_ok=True)


def generate_private_key():
    """Generate a new 2048-bit RSA private key."""

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def save_private_key(private_key, path):
    """Store a private key in PEM PKCS#8 format."""

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    path.write_bytes(pem_data)


def save_certificate(certificate, path):
    """Store an X.509 certificate in PEM format."""

    path.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )


def load_private_key(path):
    """Load a PEM encoded RSA private key."""

    return serialization.load_pem_private_key(
        path.read_bytes(),
        password=None,
    )


def load_certificate(path):
    """Load a PEM encoded X.509 certificate."""

    return x509.load_pem_x509_certificate(
        path.read_bytes()
    )


def certificate_fingerprint(certificate):
    """Return the SHA-256 certificate fingerprint."""

    fingerprint = certificate.fingerprint(hashes.SHA256())

    return ":".join(
        f"{byte:02X}"
        for byte in fingerprint
    )


def serial_number_hex(certificate):
    """Return the certificate serial number as uppercase hexadecimal."""

    return format(certificate.serial_number, "X")


def build_ca_name(common_name):
    """Build the distinguished name used by our local CAs."""

    return x509.Name(
        [
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                "IN",
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "PKI Verification Lab",
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME,
                "Certificate Authority",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                common_name,
            ),
        ]
    )


def generate_root_ca():
    """
    Generate a self-signed Root CA.

    Returns:
        tuple: (private_key, certificate)
    """

    ensure_directories()

    if ROOT_KEY_PATH.exists() or ROOT_CERT_PATH.exists():
        raise FileExistsError(
            "Root CA already exists. Existing CA material "
            "will not be overwritten."
        )

    private_key = generate_private_key()

    subject = build_ca_name(
        "PKI Verification Lab Root CA"
    )

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=1,
            ),
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
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                private_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                private_key.public_key()
            ),
            critical=False,
        )
        .sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )
    )

    save_private_key(
        private_key,
        ROOT_KEY_PATH,
    )

    save_certificate(
        certificate,
        ROOT_CERT_PATH,
    )

    shutil.copy2(
        ROOT_CERT_PATH,
        TRUSTED_ROOT_PATH,
    )

    return private_key, certificate


def generate_intermediate_ca():
    """
    Generate an Intermediate CA signed by the Root CA.

    Returns:
        tuple: (private_key, certificate)
    """

    ensure_directories()

    if not ROOT_KEY_PATH.exists() or not ROOT_CERT_PATH.exists():
        raise FileNotFoundError(
            "Root CA must exist before the Intermediate CA "
            "can be generated."
        )

    if (
        INTERMEDIATE_KEY_PATH.exists()
        or INTERMEDIATE_CERT_PATH.exists()
    ):
        raise FileExistsError(
            "Intermediate CA already exists. Existing CA material "
            "will not be overwritten."
        )

    root_key = load_private_key(ROOT_KEY_PATH)
    root_certificate = load_certificate(ROOT_CERT_PATH)

    intermediate_key = generate_private_key()

    subject = build_ca_name(
        "PKI Verification Lab Intermediate CA"
    )

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_certificate.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=0,
            ),
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
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                intermediate_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                root_key.public_key()
            ),
            critical=False,
        )
        .sign(
            private_key=root_key,
            algorithm=hashes.SHA256(),
        )
    )

    save_private_key(
        intermediate_key,
        INTERMEDIATE_KEY_PATH,
    )

    save_certificate(
        certificate,
        INTERMEDIATE_CERT_PATH,
    )

    return intermediate_key, certificate