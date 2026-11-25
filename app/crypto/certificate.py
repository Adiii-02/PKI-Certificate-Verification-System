from datetime import datetime, timedelta, timezone
from pathlib import Path
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.crypto.ca import (
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_KEY_PATH,
    PROJECT_ROOT,
    generate_private_key,
    load_certificate,
    load_private_key,
    save_certificate,
    save_private_key,
)


ISSUED_CERT_DIR = (
    PROJECT_ROOT / "storage" / "issued" / "certificates"
)

PRIVATE_KEY_DIR = (
    PROJECT_ROOT / "storage" / "private_keys"
)


COMMON_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$"
)

DNS_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def ensure_issuance_directories():
    """Create certificate/key storage directories if needed."""

    ISSUED_CERT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    PRIVATE_KEY_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def validate_common_name(common_name):
    """Validate an end-entity Common Name."""

    value = common_name.strip()

    if not value:
        raise ValueError(
            "Common Name is required."
        )

    if not COMMON_NAME_PATTERN.fullmatch(value):
        raise ValueError(
            "Common Name may contain letters, numbers, "
            "spaces, dots, underscores and hyphens, "
            "and must be 1-100 characters long."
        )

    return value


def validate_dns_name(dns_name):
    """Validate a DNS name used in a server certificate SAN."""

    value = dns_name.strip().lower()

    if not value:
        raise ValueError(
            "DNS name is required for server certificates."
        )

    if not DNS_PATTERN.fullmatch(value):
        raise ValueError(
            "Enter a valid DNS name such as "
            "server.local or www.example.test."
        )

    return value


def safe_filename(value):
    """Create a safe filename component."""

    safe = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        value.strip(),
    )

    safe = safe.strip("._-")

    if not safe:
        safe = "certificate"

    return safe[:80]


def build_subject(common_name):
    """Create the subject distinguished name."""

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
                "End Entity",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                common_name,
            ),
        ]
    )


def issue_end_entity_certificate(
    common_name,
    certificate_type,
    dns_name=None,
    validity_days=365,
):
    """
    Issue a real server or user X.509 certificate.

    The Intermediate CA signs the resulting certificate.
    """

    ensure_issuance_directories()

    common_name = validate_common_name(
        common_name
    )

    certificate_type = (
        certificate_type.strip().upper()
    )

    if certificate_type not in {
        "SERVER",
        "USER",
    }:
        raise ValueError(
            "Certificate type must be SERVER or USER."
        )

    if certificate_type == "SERVER":
        dns_name = validate_dns_name(
            dns_name or ""
        )
    else:
        dns_name = None

    if not isinstance(validity_days, int):
        raise ValueError(
            "Validity period must be an integer."
        )

    if validity_days < 1 or validity_days > 825:
        raise ValueError(
            "Validity period must be between "
            "1 and 825 days."
        )

    if (
        not INTERMEDIATE_CERT_PATH.exists()
        or not INTERMEDIATE_KEY_PATH.exists()
    ):
        raise FileNotFoundError(
            "Intermediate CA files were not found. "
            "Create the Intermediate CA first."
        )

    intermediate_certificate = load_certificate(
        INTERMEDIATE_CERT_PATH
    )

    intermediate_key = load_private_key(
        INTERMEDIATE_KEY_PATH
    )

    private_key = generate_private_key()

    subject = build_subject(
        common_name
    )

    now = datetime.now(timezone.utc)

    serial_number = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(
            intermediate_certificate.subject
        )
        .public_key(
            private_key.public_key()
        )
        .serial_number(
            serial_number
        )
        .not_valid_before(
            now - timedelta(minutes=1)
        )
        .not_valid_after(
            now + timedelta(days=validity_days)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
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
                intermediate_key.public_key()
            ),
            critical=False,
        )
    )

    if certificate_type == "SERVER":
        builder = (
            builder
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH,
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(dns_name),
                    ]
                ),
                critical=False,
            )
        )

    else:
        builder = (
            builder
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
        )

    certificate = builder.sign(
        private_key=intermediate_key,
        algorithm=hashes.SHA256(),
    )

    serial_hex = format(
        serial_number,
        "X",
    )

    filename_base = (
        f"{safe_filename(common_name)}_"
        f"{serial_hex[:12]}"
    )

    certificate_path = (
        ISSUED_CERT_DIR
        / f"{filename_base}.pem"
    )

    private_key_path = (
        PRIVATE_KEY_DIR
        / f"{filename_base}_key.pem"
    )

    save_certificate(
        certificate,
        certificate_path,
    )

    save_private_key(
        private_key,
        private_key_path,
    )

    return {
        "certificate": certificate,
        "private_key": private_key,
        "certificate_path": certificate_path,
        "private_key_path": private_key_path,
        "dns_name": dns_name,
    }