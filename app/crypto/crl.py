from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.crypto.ca import (
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_KEY_PATH,
    PROJECT_ROOT,
    load_certificate,
    load_private_key,
)


CRL_DIR = PROJECT_ROOT / "storage" / "crl"
CRL_PATH = CRL_DIR / "intermediate_ca.crl.pem"


REASON_MAP = {
    "UNSPECIFIED": x509.ReasonFlags.unspecified,
    "KEY_COMPROMISE": x509.ReasonFlags.key_compromise,
    "CA_COMPROMISE": x509.ReasonFlags.ca_compromise,
    "AFFILIATION_CHANGED": x509.ReasonFlags.affiliation_changed,
    "SUPERSEDED": x509.ReasonFlags.superseded,
    "CESSATION_OF_OPERATION": x509.ReasonFlags.cessation_of_operation,
    "CERTIFICATE_HOLD": x509.ReasonFlags.certificate_hold,
    "PRIVILEGE_WITHDRAWN": x509.ReasonFlags.privilege_withdrawn,
}


def certificate_time(certificate, attribute):
    """Return a timezone-aware certificate datetime."""

    utc_attribute = f"{attribute}_utc"

    if hasattr(certificate, utc_attribute):
        return getattr(certificate, utc_attribute)

    value = getattr(certificate, attribute)

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value


def build_crl(revocations):
    """
    Build and sign a CRL using the Intermediate CA.

    revocations must contain:
        serial_number
        revocation_date
        reason
    """

    if not INTERMEDIATE_CERT_PATH.exists():
        raise FileNotFoundError(
            "Intermediate CA certificate was not found."
        )

    if not INTERMEDIATE_KEY_PATH.exists():
        raise FileNotFoundError(
            "Intermediate CA private key was not found."
        )

    CRL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    intermediate_certificate = load_certificate(
        INTERMEDIATE_CERT_PATH
    )

    intermediate_key = load_private_key(
        INTERMEDIATE_KEY_PATH
    )

    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(
            intermediate_certificate.subject
        )
        .last_update(
            now
        )
        .next_update(
            now + timedelta(days=7)
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                intermediate_key.public_key()
            ),
            critical=False,
        )
    )

    for item in revocations:
        serial_number = int(
            item["serial_number"],
            16,
        )

        revocation_date = item[
            "revocation_date"
        ]

        if revocation_date.tzinfo is None:
            revocation_date = revocation_date.replace(
                tzinfo=timezone.utc
            )

        reason_name = item[
            "reason"
        ]

        reason_flag = REASON_MAP.get(
            reason_name,
            x509.ReasonFlags.unspecified,
        )

        revoked_certificate = (
            x509.RevokedCertificateBuilder()
            .serial_number(
                serial_number
            )
            .revocation_date(
                revocation_date
            )
            .add_extension(
                x509.CRLReason(
                    reason_flag
                ),
                critical=False,
            )
            .build()
        )

        builder = builder.add_revoked_certificate(
            revoked_certificate
        )

    crl = builder.sign(
        private_key=intermediate_key,
        algorithm=hashes.SHA256(),
    )

    CRL_PATH.write_bytes(
        crl.public_bytes(
            serialization.Encoding.PEM
        )
    )

    return crl


def load_crl(path=CRL_PATH):
    """Load a PEM encoded CRL."""

    return x509.load_pem_x509_crl(
        path.read_bytes()
    )


def get_crl_details(path=CRL_PATH):
    """Return information from the actual signed CRL."""

    crl = load_crl(path)

    if hasattr(crl, "last_update_utc"):
        last_update = crl.last_update_utc
    else:
        last_update = crl.last_update.replace(
            tzinfo=timezone.utc
        )

    if hasattr(crl, "next_update_utc"):
        next_update = crl.next_update_utc
    else:
        next_update = crl.next_update.replace(
            tzinfo=timezone.utc
        )

    return {
        "issuer": crl.issuer.rfc4514_string(),
        "last_update": last_update,
        "next_update": next_update,
        "revoked_count": len(crl),
        "signature_algorithm": (
            crl.signature_hash_algorithm.name.upper()
        ),
    }