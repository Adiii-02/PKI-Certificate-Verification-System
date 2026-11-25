from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.crypto.ca import (
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_KEY_PATH,
    PROJECT_ROOT,
    load_certificate,
    load_private_key,
)


LAB_DIR = PROJECT_ROOT / "storage" / "security_tests"

VALID_CERT_PATH = LAB_DIR / "valid_trusted.pem"
EXPIRED_CERT_PATH = LAB_DIR / "expired.pem"
FUTURE_CERT_PATH = LAB_DIR / "not_yet_valid.pem"
WRONG_SIGNATURE_CERT_PATH = LAB_DIR / "wrong_signature.pem"

MISSING_INTERMEDIATE_CERT_PATH = (
    LAB_DIR / "missing_intermediate.pem"
)

UNTRUSTED_ROOT_PATH = (
    LAB_DIR / "untrusted_root.pem"
)

UNTRUSTED_INTERMEDIATE_PATH = (
    LAB_DIR / "untrusted_intermediate.pem"
)

UNTRUSTED_CERT_PATH = (
    LAB_DIR / "untrusted_end_entity.pem"
)

TAMPERED_CERT_PATH = (
    LAB_DIR / "tampered.pem"
)

LAB_INTERMEDIATE_COPY = (
    LAB_DIR / "lab_intermediate.pem"
)

LAB_ROOT_COPY = (
    LAB_DIR / "lab_root.pem"
)


def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def make_name(common_name, unit="Security Test Lab"):
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
                unit,
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                common_name,
            ),
        ]
    )


def save_certificate(certificate, path):
    path.write_bytes(
        certificate.public_bytes(
            serialization.Encoding.PEM
        )
    )


def build_end_certificate(
    common_name,
    issuer_certificate,
    issuer_key,
    subject_key,
    not_before,
    not_after,
):
    subject = make_name(common_name)

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(
            issuer_certificate.subject
        )
        .public_key(
            subject_key.public_key()
        )
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            not_before
        )
        .not_valid_after(
            not_after
        )
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
            ),
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
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                subject_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
        .sign(
            private_key=issuer_key,
            algorithm=hashes.SHA256(),
        )
    )


def generate_untrusted_chain(now):
    untrusted_root_key = generate_key()

    root_name = make_name(
        "Security Lab Untrusted Root CA",
        "Untrusted Certificate Authority",
    )

    untrusted_root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(
            untrusted_root_key.public_key()
        )
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            now - timedelta(days=1)
        )
        .not_valid_after(
            now + timedelta(days=3650)
        )
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
                untrusted_root_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                untrusted_root_key.public_key()
            ),
            critical=False,
        )
        .sign(
            private_key=untrusted_root_key,
            algorithm=hashes.SHA256(),
        )
    )

    untrusted_intermediate_key = generate_key()

    intermediate_name = make_name(
        "Security Lab Untrusted Intermediate CA",
        "Untrusted Certificate Authority",
    )

    untrusted_intermediate = (
        x509.CertificateBuilder()
        .subject_name(
            intermediate_name
        )
        .issuer_name(
            untrusted_root.subject
        )
        .public_key(
            untrusted_intermediate_key.public_key()
        )
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            now - timedelta(days=1)
        )
        .not_valid_after(
            now + timedelta(days=1825)
        )
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
                untrusted_intermediate_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                untrusted_root_key.public_key()
            ),
            critical=False,
        )
        .sign(
            private_key=untrusted_root_key,
            algorithm=hashes.SHA256(),
        )
    )

    end_key = generate_key()

    end_certificate = build_end_certificate(
        common_name="untrusted.security.test",
        issuer_certificate=untrusted_intermediate,
        issuer_key=untrusted_intermediate_key,
        subject_key=end_key,
        not_before=now - timedelta(minutes=1),
        not_after=now + timedelta(days=365),
    )

    save_certificate(
        untrusted_root,
        UNTRUSTED_ROOT_PATH,
    )

    save_certificate(
        untrusted_intermediate,
        UNTRUSTED_INTERMEDIATE_PATH,
    )

    save_certificate(
        end_certificate,
        UNTRUSTED_CERT_PATH,
    )


def create_tampered_certificate(source_path):
    """
    Modify signed DER certificate data without re-signing it.

    The modification targets the subject Common Name while keeping
    the ASN.1 structure and field length unchanged.
    """

    certificate = load_certificate(
        source_path
    )

    der = bytearray(
        certificate.public_bytes(
            serialization.Encoding.DER
        )
    )

    original = b"valid.security.test"
    replacement = b"evil!.security.test"

    if len(original) != len(replacement):
        raise RuntimeError(
            "Tamper replacement must preserve field length."
        )

    position = der.find(original)

    if position == -1:
        raise RuntimeError(
            "Unable to locate the signed Common Name "
            "inside the DER certificate."
        )

    der[
        position:position + len(original)
    ] = replacement

    tampered_certificate = (
        x509.load_der_x509_certificate(
            bytes(der)
        )
    )

    save_certificate(
        tampered_certificate,
        TAMPERED_CERT_PATH,
    )


def generate_security_lab_certificates(
    root_cert_path,
):
    LAB_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    intermediate_certificate = load_certificate(
        INTERMEDIATE_CERT_PATH
    )

    intermediate_key = load_private_key(
        INTERMEDIATE_KEY_PATH
    )

    now = datetime.now(
        timezone.utc
    )

    shutil.copy2(
        INTERMEDIATE_CERT_PATH,
        LAB_INTERMEDIATE_COPY,
    )

    shutil.copy2(
        root_cert_path,
        LAB_ROOT_COPY,
    )

    # --------------------------------------------------
    # VALID TRUSTED
    # --------------------------------------------------

    valid_key = generate_key()

    valid_certificate = build_end_certificate(
        common_name="valid.security.test",
        issuer_certificate=intermediate_certificate,
        issuer_key=intermediate_key,
        subject_key=valid_key,
        not_before=now - timedelta(minutes=1),
        not_after=now + timedelta(days=365),
    )

    save_certificate(
        valid_certificate,
        VALID_CERT_PATH,
    )

    # --------------------------------------------------
    # EXPIRED
    # --------------------------------------------------

    expired_key = generate_key()

    expired_certificate = build_end_certificate(
        common_name="expired.security.test",
        issuer_certificate=intermediate_certificate,
        issuer_key=intermediate_key,
        subject_key=expired_key,
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1),
    )

    save_certificate(
        expired_certificate,
        EXPIRED_CERT_PATH,
    )

    # --------------------------------------------------
    # NOT YET VALID
    # --------------------------------------------------

    future_key = generate_key()

    future_certificate = build_end_certificate(
        common_name="future.security.test",
        issuer_certificate=intermediate_certificate,
        issuer_key=intermediate_key,
        subject_key=future_key,
        not_before=now + timedelta(days=1),
        not_after=now + timedelta(days=366),
    )

    save_certificate(
        future_certificate,
        FUTURE_CERT_PATH,
    )

    # --------------------------------------------------
    # WRONG SIGNATURE
    #
    # Issuer DN claims our Intermediate CA, but an
    # unrelated private key signs the certificate.
    # --------------------------------------------------

    wrong_subject_key = generate_key()
    wrong_signing_key = generate_key()

    wrong_signature_certificate = (
        x509.CertificateBuilder()
        .subject_name(
            make_name(
                "wrong-signature.security.test"
            )
        )
        .issuer_name(
            intermediate_certificate.subject
        )
        .public_key(
            wrong_subject_key.public_key()
        )
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            now - timedelta(minutes=1)
        )
        .not_valid_after(
            now + timedelta(days=365)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
            ),
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
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(
            private_key=wrong_signing_key,
            algorithm=hashes.SHA256(),
        )
    )

    save_certificate(
        wrong_signature_certificate,
        WRONG_SIGNATURE_CERT_PATH,
    )

    # --------------------------------------------------
    # MISSING INTERMEDIATE
    #
    # Certificate itself is perfectly valid, but the
    # verifier will intentionally receive a nonexistent
    # Intermediate CA path.
    # --------------------------------------------------

    missing_key = generate_key()

    missing_certificate = build_end_certificate(
        common_name="missing-intermediate.security.test",
        issuer_certificate=intermediate_certificate,
        issuer_key=intermediate_key,
        subject_key=missing_key,
        not_before=now - timedelta(minutes=1),
        not_after=now + timedelta(days=365),
    )

    save_certificate(
        missing_certificate,
        MISSING_INTERMEDIATE_CERT_PATH,
    )

    # --------------------------------------------------
    # TAMPERED
    # --------------------------------------------------

    create_tampered_certificate(
        VALID_CERT_PATH
    )

    # --------------------------------------------------
    # UNTRUSTED CHAIN
    # --------------------------------------------------

    generate_untrusted_chain(
        now
    )