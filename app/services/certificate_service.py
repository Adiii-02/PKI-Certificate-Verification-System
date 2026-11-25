from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.crypto.certificate import (
    issue_end_entity_certificate,
)
from app.db import (
    close_db_connection,
    get_db_connection,
)
from app.services.ca_service import (
    certificate_datetime,
    get_ca_by_type,
    name_to_string,
)


def fingerprint_sha256(certificate):
    """Return a colon-separated SHA-256 fingerprint."""

    fingerprint = certificate.fingerprint(
        hashes.SHA256()
    )

    return ":".join(
        f"{byte:02X}"
        for byte in fingerprint
    )


def get_common_name(certificate):
    """Return the certificate Common Name."""

    attributes = (
        certificate.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )
    )

    if not attributes:
        return ""

    return attributes[0].value


def get_dns_names(certificate):
    """Return DNS names from Subject Alternative Name."""

    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )

        return extension.value.get_values_for_type(
            x509.DNSName
        )

    except x509.ExtensionNotFound:
        return []


def save_certificate_record(
    certificate,
    certificate_type,
    certificate_path,
    private_key_path,
    issuer_ca_id,
):
    """Store issued certificate metadata in MySQL."""

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        public_key = certificate.public_key()

        cursor.execute(
            """
            INSERT INTO certificates (
                common_name,
                certificate_type,
                subject_dn,
                issuer_dn,
                serial_number,
                certificate_path,
                private_key_path,
                fingerprint_sha256,
                valid_from,
                valid_until,
                rsa_key_size,
                signature_algorithm,
                status,
                issuer_ca_id
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                get_common_name(certificate),
                certificate_type,
                name_to_string(
                    certificate.subject
                ),
                name_to_string(
                    certificate.issuer
                ),
                format(
                    certificate.serial_number,
                    "X",
                ),
                str(certificate_path),
                str(private_key_path),
                fingerprint_sha256(
                    certificate
                ),
                certificate_datetime(
                    certificate,
                    "not_valid_before",
                ).replace(tzinfo=None),
                certificate_datetime(
                    certificate,
                    "not_valid_after",
                ).replace(tzinfo=None),
                public_key.key_size,
                (
                    certificate
                    .signature_hash_algorithm
                    .name
                    .upper()
                ),
                "ACTIVE",
                issuer_ca_id,
            ),
        )

        connection.commit()

        return cursor.lastrowid

    except Exception:
        if connection is not None:
            connection.rollback()

        raise

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None:
            close_db_connection(
                connection
            )


def log_certificate_event(
    certificate_id,
    description,
):
    """Record certificate issuance in the audit log."""

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO audit_events (
                event_type,
                entity_type,
                entity_id,
                description
            )
            VALUES (%s, %s, %s, %s)
            """,
            (
                "CERTIFICATE_ISSUED",
                "CERTIFICATE",
                certificate_id,
                description,
            ),
        )

        connection.commit()

    except Exception:
        if connection is not None:
            connection.rollback()

        raise

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None:
            close_db_connection(
                connection
            )


def issue_certificate(
    common_name,
    certificate_type,
    dns_name=None,
):
    """Issue a certificate and persist its metadata."""

    intermediate = get_ca_by_type(
        "INTERMEDIATE"
    )

    if intermediate is None:
        raise RuntimeError(
            "Intermediate CA has not been created."
        )

    result = issue_end_entity_certificate(
        common_name=common_name,
        certificate_type=certificate_type,
        dns_name=dns_name,
    )

    certificate = result["certificate"]

    try:
        certificate_id = save_certificate_record(
            certificate=certificate,
            certificate_type=certificate_type.upper(),
            certificate_path=result[
                "certificate_path"
            ],
            private_key_path=result[
                "private_key_path"
            ],
            issuer_ca_id=intermediate["id"],
        )

        log_certificate_event(
            certificate_id=certificate_id,
            description=(
                f"{certificate_type.upper()} "
                f"certificate issued for "
                f"{get_common_name(certificate)}."
            ),
        )

        return certificate_id

    except Exception:
        result[
            "certificate_path"
        ].unlink(missing_ok=True)

        result[
            "private_key_path"
        ].unlink(missing_ok=True)

        raise


def get_all_certificates():
    """Return all issued certificates."""

    connection = None
    cursor = None

    try:
        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                id,
                common_name,
                certificate_type,
                subject_dn,
                issuer_dn,
                serial_number,
                certificate_path,
                fingerprint_sha256,
                valid_from,
                valid_until,
                rsa_key_size,
                signature_algorithm,
                status,
                issuer_ca_id,
                created_at
            FROM certificates
            ORDER BY id DESC
            """
        )

        return cursor.fetchall()

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None:
            close_db_connection(
                connection
            )


def get_certificate_by_id(certificate_id):
    """Return one certificate database record."""

    connection = None
    cursor = None

    try:
        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                id,
                common_name,
                certificate_type,
                subject_dn,
                issuer_dn,
                serial_number,
                certificate_path,
                fingerprint_sha256,
                valid_from,
                valid_until,
                rsa_key_size,
                signature_algorithm,
                status,
                issuer_ca_id,
                created_at
            FROM certificates
            WHERE id = %s
            """,
            (certificate_id,),
        )

        return cursor.fetchone()

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None:
            close_db_connection(
                connection
            )


def get_certificate_details(certificate_record):
    """Read details directly from an issued certificate file."""

    path = certificate_record[
        "certificate_path"
    ]

    certificate = x509.load_pem_x509_certificate(
        open(path, "rb").read()
    )

    public_key = certificate.public_key()

    return {
        "common_name": get_common_name(
            certificate
        ),
        "subject": name_to_string(
            certificate.subject
        ),
        "issuer": name_to_string(
            certificate.issuer
        ),
        "serial_number": format(
            certificate.serial_number,
            "X",
        ),
        "certificate_type": certificate_record[
            "certificate_type"
        ],
        "valid_from": certificate_datetime(
            certificate,
            "not_valid_before",
        ),
        "valid_until": certificate_datetime(
            certificate,
            "not_valid_after",
        ),
        "rsa_key_size": public_key.key_size,
        "signature_algorithm": (
            certificate
            .signature_hash_algorithm
            .name
            .upper()
        ),
        "fingerprint": fingerprint_sha256(
            certificate
        ),
        "status": certificate_record[
            "status"
        ],
        "dns_names": get_dns_names(
            certificate
        ),
    }