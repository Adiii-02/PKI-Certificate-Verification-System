from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.crypto.ca import (
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_KEY_PATH,
    ROOT_CERT_PATH,
    ROOT_KEY_PATH,
    TRUSTED_ROOT_PATH,
    certificate_fingerprint,
    generate_intermediate_ca,
    generate_root_ca,
    load_certificate,
    serial_number_hex,
)
from app.db import close_db_connection, get_db_connection


def name_to_string(name):
    """Convert an X.509 distinguished name into a readable string."""

    return name.rfc4514_string()


def certificate_datetime(certificate, attribute):
    """
    Return timezone-aware validity values while supporting
    cryptography versions with either old or new properties.
    """

    utc_attribute = f"{attribute}_utc"

    if hasattr(certificate, utc_attribute):
        return getattr(certificate, utc_attribute)

    return getattr(certificate, attribute)


def insert_ca_record(
    certificate,
    ca_type,
    certificate_path,
    private_key_path,
    is_trusted,
    parent_ca_id=None,
):
    """Insert CA certificate metadata into MySQL."""

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        common_name_attributes = (
            certificate.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )
        )

        common_name = common_name_attributes[0].value

        query = """
            INSERT INTO certificate_authorities (
                common_name,
                ca_type,
                subject_dn,
                issuer_dn,
                serial_number,
                certificate_path,
                private_key_path,
                fingerprint_sha256,
                valid_from,
                valid_until,
                is_trusted,
                parent_ca_id
            )
            VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
        """

        values = (
            common_name,
            ca_type,
            name_to_string(certificate.subject),
            name_to_string(certificate.issuer),
            serial_number_hex(certificate),
            str(certificate_path),
            str(private_key_path),
            certificate_fingerprint(certificate),
            certificate_datetime(
                certificate,
                "not_valid_before",
            ).replace(tzinfo=None),
            certificate_datetime(
                certificate,
                "not_valid_after",
            ).replace(tzinfo=None),
            is_trusted,
            parent_ca_id,
        )

        cursor.execute(query, values)
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
            close_db_connection(connection)


def log_audit_event(
    event_type,
    entity_type,
    entity_id,
    description,
):
    """Record a PKI operation in the audit log."""

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
                event_type,
                entity_type,
                entity_id,
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
            close_db_connection(connection)


def create_root_ca():
    """Generate and persist the Root CA."""

    _, certificate = generate_root_ca()

    try:
        ca_id = insert_ca_record(
            certificate=certificate,
            ca_type="ROOT",
            certificate_path=ROOT_CERT_PATH,
            private_key_path=ROOT_KEY_PATH,
            is_trusted=True,
        )

        log_audit_event(
            event_type="ROOT_CA_CREATED",
            entity_type="CERTIFICATE_AUTHORITY",
            entity_id=ca_id,
            description=(
                "Root Certificate Authority generated "
                "and added to the local trusted-root store."
            ),
        )

        return ca_id

    except Exception:
        ROOT_KEY_PATH.unlink(missing_ok=True)
        ROOT_CERT_PATH.unlink(missing_ok=True)
        TRUSTED_ROOT_PATH.unlink(missing_ok=True)
        raise


def create_intermediate_ca():
    """Generate and persist the Intermediate CA."""

    root = get_ca_by_type("ROOT")

    if root is None:
        raise RuntimeError(
            "Root CA database record was not found."
        )

    _, certificate = generate_intermediate_ca()

    try:
        ca_id = insert_ca_record(
            certificate=certificate,
            ca_type="INTERMEDIATE",
            certificate_path=INTERMEDIATE_CERT_PATH,
            private_key_path=INTERMEDIATE_KEY_PATH,
            is_trusted=False,
            parent_ca_id=root["id"],
        )

        log_audit_event(
            event_type="INTERMEDIATE_CA_CREATED",
            entity_type="CERTIFICATE_AUTHORITY",
            entity_id=ca_id,
            description=(
                "Intermediate Certificate Authority generated "
                "and signed by the Root CA."
            ),
        )

        return ca_id

    except Exception:
        INTERMEDIATE_KEY_PATH.unlink(missing_ok=True)
        INTERMEDIATE_CERT_PATH.unlink(missing_ok=True)
        raise


def get_ca_by_type(ca_type):
    """Return one CA record by type."""

    connection = None
    cursor = None

    try:
        connection = get_db_connection()

        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT *
            FROM certificate_authorities
            WHERE ca_type = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (ca_type,),
        )

        return cursor.fetchone()

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None:
            close_db_connection(connection)


def get_all_cas():
    """Return all CA records."""

    connection = None
    cursor = None

    try:
        connection = get_db_connection()

        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                id,
                common_name,
                ca_type,
                subject_dn,
                issuer_dn,
                serial_number,
                certificate_path,
                fingerprint_sha256,
                valid_from,
                valid_until,
                is_trusted,
                parent_ca_id,
                created_at
            FROM certificate_authorities
            ORDER BY
                CASE
                    WHEN ca_type = 'ROOT' THEN 1
                    ELSE 2
                END,
                id
            """
        )

        return cursor.fetchall()

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None:
            close_db_connection(connection)


def inspect_certificate(path):
    """Return selected certificate information from the actual file."""

    certificate = load_certificate(path)

    public_key = certificate.public_key()

    return {
        "subject": name_to_string(certificate.subject),
        "issuer": name_to_string(certificate.issuer),
        "serial_number": serial_number_hex(certificate),
        "valid_from": certificate_datetime(
            certificate,
            "not_valid_before",
        ),
        "valid_until": certificate_datetime(
            certificate,
            "not_valid_after",
        ),
        "key_size": public_key.key_size,
        "signature_algorithm": (
            certificate.signature_hash_algorithm.name.upper()
        ),
        "fingerprint": certificate_fingerprint(certificate),
    }