from datetime import datetime, timezone

from app.crypto.crl import (
    CRL_PATH,
    build_crl,
    get_crl_details,
)
from app.db import (
    close_db_connection,
    get_db_connection,
)
from app.services.certificate_service import (
    get_certificate_by_id,
)


ALLOWED_REASONS = {
    "UNSPECIFIED",
    "KEY_COMPROMISE",
    "CA_COMPROMISE",
    "AFFILIATION_CHANGED",
    "SUPERSEDED",
    "CESSATION_OF_OPERATION",
    "CERTIFICATE_HOLD",
    "PRIVILEGE_WITHDRAWN",
}


def get_revocations():
    """Return all revocation records."""

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
                r.id,
                r.certificate_id,
                r.serial_number,
                r.revocation_date,
                r.reason,
                r.crl_path,
                r.created_at,
                c.common_name,
                c.certificate_type
            FROM revocations r
            JOIN certificates c
                ON c.id = r.certificate_id
            ORDER BY r.revocation_date DESC
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


def get_crl_source_records():
    """Return records needed to generate the CRL."""

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
                serial_number,
                revocation_date,
                reason
            FROM revocations
            ORDER BY revocation_date
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


def regenerate_crl():
    """Generate a fresh signed CRL from database revocations."""

    records = get_crl_source_records()

    crl = build_crl(
        records
    )

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE revocations
            SET crl_path = %s
            """,
            (str(CRL_PATH),),
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

    return crl


def revoke_certificate(
    certificate_id,
    reason,
):
    """Revoke one issued certificate and regenerate the CRL."""

    reason = reason.strip().upper()

    if reason not in ALLOWED_REASONS:
        raise ValueError(
            "Invalid revocation reason."
        )

    certificate = get_certificate_by_id(
        certificate_id
    )

    if certificate is None:
        raise ValueError(
            "Certificate was not found."
        )

    if certificate["status"] == "REVOKED":
        raise ValueError(
            "This certificate has already been revoked."
        )

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        revocation_date = datetime.now(
            timezone.utc
        ).replace(tzinfo=None)

        cursor.execute(
            """
            INSERT INTO revocations (
                certificate_id,
                serial_number,
                revocation_date,
                reason
            )
            VALUES (%s, %s, %s, %s)
            """,
            (
                certificate["id"],
                certificate["serial_number"],
                revocation_date,
                reason,
            ),
        )

        cursor.execute(
            """
            UPDATE certificates
            SET status = 'REVOKED'
            WHERE id = %s
            """,
            (certificate_id,),
        )

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
                "CERTIFICATE_REVOKED",
                "CERTIFICATE",
                certificate_id,
                (
                    f"Certificate {certificate['common_name']} "
                    f"revoked for reason {reason}."
                ),
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

    try:
        regenerate_crl()

    except Exception:
        # The revocation remains valid in the database.
        # Surface the CRL generation problem so it can be fixed.
        raise RuntimeError(
            "The certificate was recorded as revoked, "
            "but CRL generation failed."
        )

    return certificate


def current_crl_details():
    """Return CRL information when a CRL exists."""

    if not CRL_PATH.exists():
        return None

    return get_crl_details(
        CRL_PATH
    )