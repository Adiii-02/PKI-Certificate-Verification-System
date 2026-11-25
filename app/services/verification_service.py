import json

from app.crypto.verification import (
    verify_certificate_chain,
)
from app.db import (
    close_db_connection,
    get_db_connection,
)
from app.services.certificate_service import (
    get_certificate_by_id,
)


def save_verification_history(
    certificate_record,
    result,
):
    """Store a verification result in MySQL."""

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO verification_history (
                certificate_id,
                certificate_serial,
                certificate_fingerprint,
                cryptographically_valid,
                trusted,
                final_result,
                failed_check,
                reason,
                verification_details
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s
            )
            """,
            (
                certificate_record["id"],
                certificate_record["serial_number"],
                certificate_record[
                    "fingerprint_sha256"
                ],
                result[
                    "cryptographically_valid"
                ],
                result["trusted"],
                result["final_result"],
                result["failed_check"],
                result["reason"],
                json.dumps(
                    result["checks"]
                ),
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


def verify_issued_certificate(
    certificate_id,
):
    """
    Verify an issued certificate using the real
    cryptographic verification engine.
    """

    certificate_record = (
        get_certificate_by_id(
            certificate_id
        )
    )

    if certificate_record is None:
        raise ValueError(
            "Certificate was not found."
        )

    result = verify_certificate_chain(
        certificate_record[
            "certificate_path"
        ]
    )

    save_verification_history(
        certificate_record,
        result,
    )

    return certificate_record, result