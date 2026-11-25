from app.db import (
    close_db_connection,
    get_db_connection,
)


def get_dashboard_data():
    """Return live PKI statistics and recent activity."""

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM certificate_authorities
            """
        )
        ca_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM certificates
            """
        )
        certificate_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM certificates
            WHERE status = 'ACTIVE'
            """
        )
        active_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM certificates
            WHERE status = 'REVOKED'
            """
        )
        revoked_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM verification_history
            """
        )
        verification_count = cursor.fetchone()["count"]

        cursor.execute(
            """
            SELECT
                common_name,
                certificate_type,
                status,
                created_at
            FROM certificates
            ORDER BY id DESC
            LIMIT 5
            """
        )
        recent_certificates = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                vh.final_result,
                vh.cryptographically_valid,
                vh.trusted,
                vh.verified_at,
                c.common_name
            FROM verification_history vh
            LEFT JOIN certificates c
                ON c.id = vh.certificate_id
            ORDER BY vh.id DESC
            LIMIT 5
            """
        )
        recent_verifications = cursor.fetchall()

        return {
            "ca_count": ca_count,
            "certificate_count": certificate_count,
            "active_count": active_count,
            "revoked_count": revoked_count,
            "verification_count": verification_count,
            "recent_certificates": recent_certificates,
            "recent_verifications": recent_verifications,
        }

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None:
            close_db_connection(connection)