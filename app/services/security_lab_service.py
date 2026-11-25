from pathlib import Path

from app.crypto.ca import (
    ROOT_CERT_PATH,
)
from app.crypto.security_lab import (
    EXPIRED_CERT_PATH,
    FUTURE_CERT_PATH,
    LAB_INTERMEDIATE_COPY,
    LAB_ROOT_COPY,
    MISSING_INTERMEDIATE_CERT_PATH,
    TAMPERED_CERT_PATH,
    UNTRUSTED_CERT_PATH,
    UNTRUSTED_INTERMEDIATE_PATH,
    UNTRUSTED_ROOT_PATH,
    VALID_CERT_PATH,
    WRONG_SIGNATURE_CERT_PATH,
    generate_security_lab_certificates,
)
from app.crypto.verification import (
    verify_certificate_chain,
)
from app.db import (
    close_db_connection,
    get_db_connection,
)


MISSING_INTERMEDIATE_PATH = (
    Path(__file__).resolve().parents[2]
    / "storage"
    / "security_tests"
    / "does_not_exist_intermediate.pem"
)


def get_revoked_certificate():
    """Return one genuinely revoked issued certificate."""

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
                certificate_path,
                serial_number,
                status
            FROM certificates
            WHERE status = 'REVOKED'
            ORDER BY id
            LIMIT 1
            """
        )

        return cursor.fetchone()

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None:
            close_db_connection(
                connection
            )


def generate_lab():
    generate_security_lab_certificates(
        ROOT_CERT_PATH
    )


def scenario_definitions():
    revoked = get_revoked_certificate()

    revoked_path = None

    if revoked is not None:
        revoked_path = Path(
            revoked["certificate_path"]
        )

    return [
        {
            "id": "valid",
            "title": "Valid Trusted Certificate",
            "short_title": "Valid",
            "description": (
                "A correctly signed certificate with a complete "
                "chain terminating at the trusted Root CA."
            ),
            "certificate_path": VALID_CERT_PATH,
            "intermediate_path": LAB_INTERMEDIATE_COPY,
            "root_path": LAB_ROOT_COPY,
            "category": "success",
        },
        {
            "id": "expired",
            "title": "Expired Certificate",
            "short_title": "Expired",
            "description": (
                "A correctly signed certificate whose validity "
                "period has already ended."
            ),
            "certificate_path": EXPIRED_CERT_PATH,
            "intermediate_path": LAB_INTERMEDIATE_COPY,
            "root_path": LAB_ROOT_COPY,
            "category": "failure",
        },
        {
            "id": "future",
            "title": "Not-Yet-Valid Certificate",
            "short_title": "Not Yet Valid",
            "description": (
                "A correctly signed certificate whose validity "
                "period starts in the future."
            ),
            "certificate_path": FUTURE_CERT_PATH,
            "intermediate_path": LAB_INTERMEDIATE_COPY,
            "root_path": LAB_ROOT_COPY,
            "category": "warning",
        },
        {
            "id": "revoked",
            "title": "Revoked Certificate",
            "short_title": "Revoked",
            "description": (
                "A genuinely issued certificate whose serial "
                "number is present in the signed CRL."
            ),
            "certificate_path": revoked_path,
            "intermediate_path": LAB_INTERMEDIATE_COPY,
            "root_path": LAB_ROOT_COPY,
            "category": "failure",
        },
        {
            "id": "tampered",
            "title": "Altered / Tampered Certificate",
            "short_title": "Tampered",
            "description": (
                "Signed certificate data is modified after signing, "
                "causing cryptographic integrity verification to fail."
            ),
            "certificate_path": TAMPERED_CERT_PATH,
            "intermediate_path": LAB_INTERMEDIATE_COPY,
            "root_path": LAB_ROOT_COPY,
            "category": "failure",
        },
        {
            "id": "wrong-signature",
            "title": "Incorrect Signature",
            "short_title": "Bad Signature",
            "description": (
                "The certificate claims the normal Intermediate CA "
                "as issuer but was signed with an unrelated key."
            ),
            "certificate_path": WRONG_SIGNATURE_CERT_PATH,
            "intermediate_path": LAB_INTERMEDIATE_COPY,
            "root_path": LAB_ROOT_COPY,
            "category": "failure",
        },
        {
            "id": "missing-intermediate",
            "title": "Missing Intermediate CA",
            "short_title": "Missing Issuer",
            "description": (
                "The certificate is valid, but the issuing "
                "Intermediate CA is deliberately unavailable."
            ),
            "certificate_path": MISSING_INTERMEDIATE_CERT_PATH,
            "intermediate_path": MISSING_INTERMEDIATE_PATH,
            "root_path": LAB_ROOT_COPY,
            "category": "warning",
        },
        {
            "id": "untrusted",
            "title": "Untrusted CA",
            "short_title": "Untrusted",
            "description": (
                "The complete chain is cryptographically valid, "
                "but its Root CA is absent from the trusted-root store."
            ),
            "certificate_path": UNTRUSTED_CERT_PATH,
            "intermediate_path": UNTRUSTED_INTERMEDIATE_PATH,
            "root_path": UNTRUSTED_ROOT_PATH,
            "category": "warning",
        },
    ]


def get_scenarios():
    scenarios = scenario_definitions()

    for scenario in scenarios:
        path = scenario["certificate_path"]

        scenario["generated"] = (
            path is not None
            and path.exists()
        )

    return scenarios


def run_scenario(scenario_id):
    scenarios = scenario_definitions()

    scenario = next(
        (
            item
            for item in scenarios
            if item["id"] == scenario_id
        ),
        None,
    )

    if scenario is None:
        raise ValueError(
            "Unknown Security Lab scenario."
        )

    path = scenario["certificate_path"]

    if path is None or not path.exists():
        if scenario_id == "revoked":
            raise FileNotFoundError(
                "No revoked certificate is available. "
                "Revoke an issued certificate first."
            )

        raise FileNotFoundError(
            "Security Lab certificate has not been generated."
        )

    result = verify_certificate_chain(
        certificate_path=path,
        intermediate_path=scenario[
            "intermediate_path"
        ],
        root_path=scenario[
            "root_path"
        ],
    )

    display_result = result[
        "final_result"
    ]

    if (
        scenario_id == "tampered"
        and result["final_result"]
        == "INVALID_SIGNATURE"
    ):
        display_result = (
            "ALTERED / TAMPERED"
        )

    return (
        scenario,
        result,
        display_result,
    )