import shutil
import subprocess
from pathlib import Path

from app.crypto.ca import (
    INTERMEDIATE_CERT_PATH,
    ROOT_CERT_PATH,
)
from app.crypto.crl import CRL_PATH


def get_openssl_executable():
    """
    Locate the OpenSSL executable.

    OpenSSL must already be installed and available through PATH.
    """

    executable = shutil.which("openssl")

    if executable is None:
        raise RuntimeError(
            "OpenSSL executable was not found in PATH."
        )

    return executable


def run_openssl(arguments):
    """
    Run OpenSSL safely without invoking a command shell.

    Arguments are passed as a list, preventing shell-command
    injection through certificate paths or other values.
    """

    executable = get_openssl_executable()

    command = [
        executable,
        *arguments,
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            shell=False,
        )

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "OpenSSL verification timed out."
        ) from exc

    output_parts = []

    if completed.stdout:
        output_parts.append(
            completed.stdout.strip()
        )

    if completed.stderr:
        output_parts.append(
            completed.stderr.strip()
        )

    output = "\n".join(
        part
        for part in output_parts
        if part
    )

    return {
        "return_code": completed.returncode,
        "output": output,
        "command": command,
    }


def openssl_certificate_info(
    certificate_path,
):
    """Inspect selected certificate information with OpenSSL."""

    certificate_path = Path(
        certificate_path
    )

    if not certificate_path.exists():
        raise FileNotFoundError(
            "Certificate file was not found."
        )

    return run_openssl(
        [
            "x509",
            "-in",
            str(certificate_path),
            "-noout",
            "-subject",
            "-issuer",
            "-serial",
            "-dates",
            "-fingerprint",
            "-sha256",
        ]
    )


def openssl_verify_chain(
    certificate_path,
    root_path=ROOT_CERT_PATH,
    intermediate_path=INTERMEDIATE_CERT_PATH,
):
    """Verify a certificate chain without CRL checking."""

    certificate_path = Path(
        certificate_path
    )

    root_path = Path(
        root_path
    )

    intermediate_path = Path(
        intermediate_path
    )

    for path, label in [
        (certificate_path, "Certificate"),
        (root_path, "Root CA"),
        (intermediate_path, "Intermediate CA"),
    ]:
        if not path.exists():
            return {
                "return_code": None,
                "output": (
                    f"{label} file was not found: {path}"
                ),
                "command": [],
            }

    return run_openssl(
        [
            "verify",
            "-CAfile",
            str(root_path),
            "-untrusted",
            str(intermediate_path),
            str(certificate_path),
        ]
    )


def openssl_verify_with_crl(
    certificate_path,
    root_path=ROOT_CERT_PATH,
    intermediate_path=INTERMEDIATE_CERT_PATH,
    crl_path=CRL_PATH,
):
    """Verify a certificate chain and check the signed CRL."""

    certificate_path = Path(
        certificate_path
    )

    root_path = Path(
        root_path
    )

    intermediate_path = Path(
        intermediate_path
    )

    crl_path = Path(
        crl_path
    )

    for path, label in [
        (certificate_path, "Certificate"),
        (root_path, "Root CA"),
        (intermediate_path, "Intermediate CA"),
        (crl_path, "CRL"),
    ]:
        if not path.exists():
            return {
                "return_code": None,
                "output": (
                    f"{label} file was not found: {path}"
                ),
                "command": [],
            }

    return run_openssl(
        [
            "verify",
            "-crl_check",
            "-CAfile",
            str(root_path),
            "-untrusted",
            str(intermediate_path),
            "-CRLfile",
            str(crl_path),
            str(certificate_path),
        ]
    )


def classify_openssl_result(
    verification,
):
    """
    Convert OpenSSL verification output into an application-friendly
    result category.

    This classification is only for comparison/display.
    OpenSSL does not make the application's primary trust decision.
    """

    return_code = verification[
        "return_code"
    ]

    output = verification[
        "output"
    ]

    normalized = output.lower()

    if return_code == 0:
        return "TRUSTED"

    if "certificate revoked" in normalized:
        return "REVOKED"

    if "certificate has expired" in normalized:
        return "EXPIRED"

    if (
        "certificate is not yet valid" in normalized
        or "not yet valid" in normalized
    ):
        return "NOT_YET_VALID"

    if (
        "unable to get local issuer certificate"
        in normalized
        or "unable to get issuer certificate"
        in normalized
        or "unable to verify the first certificate"
        in normalized
    ):
        return "INCOMPLETE_CHAIN"

    if (
        "certificate signature failure"
        in normalized
        or "bad signature"
        in normalized
        or "signature failure"
        in normalized
    ):
        return "INVALID_SIGNATURE"

    if (
        "self-signed certificate in certificate chain"
        in normalized
        or "self-signed certificate"
        in normalized
    ):
        return "UNTRUSTED"

    return "VERIFICATION_FAILED"


def compare_results(
    application_result,
    openssl_result,
):
    """Compare application and OpenSSL final result categories."""

    return (
        "MATCH"
        if application_result == openssl_result
        else "MISMATCH"
    )


def cross_validate_certificate(
    certificate_path,
    application_result,
    root_path=ROOT_CERT_PATH,
    intermediate_path=INTERMEDIATE_CERT_PATH,
    crl_path=CRL_PATH,
):
    """
    Cross-check the Python application result against OpenSSL.

    CRL-aware verification is used whenever a CRL exists.
    """

    crl_path = Path(
        crl_path
    )

    if crl_path.exists():
        verification = (
            openssl_verify_with_crl(
                certificate_path=certificate_path,
                root_path=root_path,
                intermediate_path=intermediate_path,
                crl_path=crl_path,
            )
        )

        mode = "CHAIN + CRL"

    else:
        verification = (
            openssl_verify_chain(
                certificate_path=certificate_path,
                root_path=root_path,
                intermediate_path=intermediate_path,
            )
        )

        mode = "CHAIN"

    openssl_result = (
        classify_openssl_result(
            verification
        )
    )

    comparison = compare_results(
        application_result,
        openssl_result,
    )

    return {
        "application_result": application_result,
        "openssl_result": openssl_result,
        "comparison": comparison,
        "mode": mode,
        "return_code": verification[
            "return_code"
        ],
        "output": verification[
            "output"
        ],
    }