from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    padding,
    rsa,
)

from app.crypto.ca import (
    INTERMEDIATE_CERT_PATH,
    ROOT_CERT_PATH,
    TRUSTED_ROOTS_DIR,
    certificate_fingerprint,
    load_certificate,
)
from app.crypto.crl import (
    CRL_PATH,
    load_crl,
)


def make_check(
    name,
    passed,
    explanation,
    evidence=None,
):
    """Create one verification-stage result."""

    return {
        "name": name,
        "passed": passed,
        "explanation": explanation,
        "evidence": evidence,
    }


def certificate_time(
    certificate,
    attribute,
):
    """Return a timezone-aware certificate validity datetime."""

    utc_attribute = f"{attribute}_utc"

    if hasattr(certificate, utc_attribute):
        return getattr(certificate, utc_attribute)

    value = getattr(certificate, attribute)

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value


def crl_time(
    crl,
    attribute,
):
    """Return a timezone-aware CRL datetime."""

    utc_attribute = f"{attribute}_utc"

    if hasattr(crl, utc_attribute):
        return getattr(crl, utc_attribute)

    value = getattr(crl, attribute)

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value


def verify_signed_object(
    signature,
    signed_data,
    signature_hash_algorithm,
    public_key,
):
    """
    Verify a certificate or CRL signature using
    the supplied issuer public key.
    """

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            signature,
            signed_data,
            padding.PKCS1v15(),
            signature_hash_algorithm,
        )

    elif isinstance(
        public_key,
        ec.EllipticCurvePublicKey,
    ):
        public_key.verify(
            signature,
            signed_data,
            ec.ECDSA(
                signature_hash_algorithm
            ),
        )

    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key.verify(
            signature,
            signed_data,
            signature_hash_algorithm,
        )

    elif isinstance(
        public_key,
        (
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
        ),
    ):
        public_key.verify(
            signature,
            signed_data,
        )

    else:
        raise TypeError(
            "Unsupported public-key algorithm."
        )


def verify_signature(
    certificate,
    issuer_certificate,
):
    """Verify an X.509 certificate signature."""

    verify_signed_object(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        certificate.signature_hash_algorithm,
        issuer_certificate.public_key(),
    )


def verify_crl_signature(
    crl,
    issuer_certificate,
):
    """Verify an X.509 CRL signature."""

    verify_signed_object(
        crl.signature,
        crl.tbs_certlist_bytes,
        crl.signature_hash_algorithm,
        issuer_certificate.public_key(),
    )


def check_ca_permissions(certificate):
    """
    Verify that a certificate is permitted to operate
    as a Certificate Authority.
    """

    basic_constraints = (
        certificate.extensions
        .get_extension_for_class(
            x509.BasicConstraints
        )
        .value
    )

    if not basic_constraints.ca:
        raise ValueError(
            "Issuer Basic Constraints does not permit CA usage."
        )

    key_usage = (
        certificate.extensions
        .get_extension_for_class(
            x509.KeyUsage
        )
        .value
    )

    if not key_usage.key_cert_sign:
        raise ValueError(
            "Issuer Key Usage does not permit certificate signing."
        )

    return basic_constraints, key_usage


def check_crl_permission(certificate):
    """Verify that a CA is permitted to sign CRLs."""

    key_usage = (
        certificate.extensions
        .get_extension_for_class(
            x509.KeyUsage
        )
        .value
    )

    if not key_usage.crl_sign:
        raise ValueError(
            "Intermediate CA Key Usage does not permit CRL signing."
        )


def find_trusted_root(root_certificate):
    """
    Check whether the exact Root CA exists in the
    application's local trusted-root store.
    """

    expected_fingerprint = (
        certificate_fingerprint(
            root_certificate
        )
    )

    if not TRUSTED_ROOTS_DIR.exists():
        return None

    for path in TRUSTED_ROOTS_DIR.glob("*.pem"):
        try:
            trusted_certificate = (
                load_certificate(path)
            )

            trusted_fingerprint = (
                certificate_fingerprint(
                    trusted_certificate
                )
            )

            if (
                trusted_fingerprint
                == expected_fingerprint
            ):
                return path

        except (OSError, ValueError):
            continue

    return None


def verify_certificate_chain(
    certificate_path,
    intermediate_path=INTERMEDIATE_CERT_PATH,
    root_path=ROOT_CERT_PATH,
    crl_path=CRL_PATH,
):
    """
    Perform complete certificate trust-chain verification.

    This evaluates:
    - X.509 parsing
    - certificate validity
    - issuer relationship
    - end-certificate signature
    - Intermediate CA permissions
    - Root relationship
    - Intermediate signature
    - Root CA permissions
    - Root self-signature
    - trusted-root status
    - CRL issuer
    - CRL signing permission
    - CRL signature
    - CRL validity
    - certificate revocation status
    """

    checks = []

    result = {
        "checks": checks,
        "cryptographically_valid": False,
        "trusted": False,
        "final_result": "INVALID_CERTIFICATE",
        "failed_check": None,
        "reason": None,
    }

    certificate_path = Path(
        certificate_path
    )

    intermediate_path = Path(
        intermediate_path
    )

    root_path = Path(
        root_path
    )

    crl_path = Path(
        crl_path
    )

    # =====================================================
    # 1. CERTIFICATE PARSING
    # =====================================================

    try:
        certificate = load_certificate(
            certificate_path
        )

        checks.append(
            make_check(
                "Certificate Parsing",
                True,
                (
                    "The end-entity certificate was parsed "
                    "as a valid X.509 certificate."
                ),
                str(certificate_path),
            )
        )

    except (OSError, ValueError) as exc:
        checks.append(
            make_check(
                "Certificate Parsing",
                False,
                (
                    "The certificate could not be parsed "
                    "as a valid X.509 certificate."
                ),
            )
        )

        result["failed_check"] = (
            "Certificate Parsing"
        )

        result["reason"] = str(exc)

        return result

    # =====================================================
    # 2. VALIDITY PERIOD
    # =====================================================

    now = datetime.now(
        timezone.utc
    )

    not_before = certificate_time(
        certificate,
        "not_valid_before",
    )

    not_after = certificate_time(
        certificate,
        "not_valid_after",
    )

    if now < not_before:
        checks.append(
            make_check(
                "Validity Check",
                False,
                "The certificate is not yet valid.",
                (
                    f"Valid from "
                    f"{not_before.isoformat()}"
                ),
            )
        )

        result["final_result"] = (
            "NOT_YET_VALID"
        )

        result["failed_check"] = (
            "Validity Check"
        )

        result["reason"] = (
            "The current time is before the "
            "certificate Not Before value."
        )

        return result

    if now > not_after:
        checks.append(
            make_check(
                "Validity Check",
                False,
                "The certificate has expired.",
                (
                    f"Expired at "
                    f"{not_after.isoformat()}"
                ),
            )
        )

        result["final_result"] = "EXPIRED"

        result["failed_check"] = (
            "Validity Check"
        )

        result["reason"] = (
            "The current time is after the "
            "certificate Not After value."
        )

        return result

    checks.append(
        make_check(
            "Validity Check",
            True,
            (
                "The certificate is currently "
                "within its validity period."
            ),
            (
                f"{not_before.isoformat()} "
                f"to {not_after.isoformat()}"
            ),
        )
    )

    # =====================================================
    # 3. INTERMEDIATE CA
    # =====================================================

    try:
        intermediate = load_certificate(
            intermediate_path
        )

        checks.append(
            make_check(
                "Issuer Identification",
                True,
                (
                    "The Intermediate CA certificate "
                    "required by the chain is available."
                ),
                intermediate.subject.rfc4514_string(),
            )
        )

    except (OSError, ValueError):
        checks.append(
            make_check(
                "Issuer Identification",
                False,
                (
                    "The Intermediate CA certificate "
                    "required to build the chain is unavailable."
                ),
            )
        )

        result["final_result"] = (
            "INCOMPLETE_CHAIN"
        )

        result["failed_check"] = (
            "Issuer Identification"
        )

        result["reason"] = (
            "The issuing Intermediate CA "
            "could not be loaded."
        )

        return result

    # =====================================================
    # 4. ISSUER / SUBJECT RELATIONSHIP
    # =====================================================

    if (
        certificate.issuer
        != intermediate.subject
    ):
        checks.append(
            make_check(
                "Issuer / Subject Relationship",
                False,
                (
                    "The end certificate Issuer does "
                    "not match the Intermediate CA Subject."
                ),
                (
                    f"Certificate issuer: "
                    f"{certificate.issuer.rfc4514_string()}"
                ),
            )
        )

        result["final_result"] = (
            "INCOMPLETE_CHAIN"
        )

        result["failed_check"] = (
            "Issuer / Subject Relationship"
        )

        result["reason"] = (
            "The supplied Intermediate CA is not "
            "identified as the issuer of this certificate."
        )

        return result

    checks.append(
        make_check(
            "Issuer / Subject Relationship",
            True,
            (
                "The certificate Issuer matches "
                "the Intermediate CA Subject."
            ),
            certificate.issuer.rfc4514_string(),
        )
    )

    # =====================================================
    # 5. END-CERTIFICATE SIGNATURE
    # =====================================================

    try:
        verify_signature(
            certificate,
            intermediate,
        )

        checks.append(
            make_check(
                "Certificate Signature",
                True,
                (
                    "The certificate signature was successfully "
                    "verified using the Intermediate CA public key."
                ),
                (
                    certificate
                    .signature_algorithm_oid
                    .dotted_string
                ),
            )
        )

    except InvalidSignature:
        checks.append(
            make_check(
                "Certificate Signature",
                False,
                (
                    "The certificate signature does not verify "
                    "with the Intermediate CA public key."
                ),
            )
        )

        result["final_result"] = (
            "INVALID_SIGNATURE"
        )

        result["failed_check"] = (
            "Certificate Signature"
        )

        result["reason"] = (
            "The signed certificate data and its signature "
            "do not cryptographically match."
        )

        return result

    except Exception as exc:
        checks.append(
            make_check(
                "Certificate Signature",
                False,
                (
                    "The certificate signature "
                    "could not be verified."
                ),
            )
        )

        result["final_result"] = (
            "INVALID_SIGNATURE"
        )

        result["failed_check"] = (
            "Certificate Signature"
        )

        result["reason"] = str(exc)

        return result

    # =====================================================
    # 6. INTERMEDIATE BASIC CONSTRAINTS + KEY USAGE
    # =====================================================

    try:
        constraints, _ = (
            check_ca_permissions(
                intermediate
            )
        )

        checks.append(
            make_check(
                "Intermediate Basic Constraints",
                True,
                (
                    "The Intermediate certificate is "
                    "authorized to act as a Certificate Authority."
                ),
                (
                    f"CA=TRUE, path_length="
                    f"{constraints.path_length}"
                ),
            )
        )

        checks.append(
            make_check(
                "Intermediate Key Usage",
                True,
                (
                    "The Intermediate CA Key Usage "
                    "permits certificate signing."
                ),
                "keyCertSign=TRUE",
            )
        )

    except (
        x509.ExtensionNotFound,
        ValueError,
    ) as exc:
        checks.append(
            make_check(
                "CA Permission",
                False,
                str(exc),
            )
        )

        result["final_result"] = (
            "INVALID_CERTIFICATE"
        )

        result["failed_check"] = (
            "CA Permission"
        )

        result["reason"] = str(exc)

        return result

    # =====================================================
    # 7. ROOT CA CERTIFICATE
    # =====================================================

    try:
        root = load_certificate(
            root_path
        )

        checks.append(
            make_check(
                "Root CA Certificate",
                True,
                (
                    "The Root CA certificate required "
                    "by the chain is available."
                ),
                root.subject.rfc4514_string(),
            )
        )

    except (OSError, ValueError):
        checks.append(
            make_check(
                "Root CA Certificate",
                False,
                (
                    "The Root CA certificate required "
                    "to complete the chain is unavailable."
                ),
            )
        )

        result["final_result"] = (
            "INCOMPLETE_CHAIN"
        )

        result["failed_check"] = (
            "Root CA Certificate"
        )

        result["reason"] = (
            "The Root CA certificate "
            "could not be loaded."
        )

        return result

    # =====================================================
    # 8. INTERMEDIATE -> ROOT RELATIONSHIP
    # =====================================================

    if intermediate.issuer != root.subject:
        checks.append(
            make_check(
                "Intermediate Issuer",
                False,
                (
                    "The Intermediate CA Issuer does "
                    "not match the Root CA Subject."
                ),
            )
        )

        result["final_result"] = (
            "INCOMPLETE_CHAIN"
        )

        result["failed_check"] = (
            "Intermediate Issuer"
        )

        result["reason"] = (
            "The supplied Root CA is not "
            "the Intermediate CA issuer."
        )

        return result

    checks.append(
        make_check(
            "Intermediate Issuer",
            True,
            (
                "The Intermediate CA identifies "
                "the Root CA as its issuer."
            ),
            intermediate.issuer.rfc4514_string(),
        )
    )

    # =====================================================
    # 9. INTERMEDIATE SIGNATURE
    # =====================================================

    try:
        verify_signature(
            intermediate,
            root,
        )

        checks.append(
            make_check(
                "Intermediate Signature",
                True,
                (
                    "The Intermediate CA signature was "
                    "successfully verified using the "
                    "Root CA public key."
                ),
                (
                    intermediate
                    .signature_algorithm_oid
                    .dotted_string
                ),
            )
        )

    except InvalidSignature:
        checks.append(
            make_check(
                "Intermediate Signature",
                False,
                (
                    "The Intermediate CA signature does "
                    "not verify using the Root CA public key."
                ),
            )
        )

        result["final_result"] = (
            "INVALID_SIGNATURE"
        )

        result["failed_check"] = (
            "Intermediate Signature"
        )

        result["reason"] = (
            "Cryptographic verification of the "
            "Intermediate CA signature failed."
        )

        return result

    except Exception as exc:
        checks.append(
            make_check(
                "Intermediate Signature",
                False,
                (
                    "The Intermediate CA signature "
                    "could not be verified."
                ),
            )
        )

        result["final_result"] = (
            "INVALID_SIGNATURE"
        )

        result["failed_check"] = (
            "Intermediate Signature"
        )

        result["reason"] = str(exc)

        return result

    # =====================================================
    # 10. ROOT CA CONSTRAINTS
    # =====================================================

    try:
        root_constraints, _ = (
            check_ca_permissions(
                root
            )
        )

        checks.append(
            make_check(
                "Root CA Constraints",
                True,
                (
                    "The Root certificate is authorized "
                    "to act as a Certificate Authority."
                ),
                (
                    f"CA=TRUE, path_length="
                    f"{root_constraints.path_length}"
                ),
            )
        )

    except (
        x509.ExtensionNotFound,
        ValueError,
    ) as exc:
        checks.append(
            make_check(
                "Root CA Constraints",
                False,
                (
                    "The Root certificate does not "
                    "have valid CA permissions."
                ),
            )
        )

        result["final_result"] = (
            "INVALID_CERTIFICATE"
        )

        result["failed_check"] = (
            "Root CA Constraints"
        )

        result["reason"] = str(exc)

        return result

    # =====================================================
    # 11. ROOT SELF-SIGNATURE
    # =====================================================

    if root.subject != root.issuer:
        checks.append(
            make_check(
                "Root Self-Signature",
                False,
                (
                    "The configured Root CA "
                    "is not self-issued."
                ),
            )
        )

        result["final_result"] = (
            "INVALID_CERTIFICATE"
        )

        result["failed_check"] = (
            "Root Self-Signature"
        )

        result["reason"] = (
            "Root Subject and Issuer differ."
        )

        return result

    try:
        verify_signature(
            root,
            root,
        )

        checks.append(
            make_check(
                "Root Self-Signature",
                True,
                (
                    "The Root CA self-signature "
                    "is cryptographically valid."
                ),
                (
                    root
                    .signature_algorithm_oid
                    .dotted_string
                ),
            )
        )

    except Exception:
        checks.append(
            make_check(
                "Root Self-Signature",
                False,
                (
                    "The Root CA self-signature "
                    "is invalid."
                ),
            )
        )

        result["final_result"] = (
            "INVALID_SIGNATURE"
        )

        result["failed_check"] = (
            "Root Self-Signature"
        )

        result["reason"] = (
            "The Root CA self-signature "
            "could not be verified."
        )

        return result

    # Certificate and CA signatures have all passed.
    result["cryptographically_valid"] = True

    # =====================================================
    # 12. TRUSTED ROOT
    # =====================================================

    trusted_root = find_trusted_root(
        root
    )

    if trusted_root is None:
        checks.append(
            make_check(
                "Trusted Root",
                False,
                (
                    "The signature chain is cryptographically "
                    "valid, but the Root CA is not present in "
                    "the local trusted-root store."
                ),
            )
        )

        result["final_result"] = (
            "UNTRUSTED"
        )

        result["failed_check"] = (
            "Trusted Root"
        )

        result["reason"] = (
            "A cryptographically valid chain does "
            "not automatically imply trust."
        )

        return result

    checks.append(
        make_check(
            "Trusted Root",
            True,
            (
                "The Root CA exists in the application's "
                "local trusted-root store."
            ),
            str(trusted_root),
        )
    )

    # =====================================================
    # 13. CRL AVAILABILITY
    # =====================================================

    if not crl_path.exists():
        checks.append(
            make_check(
                "CRL Check",
                True,
                (
                    "No CRL has been published yet, so "
                    "there are currently no locally "
                    "recorded revocations."
                ),
                "No CRL file present",
            )
        )

        result["trusted"] = True

        result["final_result"] = (
            "TRUSTED"
        )

        result["reason"] = (
            "The certificate has a valid signature chain, "
            "terminates at a trusted Root CA, and no local "
            "revocation list has been published."
        )

        return result

    try:
        crl = load_crl(
            crl_path
        )

    except (OSError, ValueError) as exc:
        checks.append(
            make_check(
                "CRL Parsing",
                False,
                (
                    "The published CRL "
                    "could not be parsed."
                ),
            )
        )

        result["final_result"] = (
            "INVALID_CERTIFICATE"
        )

        result["failed_check"] = (
            "CRL Parsing"
        )

        result["reason"] = str(exc)

        return result

    # =====================================================
    # 14. CRL ISSUER
    # =====================================================

    if crl.issuer != intermediate.subject:
        checks.append(
            make_check(
                "CRL Issuer",
                False,
                (
                    "The CRL issuer does not match "
                    "the Intermediate CA."
                ),
            )
        )

        result["final_result"] = (
            "INVALID_CERTIFICATE"
        )

        result["failed_check"] = (
            "CRL Issuer"
        )

        result["reason"] = (
            "The CRL was not issued by the "
            "expected Intermediate CA."
        )

        return result

    checks.append(
        make_check(
            "CRL Issuer",
            True,
            (
                "The CRL identifies the Intermediate "
                "CA as its issuer."
            ),
            crl.issuer.rfc4514_string(),
        )
    )

    # =====================================================
    # 15. CRL SIGNING PERMISSION
    # =====================================================

    try:
        check_crl_permission(
            intermediate
        )

        checks.append(
            make_check(
                "CRL Signing Permission",
                True,
                (
                    "The Intermediate CA Key Usage "
                    "permits CRL signing."
                ),
                "cRLSign=TRUE",
            )
        )

    except (
        x509.ExtensionNotFound,
        ValueError,
    ) as exc:
        checks.append(
            make_check(
                "CRL Signing Permission",
                False,
                str(exc),
            )
        )

        result["final_result"] = (
            "INVALID_CERTIFICATE"
        )

        result["failed_check"] = (
            "CRL Signing Permission"
        )

        result["reason"] = str(exc)

        return result

    # =====================================================
    # 16. CRL SIGNATURE
    # =====================================================

    try:
        verify_crl_signature(
            crl,
            intermediate,
        )

        checks.append(
            make_check(
                "CRL Signature",
                True,
                (
                    "The CRL signature was successfully "
                    "verified using the Intermediate CA "
                    "public key."
                ),
                (
                    crl
                    .signature_algorithm_oid
                    .dotted_string
                ),
            )
        )

    except InvalidSignature:
        checks.append(
            make_check(
                "CRL Signature",
                False,
                "The CRL signature is invalid.",
            )
        )

        result["final_result"] = (
            "INVALID_SIGNATURE"
        )

        result["failed_check"] = (
            "CRL Signature"
        )

        result["reason"] = (
            "Cryptographic verification of "
            "the CRL signature failed."
        )

        return result

    except Exception as exc:
        checks.append(
            make_check(
                "CRL Signature",
                False,
                (
                    "The CRL signature "
                    "could not be verified."
                ),
            )
        )

        result["final_result"] = (
            "INVALID_SIGNATURE"
        )

        result["failed_check"] = (
            "CRL Signature"
        )

        result["reason"] = str(exc)

        return result

    # =====================================================
    # 17. CRL VALIDITY WINDOW
    # =====================================================

    last_update = crl_time(
        crl,
        "last_update",
    )

    next_update = crl_time(
        crl,
        "next_update",
    )

    if (
        now < last_update
        or now > next_update
    ):
        checks.append(
            make_check(
                "CRL Validity",
                False,
                (
                    "The CRL is outside its "
                    "valid update window."
                ),
                (
                    f"{last_update.isoformat()} "
                    f"to {next_update.isoformat()}"
                ),
            )
        )

        result["final_result"] = (
            "INVALID_CERTIFICATE"
        )

        result["failed_check"] = (
            "CRL Validity"
        )

        result["reason"] = (
            "The CRL is not currently valid."
        )

        return result

    checks.append(
        make_check(
            "CRL Validity",
            True,
            (
                "The signed CRL is currently "
                "within its update window."
            ),
            (
                f"{last_update.isoformat()} "
                f"to {next_update.isoformat()}"
            ),
        )
    )

    # =====================================================
    # 18. REVOCATION STATUS
    # =====================================================

    revoked_entry = (
        crl.get_revoked_certificate_by_serial_number(
            certificate.serial_number
        )
    )

    if revoked_entry is not None:
        checks.append(
            make_check(
                "Revocation Status",
                False,
                (
                    "The certificate serial number "
                    "was found in the signed CRL."
                ),
                (
                    f"Serial: "
                    f"{format(certificate.serial_number, 'X')}"
                ),
            )
        )

        result["trusted"] = False

        result["final_result"] = (
            "REVOKED"
        )

        result["failed_check"] = (
            "Revocation Status"
        )

        result["reason"] = (
            "The certificate remains cryptographically valid, "
            "but it has been revoked by its issuing CA."
        )

        return result

    checks.append(
        make_check(
            "Revocation Status",
            True,
            (
                "The certificate serial number is "
                "not present in the signed CRL."
            ),
            (
                f"Serial: "
                f"{format(certificate.serial_number, 'X')}"
            ),
        )
    )

    # =====================================================
    # FINAL DECISION
    # =====================================================

    result["trusted"] = True

    result["final_result"] = (
        "TRUSTED"
    )

    result["reason"] = (
        "The certificate has a valid signature chain, "
        "terminates at a trusted Root CA, and is not revoked."
    )

    return result