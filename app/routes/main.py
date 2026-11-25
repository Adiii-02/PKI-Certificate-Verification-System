from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from app.crypto.ca import (
    INTERMEDIATE_CERT_PATH,
    ROOT_CERT_PATH,
)

from app.services.ca_service import (
    create_intermediate_ca,
    create_root_ca,
    get_all_cas,
    get_ca_by_type,
    inspect_certificate,
)

from app.services.certificate_service import (
    get_all_certificates,
    get_certificate_by_id,
    get_certificate_details,
    issue_certificate as issue_certificate_service,
)

from app.services.dashboard_service import (
    get_dashboard_data,
)

from app.services.revocation_service import (
    current_crl_details,
    get_revocations,
    revoke_certificate as revoke_certificate_service,
)

from app.services.security_lab_service import (
    generate_lab,
    get_scenarios,
    run_scenario,
)

from app.services.verification_service import (
    verify_issued_certificate,
)


main_bp = Blueprint(
    "main",
    __name__,
)


# =========================================================
# DASHBOARD
# =========================================================

@main_bp.route("/")
def dashboard():
    dashboard_data = get_dashboard_data()

    root = get_ca_by_type(
        "ROOT"
    )

    intermediate = get_ca_by_type(
        "INTERMEDIATE"
    )

    return render_template(
        "dashboard.html",
        page_title="Dashboard",
        data=dashboard_data,
        root=root,
        intermediate=intermediate,
    )


# =========================================================
# CERTIFICATE AUTHORITIES
# =========================================================

@main_bp.route("/certificate-authorities")
def certificate_authorities():
    cas = get_all_cas()

    root = get_ca_by_type(
        "ROOT"
    )

    intermediate = get_ca_by_type(
        "INTERMEDIATE"
    )

    root_details = None
    intermediate_details = None

    if root and ROOT_CERT_PATH.exists():
        root_details = inspect_certificate(
            ROOT_CERT_PATH
        )

    if (
        intermediate
        and INTERMEDIATE_CERT_PATH.exists()
    ):
        intermediate_details = inspect_certificate(
            INTERMEDIATE_CERT_PATH
        )

    return render_template(
        "ca/index.html",
        page_title="Certificate Authorities",
        cas=cas,
        root=root,
        intermediate=intermediate,
        root_details=root_details,
        intermediate_details=intermediate_details,
    )


@main_bp.route(
    "/certificate-authorities/create-root",
    methods=["POST"],
)
def create_root():
    try:
        create_root_ca()

        flash(
            "Root CA created successfully and added "
            "to the local trusted-root store.",
            "success",
        )

    except FileExistsError as exc:
        flash(
            str(exc),
            "warning",
        )

    except Exception as exc:
        flash(
            f"Unable to create Root CA: {exc}",
            "danger",
        )

    return redirect(
        url_for(
            "main.certificate_authorities"
        )
    )


@main_bp.route(
    "/certificate-authorities/create-intermediate",
    methods=["POST"],
)
def create_intermediate():
    try:
        create_intermediate_ca()

        flash(
            "Intermediate CA created successfully "
            "and signed by the Root CA.",
            "success",
        )

    except (
        FileExistsError,
        FileNotFoundError,
        RuntimeError,
    ) as exc:
        flash(
            str(exc),
            "warning",
        )

    except Exception as exc:
        flash(
            f"Unable to create Intermediate CA: {exc}",
            "danger",
        )

    return redirect(
        url_for(
            "main.certificate_authorities"
        )
    )


# =========================================================
# CERTIFICATE ISSUANCE
# =========================================================

@main_bp.route(
    "/issue",
    methods=["GET", "POST"],
)
def issue_certificate():
    intermediate = get_ca_by_type(
        "INTERMEDIATE"
    )

    if request.method == "POST":
        common_name = request.form.get(
            "common_name",
            "",
        ).strip()

        certificate_type = request.form.get(
            "certificate_type",
            "",
        ).strip().upper()

        dns_name = request.form.get(
            "dns_name",
            "",
        ).strip()

        try:
            certificate_id = (
                issue_certificate_service(
                    common_name=common_name,
                    certificate_type=certificate_type,
                    dns_name=dns_name,
                )
            )

            flash(
                "Certificate issued successfully.",
                "success",
            )

            return redirect(
                url_for(
                    "main.certificate_details",
                    certificate_id=certificate_id,
                )
            )

        except (
            ValueError,
            RuntimeError,
            FileNotFoundError,
        ) as exc:
            flash(
                str(exc),
                "warning",
            )

        except Exception as exc:
            flash(
                f"Certificate issuance failed: {exc}",
                "danger",
            )

    certificates = get_all_certificates()

    return render_template(
        "certificates/issue.html",
        page_title="Issue Certificate",
        intermediate=intermediate,
        certificates=certificates,
    )


# =========================================================
# CERTIFICATE DETAILS
# =========================================================

@main_bp.route(
    "/certificates/<int:certificate_id>",
)
def certificate_details(
    certificate_id,
):
    certificate_record = (
        get_certificate_by_id(
            certificate_id
        )
    )

    if certificate_record is None:
        abort(404)

    try:
        details = get_certificate_details(
            certificate_record
        )

    except (
        OSError,
        ValueError,
    ):
        abort(500)

    return render_template(
        "certificates/details.html",
        page_title="Certificate Details",
        certificate=certificate_record,
        details=details,
    )


# =========================================================
# CERTIFICATE VERIFICATION
# =========================================================

@main_bp.route("/verify")
def verify_certificate():
    certificates = get_all_certificates()

    return render_template(
        "verification/index.html",
        page_title="Verify Certificate",
        certificates=certificates,
        result=None,
        certificate=None,
    )


@main_bp.route(
    "/verify/<int:certificate_id>",
    methods=["POST"],
)
def run_verification(
    certificate_id,
):
    try:
        certificate, result = (
            verify_issued_certificate(
                certificate_id
            )
        )

    except ValueError as exc:
        flash(
            str(exc),
            "warning",
        )

        return redirect(
            url_for(
                "main.verify_certificate"
            )
        )

    except Exception as exc:
        flash(
            f"Verification failed: {exc}",
            "danger",
        )

        return redirect(
            url_for(
                "main.verify_certificate"
            )
        )

    certificates = get_all_certificates()

    return render_template(
        "verification/index.html",
        page_title="Verify Certificate",
        certificates=certificates,
        result=result,
        certificate=certificate,
    )


# =========================================================
# CERTIFICATE REVOCATION
# =========================================================

@main_bp.route("/revoke")
def revoke_certificate():
    certificates = get_all_certificates()

    revocations = get_revocations()

    crl_details = current_crl_details()

    return render_template(
        "revocation/index.html",
        page_title="Revoke Certificate",
        certificates=certificates,
        revocations=revocations,
        crl_details=crl_details,
    )


@main_bp.route(
    "/revoke/<int:certificate_id>",
    methods=["POST"],
)
def run_revocation(
    certificate_id,
):
    reason = request.form.get(
        "reason",
        "UNSPECIFIED",
    )

    try:
        certificate = (
            revoke_certificate_service(
                certificate_id,
                reason,
            )
        )

        flash(
            (
                f"Certificate "
                f"'{certificate['common_name']}' "
                "was revoked and the signed CRL "
                "was updated."
            ),
            "success",
        )

    except ValueError as exc:
        flash(
            str(exc),
            "warning",
        )

    except Exception as exc:
        flash(
            f"Revocation failed: {exc}",
            "danger",
        )

    return redirect(
        url_for(
            "main.revoke_certificate"
        )
    )


# =========================================================
# SECURITY TEST LAB
# =========================================================

@main_bp.route("/security-lab")
def security_lab():
    scenarios = get_scenarios()

    return render_template(
        "security_lab/index.html",
        page_title="Security Test Lab",
        scenarios=scenarios,
        selected_scenario=None,
        result=None,
        display_result=None,
    )


@main_bp.route(
    "/security-lab/generate",
    methods=["POST"],
)
def generate_security_lab():
    try:
        generate_lab()

        flash(
            "Security Test Lab certificates "
            "generated successfully.",
            "success",
        )

    except Exception as exc:
        flash(
            (
                "Unable to generate "
                f"Security Lab: {exc}"
            ),
            "danger",
        )

    return redirect(
        url_for(
            "main.security_lab"
        )
    )


@main_bp.route(
    "/security-lab/run/<scenario_id>",
    methods=["POST"],
)
def run_security_scenario(
    scenario_id,
):
    try:
        (
            selected_scenario,
            result,
            display_result,
        ) = run_scenario(
            scenario_id
        )

    except (
        ValueError,
        FileNotFoundError,
    ) as exc:
        flash(
            str(exc),
            "warning",
        )

        return redirect(
            url_for(
                "main.security_lab"
            )
        )

    except Exception as exc:
        flash(
            (
                "Security Lab verification "
                f"failed: {exc}"
            ),
            "danger",
        )

        return redirect(
            url_for(
                "main.security_lab"
            )
        )

    return render_template(
        "security_lab/index.html",
        page_title="Security Test Lab",
        scenarios=get_scenarios(),
        selected_scenario=selected_scenario,
        result=result,
        display_result=display_result,
    )