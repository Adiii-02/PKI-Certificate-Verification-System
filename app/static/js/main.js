"use strict";

document.addEventListener("DOMContentLoaded", function () {
    const certificateType =
        document.getElementById("certificate_type");

    const dnsField =
        document.getElementById("dnsField");

    const dnsInput =
        document.getElementById("dns_name");

    if (!certificateType || !dnsField || !dnsInput) {
        return;
    }

    function updateCertificateForm() {
        const isServer =
            certificateType.value === "SERVER";

        dnsField.style.display =
            isServer ? "block" : "none";

        dnsInput.required =
            isServer;

        if (!isServer) {
            dnsInput.value = "";
        }
    }

    certificateType.addEventListener(
        "change",
        updateCertificateForm
    );

    updateCertificateForm();
});