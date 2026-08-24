(() => {
  "use strict";

  const reportLink = document.querySelector("#report-link");
  const signal = document.querySelector("#report-signal");
  const signalText = document.querySelector("#report-signal-text");
  const dnsStatus = document.querySelector("#report-status");
  const dnsSummary = document.querySelector("#report-summary");
  const assertionCount = document.querySelector("#report-assertions");
  const automatedStatus = document.querySelector("#provisioning-automated-status");
  const hardwareStatus = document.querySelector("#provisioning-hardware-status");
  const provisioningSummary = document.querySelector("#provisioning-summary");

  if (
    !reportLink ||
    !signal ||
    !signalText ||
    !dnsStatus ||
    !dnsSummary ||
    !assertionCount ||
    !automatedStatus ||
    !hardwareStatus ||
    !provisioningSummary
  ) {
    return;
  }

  const replaceState = (element, state, states) => {
    for (const item of states) {
      element.classList.remove(`is-${item}`);
    }
    element.classList.add(`is-${state}`);
  };

  const setDnsState = (state, total = 0, passed = 0) => {
    replaceState(signal, state, ["passed", "failed", "unavailable"]);
    replaceState(dnsStatus, state, ["passed", "failed", "unavailable"]);

    if (state === "passed") {
      signalText.textContent = "Latest DNS report passed";
      dnsStatus.textContent = "PASSED";
      assertionCount.textContent = `${passed} / ${total}`;
      dnsSummary.textContent = `${passed} of ${total} assertions passed in the Kaiba DNS pilot. Open the report to inspect every claim and its evidence.`;
      return;
    }

    if (state === "failed") {
      signalText.textContent = "Latest DNS report has failures";
      dnsStatus.textContent = "FAILED";
      assertionCount.textContent = `${passed} / ${total}`;
      dnsSummary.textContent = `${passed} of ${total} assertions passed in the Kaiba DNS pilot. The diagnostic report remains available with failure details and evidence.`;
      return;
    }

    signalText.textContent = "DNS report status unavailable";
    dnsStatus.textContent = "STATUS UNAVAILABLE";
    assertionCount.textContent = "—";
    dnsSummary.textContent = "The DNS result could not be loaded. The direct report link remains available.";
  };

  const validProvisioningReport = (report) => {
    const validEvidence = (value) =>
      Array.isArray(value) &&
      new Set(value).size === value.length &&
      value.every(
        (path) =>
          typeof path === "string" &&
          /^evidence\/[A-Za-z0-9._/-]+$/.test(path) &&
          !path.split("/").some((part) => !part || part === "." || part === ".."),
      );
    if (
      !report ||
      report.schema_version !== 1 ||
      report.suite !== "kaiba-rpi5-provisioning-probe" ||
      report.mutation_eligible !== false ||
      !report.automated ||
      !["passed", "failed", "partial"].includes(report.automated.overall) ||
      !Array.isArray(report.automated.checks) ||
      report.automated.checks.length === 0 ||
      !report.hardware_qualification ||
      !["pending", "passed", "failed"].includes(report.hardware_qualification.status) ||
      typeof report.hardware_qualification.description !== "string" ||
      report.hardware_qualification.description.length === 0 ||
      !validEvidence(report.hardware_qualification.evidence)
    ) {
      return false;
    }

    const checkKeys = new Set();
    for (const check of report.automated.checks) {
      if (
        !check ||
        typeof check.id !== "string" ||
        check.id.length === 0 ||
        typeof check.system !== "string" ||
        !["x86_64-linux", "aarch64-linux"].includes(check.system) ||
        checkKeys.has(`${check.system}\u0000${check.id}`) ||
        typeof check.description !== "string" ||
        check.description.length === 0 ||
        !["passed", "failed", "not-observed"].includes(check.status) ||
        !validEvidence(check.evidence) ||
        (check.source_revision !== undefined &&
          !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(check.source_revision)) ||
        (check.status === "not-observed" &&
          (check.evidence.length !== 0 || check.source_revision !== undefined))
      ) {
        return false;
      }
      checkKeys.add(`${check.system}\u0000${check.id}`);
    }

    const statuses = report.automated.checks.map((check) => check.status);
    const hardware = report.hardware_qualification;
    if (
      (hardware.status === "pending" && hardware.evidence.length !== 0) ||
      (hardware.status !== "pending" && hardware.evidence.length === 0)
    ) {
      return false;
    }
    const expectedOverall = statuses.includes("failed")
      ? "failed"
      : statuses.includes("not-observed")
        ? "partial"
        : "passed";
    return report.automated.overall === expectedOverall;
  };

  const setProvisioningState = (report) => {
    const checks = report.automated.checks;
    const passed = checks.filter((check) => check.status === "passed").length;
    const total = checks.length;
    const automated = report.automated.overall;
    const hardware = report.hardware_qualification.status;

    replaceState(automatedStatus, automated, ["passed", "failed", "partial", "unavailable"]);
    replaceState(hardwareStatus, hardware, ["passed", "failed", "pending", "unavailable"]);
    automatedStatus.textContent = `${automated.toUpperCase()} (${passed} / ${total})`;
    hardwareStatus.textContent = `${hardware.toUpperCase()} — MANUAL`;

    const automatedText =
      automated === "passed"
        ? `Automated probe verification passed all ${total} checks.`
        : automated === "failed"
          ? `Automated probe verification has failures; ${passed} of ${total} checks passed.`
          : `Automated probe verification is partial; ${passed} of ${total} checks passed.`;
    const hardwareText =
      hardware === "pending"
        ? "Physical Pi 5 qualification is pending for this report and is not run in CI; mutation remains disabled."
        : hardware === "passed"
          ? "The separate manual physical Pi 5 qualification passed; the profile is stable for read-only classification, not mutation."
          : "The separate manual physical Pi 5 qualification failed.";
    provisioningSummary.textContent = `${automatedText} ${hardwareText}`;
  };

  const setProvisioningUnavailable = () => {
    replaceState(automatedStatus, "unavailable", ["passed", "failed", "partial", "unavailable"]);
    replaceState(hardwareStatus, "unavailable", ["passed", "failed", "pending", "unavailable"]);
    automatedStatus.textContent = "STATUS UNAVAILABLE";
    hardwareStatus.textContent = "STATUS UNAVAILABLE";
    provisioningSummary.textContent =
      "The provisioning result could not be loaded. No automated or hardware qualification status is implied.";
  };

  const fetchJson = (url, unavailableMessage) =>
    fetch(url, { cache: "no-store" }).then((response) => {
      if (!response.ok) {
        throw new Error(unavailableMessage);
      }
      return response.json();
    });

  fetchJson(new URL("result.json", reportLink.href), "DNS result is unavailable")
    .then((report) => {
      if (
        !report ||
        report.suite !== "kaiba-dns-pilot" ||
        !["passed", "failed"].includes(report.overall) ||
        !Array.isArray(report.assertions) ||
        report.assertions.length === 0
      ) {
        throw new Error("DNS result is malformed");
      }

      const invalidAssertion = report.assertions.some(
        (assertion) => !assertion || !["passed", "failed"].includes(assertion.status),
      );
      if (invalidAssertion) {
        throw new Error("DNS assertions are malformed");
      }

      const passed = report.assertions.filter((assertion) => assertion.status === "passed").length;
      const expectedOverall = passed === report.assertions.length ? "passed" : "failed";
      if (report.overall !== expectedOverall) {
        throw new Error("DNS status is inconsistent");
      }
      setDnsState(report.overall, report.assertions.length, passed);
    })
    .catch(() => setDnsState("unavailable"));

  fetchJson(new URL("provisioning.json", reportLink.href), "provisioning result is unavailable")
    .then((report) => {
      if (!validProvisioningReport(report)) {
        throw new Error("provisioning result is malformed");
      }
      setProvisioningState(report);
    })
    .catch(setProvisioningUnavailable);
})();
