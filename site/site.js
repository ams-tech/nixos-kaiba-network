(() => {
  "use strict";

  const reportLink = document.querySelector("#report-link");
  const signal = document.querySelector("#report-signal");
  const signalText = document.querySelector("#report-signal-text");
  const status = document.querySelector("#report-status");
  const summary = document.querySelector("#report-summary");
  const assertionCount = document.querySelector("#report-assertions");

  if (!reportLink || !signal || !signalText || !status || !summary || !assertionCount) {
    return;
  }

  const setState = (state, total = 0, passed = 0, suite = "") => {
    signal.classList.remove("is-passed", "is-failed", "is-unavailable");
    status.classList.remove("is-passed", "is-failed", "is-unavailable");
    signal.classList.add(`is-${state}`);
    status.classList.add(`is-${state}`);

    if (state === "passed") {
      signalText.textContent = "Latest report passed";
      status.textContent = "PASSED";
      assertionCount.textContent = `${passed} / ${total}`;
      summary.textContent = `${passed} of ${total} assertions passed in ${suite}. Open the report to inspect every claim and its evidence.`;
      return;
    }

    if (state === "failed") {
      signalText.textContent = "Latest report has failures";
      status.textContent = "FAILED";
      assertionCount.textContent = `${passed} / ${total}`;
      summary.textContent = `${passed} of ${total} assertions passed in ${suite}. The diagnostic report remains available with failure details and evidence.`;
      return;
    }

    signalText.textContent = "Report status unavailable";
    status.textContent = "STATUS UNAVAILABLE";
    assertionCount.textContent = "—";
    summary.textContent = "The structured status could not be loaded. The direct report link remains available.";
  };

  const resultUrl = new URL("result.json", reportLink.href);

  fetch(resultUrl, { cache: "no-store" })
    .then((response) => {
      if (!response.ok) {
        throw new Error("report result is unavailable");
      }
      return response.json();
    })
    .then((report) => {
      if (
        !report ||
        typeof report.suite !== "string" ||
        !["passed", "failed"].includes(report.overall) ||
        !Array.isArray(report.assertions) ||
        report.assertions.length === 0
      ) {
        throw new Error("report result is malformed");
      }

      const invalidAssertion = report.assertions.some(
        (assertion) => !assertion || !["passed", "failed"].includes(assertion.status),
      );
      if (invalidAssertion) {
        throw new Error("report assertions are malformed");
      }

      const passed = report.assertions.filter((assertion) => assertion.status === "passed").length;
      const expectedOverall = passed === report.assertions.length ? "passed" : "failed";
      if (report.overall !== expectedOverall) {
        throw new Error("report status is inconsistent");
      }

      const suiteName = report.suite === "kaiba-dns-pilot" ? "the Kaiba DNS pilot" : report.suite;
      setState(report.overall, report.assertions.length, passed, suiteName);
    })
    .catch(() => setState("unavailable"));
})();
