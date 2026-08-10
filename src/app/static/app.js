"use strict";

const state = {
  data: null,
  lastDecision: null,
};

const byId = (id) => document.getElementById(id);

function createElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function replaceChildren(target, children) {
  target.replaceChildren(...children);
}

function renderMetrics(metrics) {
  const cards = metrics.map((metric) => {
    const card = createElement("article", `metric-card tone-${metric.tone}`);
    card.append(
      createElement("span", "", metric.label),
      createElement("strong", "", String(metric.value)),
      createElement("small", "", metric.detail),
    );
    return card;
  });
  replaceChildren(byId("metric-grid"), cards);
}

function renderArchitecture(items) {
  const nodes = items.map((item) => {
    const node = document.createElement("li");
    node.append(
      createElement("span", "", item.step),
      createElement("strong", "", item.title),
      createElement("small", "", item.detail),
    );
    return node;
  });
  replaceChildren(byId("architecture-flow"), nodes);
}

function renderControls(controls) {
  const cards = controls.map((control) => {
    const card = createElement("article", "control-card");
    card.append(
      createElement("span", "", control.index),
      createElement("h3", "", control.title),
      createElement("p", "", control.description),
      createElement("small", "", control.tag),
    );
    return card;
  });
  replaceChildren(byId("control-grid"), cards);
}

function renderEvidence(events) {
  const rows = events.map((event) => {
    const row = createElement("div", "event-row");
    row.append(
      createElement("span", `event-state ${event.tone}`, event.state),
      createElement("code", "", event.requestId),
      createElement("strong", "", event.summary),
      createElement("small", "", event.result),
    );
    return row;
  });
  replaceChildren(byId("evidence-list"), rows);
}

function renderRoadmap(items) {
  const rows = items.map((item) => {
    const row = createElement("li", item.current ? "is-current" : "");
    const copy = document.createElement("div");
    copy.append(
      createElement("strong", "", item.title),
      createElement("small", "", item.detail),
    );
    row.append(createElement("span", "", item.week), copy);
    return row;
  });
  replaceChildren(byId("roadmap-list"), rows);
}

function populateEndpoints() {
  const select = byId("endpoint-select");
  const options = state.data.endpoints.map((endpoint) => {
    const option = document.createElement("option");
    option.value = endpoint.id;
    option.textContent = `${endpoint.method} ${endpoint.path} — ${endpoint.label}`;
    return option;
  });
  replaceChildren(select, options);
  select.value = "input-validation";
  populateTestCases();
}

function currentEndpoint() {
  return state.data.endpoints.find((item) => item.id === byId("endpoint-select").value);
}

function currentTestCase() {
  return state.data.testCases.find((item) => item.id === byId("test-case-select").value);
}

function populateTestCases() {
  const endpoint = currentEndpoint();
  const select = byId("test-case-select");
  const available = state.data.testCases.filter((item) => endpoint.allowedTestCases.includes(item.id));
  const options = available.map((testCase) => {
    const option = document.createElement("option");
    option.value = testCase.id;
    option.textContent = `${testCase.label} · expected ${testCase.expectedStatus}`;
    return option;
  });
  replaceChildren(select, options);
  select.value = available.some((item) => item.id === "special-characters") ? "special-characters" : available[0].id;
  updateTestCaseHelp();
}

function updateTestCaseHelp() {
  const testCase = currentTestCase();
  byId("test-case-help").textContent = testCase
    ? testCase.description
    : "Payload được materialize từ catalog, không nhập trực tiếp.";
}

function materializeValue(testCase) {
  if (testCase.kind === "repeated-string") return testCase.character.repeat(testCase.length);
  return testCase.value;
}

function boundedPreview(value, limit = 96) {
  const serialized = typeof value === "string" ? value : JSON.stringify(value);
  if (serialized.length <= limit) return serialized;
  return `${serialized.slice(0, limit)}…[${serialized.length - limit} ký tự đã ẩn]`;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

async function proposalId(proposal) {
  const canonical = new TextEncoder().encode(canonicalJson(proposal));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", canonical);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);
}

function containsOnlyPrintableAscii(value) {
  return [...value].every((character) => {
    const code = character.charCodeAt(0);
    return code >= 32 && code <= 126;
  });
}

function renderJson(targetId, value) {
  const target = byId(targetId);
  target.querySelector("code").textContent = JSON.stringify(value, null, 2);
}

function activateTab(targetId) {
  document.querySelectorAll(".code-tab").forEach((tab) => {
    const active = tab.dataset.panel === targetId;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll(".code-output").forEach((panel) => {
    const active = panel.id === targetId;
    panel.classList.toggle("is-active", active);
    panel.hidden = !active;
  });
}

function buildRequestedHeaders() {
  const headers = {};
  const language = byId("language-select").value;
  const purpose = byId("purpose-input").value.trim();
  if (language) headers["accept-language"] = language;
  if (purpose) headers["x-test-purpose"] = purpose;
  return headers;
}

async function runDryRun(event) {
  event.preventDefault();
  const endpoint = currentEndpoint();
  const testCase = currentTestCase();
  const rationale = byId("rationale-input").value.trim();
  const finding = byId("finding-input").value.trim();
  const requestedHeaders = buildRequestedHeaders();
  const headerValuesAllowed = Object.values(requestedHeaders).every(containsOnlyPrintableAscii);
  const allowed = Boolean(
    endpoint &&
    testCase &&
    endpoint.allowedTestCases.includes(testCase.id) &&
    rationale.length > 0 &&
    Object.keys(requestedHeaders).every((name) => ["accept-language", "x-test-purpose"].includes(name)) &&
    headerValuesAllowed
  );

  const proposal = {
    endpoint_id: endpoint ? endpoint.id : "unknown",
    test_case_id: testCase ? testCase.id : "unknown",
    rationale,
    source_finding_ids: finding ? [finding] : [],
    requested_headers: requestedHeaders,
  };

  const value = testCase ? materializeValue(testCase) : null;
  const materialized = allowed ? {
    origin: state.data.project.gatewayOrigin,
    method: endpoint.method,
    path: endpoint.path,
    headers: requestedHeaders,
    body: endpoint.method === "POST" ? { value_preview: boundedPreview(value), value_type: typeof value } : null,
    follow_redirects: false,
    network_call: false,
  } : null;

  const receipt = {
    schema_version: "1.0",
    proposal_id: await proposalId(proposal),
    policy_sha256: state.data.project.policySha256,
    decision: allowed ? "allow" : "deny",
    reason: allowed ? "policy_allowed" : (headerValuesAllowed ? "proposal_invalid" : "header_value_not_printable_ascii"),
    expected_status: testCase ? testCase.expectedStatus : null,
    requested_header_names: Object.keys(requestedHeaders),
    sensitive_header_values_logged: false,
    response_excerpt: null,
    dry_run: true,
  };

  renderJson("proposal-output", proposal);
  renderJson("request-output", materialized || { network_call: false, reason: "policy_denied" });
  renderJson("receipt-output", receipt);

  const badge = byId("decision-badge");
  badge.textContent = allowed ? "ALLOW" : "DENY";
  badge.className = `decision-badge ${allowed ? "is-allow" : "is-deny"}`;

  const summary = byId("decision-summary");
  const icon = createElement("span", "decision-icon", allowed ? "✓" : "×");
  icon.setAttribute("aria-hidden", "true");
  const copy = document.createElement("div");
  copy.append(
    createElement("strong", "", allowed ? "Proposal hợp lệ với policy" : "Proposal bị từ chối trước transport"),
    createElement("p", "", allowed
      ? `${endpoint.method} ${endpoint.path} · expected ${testCase.expectedStatus} · không có network call`
      : "Không request nào được materialize hoặc gửi đi."),
  );
  replaceChildren(summary, [icon, copy]);
  state.lastDecision = receipt;
  activateTab("proposal-output");
}

function resetSimulator() {
  window.setTimeout(() => {
    byId("endpoint-select").value = "input-validation";
    populateTestCases();
    byId("decision-badge").textContent = "READY";
    byId("decision-badge").className = "decision-badge is-idle";
    const summary = byId("decision-summary");
    const icon = createElement("span", "decision-icon", "◇");
    icon.setAttribute("aria-hidden", "true");
    const copy = document.createElement("div");
    copy.append(
      createElement("strong", "", "Chờ proposal"),
      createElement("p", "", "Chọn capability và safe test case để xem request đã materialize."),
    );
    replaceChildren(summary, [icon, copy]);
    renderJson("proposal-output", { state: "waiting_for_input" });
    renderJson("request-output", { network_call: false });
    renderJson("receipt-output", { audit: "sanitized_metadata_only" });
    state.lastDecision = null;
    activateTab("proposal-output");
  }, 0);
}

async function checkHealth() {
  const button = byId("health-button");
  const status = byId("health-status");
  button.disabled = true;
  button.classList.remove("is-ok", "is-error", "is-static");
  status.textContent = "Đang kiểm tra endpoint public cùng origin…";

  if (!isFullStackUiPath()) {
    button.classList.add("is-static");
    status.textContent = "Kênh static showcase; full stack được xác minh riêng trong CI.";
    button.disabled = false;
    return;
  }

  if (!['http:', 'https:'].includes(window.location.protocol)) {
    button.classList.add("is-error");
    status.textContent = "Health check chỉ khả dụng khi dashboard được phục vụ qua HTTP(S).";
    button.disabled = false;
    return;
  }

  try {
    const healthUrl = new URL("/health", window.location.origin);
    if (healthUrl.origin !== window.location.origin) throw new Error("off_origin");
    const response = await fetch(healthUrl, {
      method: "GET",
      credentials: "omit",
      redirect: "error",
      headers: { Accept: "application/json" },
    });
    const body = await response.json();
    if (!response.ok || body.status !== "ok") throw new Error("health_unavailable");
    button.classList.add("is-ok");
    status.textContent = "Public /health phản hồi OK; không gọi endpoint được bảo vệ.";
  } catch (_error) {
    button.classList.add("is-error");
    status.textContent = "Không kết nối được /health. Dashboard và dry-run vẫn hoạt động offline.";
  } finally {
    button.disabled = false;
  }
}

function configureHostingMode() {
  if (isFullStackUiPath()) return;
  const button = byId("health-button");
  button.classList.add("is-static");
  byId("health-label").textContent = "Static showcase";
  byId("health-status").textContent = "Dashboard tĩnh không chứa credential hoặc gọi protected API.";
}

function isFullStackUiPath() {
  return window.location.pathname === "/ui" || window.location.pathname.startsWith("/ui/");
}

function handleTabKeydown(event) {
  const supportedKeys = ["ArrowLeft", "ArrowRight", "Home", "End"];
  if (!supportedKeys.includes(event.key)) return;
  const tabs = [...document.querySelectorAll(".code-tab")];
  const currentIndex = tabs.indexOf(event.currentTarget);
  let nextIndex = currentIndex;
  if (event.key === "Home") nextIndex = 0;
  if (event.key === "End") nextIndex = tabs.length - 1;
  if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
  if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % tabs.length;
  event.preventDefault();
  tabs[nextIndex].focus();
  activateTab(tabs[nextIndex].dataset.panel);
}

function wireInteractions() {
  byId("endpoint-select").addEventListener("change", populateTestCases);
  byId("test-case-select").addEventListener("change", updateTestCaseHelp);
  byId("proposal-form").addEventListener("submit", runDryRun);
  byId("reset-button").addEventListener("click", resetSimulator);
  byId("health-button").addEventListener("click", checkHealth);
  document.querySelectorAll(".code-tab").forEach((tab) => {
    tab.addEventListener("click", () => activateTab(tab.dataset.panel));
    tab.addEventListener("keydown", handleTabKeydown);
  });
}

async function initialize() {
  try {
    const response = await fetch("./dashboard-data.json", { cache: "no-store", credentials: "same-origin" });
    if (!response.ok) throw new Error(`dashboard_data_${response.status}`);
    state.data = await response.json();
    renderMetrics(state.data.metrics);
    renderArchitecture(state.data.architecture);
    renderControls(state.data.controls);
    renderEvidence(state.data.evidence);
    renderRoadmap(state.data.roadmap);
    populateEndpoints();
    wireInteractions();
    configureHostingMode();
  } catch (_error) {
    byId("decision-summary").querySelector("strong").textContent = "Không tải được dữ liệu curated";
    byId("decision-summary").querySelector("p").textContent = "Hãy phục vụ thư mục static qua HTTP để dùng simulator. Nội dung tổng quan vẫn hiển thị.";
    byId("decision-badge").textContent = "OFFLINE";
    byId("decision-badge").className = "decision-badge is-deny";
    byId("proposal-form").querySelectorAll("input, select, textarea, button").forEach((control) => { control.disabled = true; });
    byId("health-button").addEventListener("click", checkHealth);
    configureHostingMode();
  }
}

initialize();
