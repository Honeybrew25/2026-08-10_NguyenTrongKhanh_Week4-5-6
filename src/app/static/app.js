"use strict";

const state = {
  data: null,
  lastDecision: null,
  runtime: {},
  selectedRuntimeLayer: "policy",
  selectedE2eScenario: "reject",
  selectedE2eStage: "approval",
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

const RUNTIME_LAYER_TITLES = {
  gateway: "Gateway",
  policy: "Policy",
  evidence: "Evidence",
};

const E2E_STATE_LABELS = {
  success: "SUCCESS",
  approved: "APPROVED",
  rejected: "REJECTED",
  blocked: "BLOCKED",
  quarantined: "QUARANTINED",
  not_required: "NOT REQUIRED",
  skipped: "SKIPPED",
};

function refreshOverallRuntimeState() {
  const values = Object.values(state.runtime);
  let status = "INITIALIZING";
  let tone = "snapshot";

  if (values.some((item) => ["failed", "unavailable"].includes(item.state))) {
    status = "DEGRADED";
    tone = "failed";
  } else if (state.runtime.policy?.state === "deny") {
    status = "CONTROLLED DENY";
    tone = "deny";
  } else if (state.runtime.evidence?.state === "dry-run") {
    status = state.runtime.policy?.state === "allow" ? "DRY-RUN ALLOW" : "DRY-RUN";
    tone = "dry-run";
  } else if (state.runtime.gateway?.state === "live") {
    status = "LIVE · VERIFIED";
    tone = "live";
  } else if (state.runtime.gateway?.state === "static") {
    status = "STATIC SNAPSHOT";
    tone = "static";
  } else if (state.runtime.policy?.state === "verified" && state.runtime.evidence?.state === "snapshot") {
    status = "VERIFIED SNAPSHOT";
    tone = "snapshot";
  }

  const overall = byId("runtime-overall-state");
  overall.textContent = status;
  overall.dataset.state = tone;
  byId("runtime-radar-summary").textContent = Object.entries(state.runtime)
    .map(([layer, item]) => `${RUNTIME_LAYER_TITLES[layer]}: ${item.label}, ${item.detail}.`)
    .join(" ");
}

function setRuntimeLayer(layer, runtimeState, label, detail) {
  state.runtime[layer] = { state: runtimeState, label, detail };

  const ring = byId(`radar-${layer}-layer`);
  ring.dataset.state = runtimeState;
  ring.setAttribute("aria-label", `${RUNTIME_LAYER_TITLES[layer]}: ${label}. ${detail}`);

  const signal = byId(`${layer}-signal`);
  signal.dataset.state = runtimeState;
  const hotspot = document.querySelector(`[data-runtime-layer="${layer}"]`);
  hotspot.dataset.state = runtimeState;
  byId(`${layer}-runtime-state`).textContent = label;
  byId(`${layer}-runtime-detail`).textContent = detail;
  refreshOverallRuntimeState();
  if (state.selectedRuntimeLayer === layer) renderRuntimeInspector(layer);
}

function renderRuntimeInspector(layer) {
  const runtime = state.runtime[layer];
  if (!runtime) return;
  const definition = state.data?.runtimeRadar?.[layer];
  const position = definition?.layer?.toUpperCase() || "RUNTIME";
  byId("runtime-inspector-layer").textContent = `${position} RING · ${RUNTIME_LAYER_TITLES[layer].toUpperCase()}`;
  const inspectorState = byId("runtime-inspector-state");
  inspectorState.textContent = runtime.label;
  inspectorState.dataset.state = runtime.state;
  byId("runtime-inspector-title").textContent = definition?.title || RUNTIME_LAYER_TITLES[layer];
  byId("runtime-inspector-description").textContent = definition?.description || "Runtime metadata không khả dụng.";
  byId("runtime-inspector-detail").textContent = runtime.detail;
}

function selectRuntimeLayer(layer) {
  if (!RUNTIME_LAYER_TITLES[layer]) return;
  state.selectedRuntimeLayer = layer;
  document.querySelectorAll(".radar-hotspot").forEach((button) => {
    const active = button.dataset.runtimeLayer === layer;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  renderRuntimeInspector(layer);
}

function restorePolicyAndEvidenceRadar() {
  const radar = state.data.runtimeRadar;
  const policy = radar.policy;
  const evidence = radar.evidence;
  setRuntimeLayer(
    "policy",
    policy.initialState,
    `VERIFIED · v${policy.version}`,
    `${policy.capabilityCount} capabilities · ${policy.testCaseCount} test cases · SHA ${policy.sha256.slice(0, 12)}…`,
  );
  setRuntimeLayer(
    "evidence",
    evidence.initialState,
    "VERIFIED SNAPSHOT",
    `${evidence.successCount} success · ${evidence.deniedCount} policy denied · ${evidence.verifiedAt}`,
  );
}

function initializeRuntimeRadar() {
  const gateway = state.data.runtimeRadar.gateway;
  const gatewayHost = new URL(gateway.origin).host;
  setRuntimeLayer("gateway", gateway.initialState, "UNCHECKED", `${gatewayHost}${gateway.healthPath}`);
  restorePolicyAndEvidenceRadar();
  selectRuntimeLayer("policy");
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

function e2eStateTone(value) {
  if (["success", "approved"].includes(value)) return "allow";
  if (["rejected", "blocked", "quarantined"].includes(value)) return "warn";
  return "muted";
}

function currentE2eScenario() {
  return state.data.e2eReplay.scenarios.find(
    (item) => item.id === state.selectedE2eScenario,
  );
}

function renderE2eEvaluation(evaluation) {
  byId("e2e-eval-cases").textContent = String(evaluation.cases);
  byId("e2e-eval-passed").textContent = String(evaluation.passed);
  byId("e2e-eval-tp").textContent = String(evaluation.tp);
  byId("e2e-eval-fp").textContent = String(evaluation.fp);
  byId("e2e-eval-fn").textContent = String(evaluation.fn);
  byId("e2e-eval-safety").textContent = `${evaluation.secretPiiLeakCount} / ${evaluation.policyBypassCount}`;
}

function renderE2eStageDetail(stageId) {
  const scenario = currentE2eScenario();
  const stage = scenario?.stages.find((item) => item.id === stageId);
  if (!stage) return;

  state.selectedE2eStage = stage.id;
  document.querySelectorAll("[data-e2e-stage]").forEach((button) => {
    const active = button.dataset.e2eStage === stage.id;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  });

  const stateLabel = E2E_STATE_LABELS[stage.state] || stage.state.toUpperCase();
  const badge = byId("e2e-stage-state");
  badge.textContent = stateLabel;
  badge.className = `event-state ${e2eStateTone(stage.state)}`;
  byId("e2e-stage-title").textContent = stage.title;
  byId("e2e-stage-description").textContent = stage.detail;
}

function renderE2eStages(replay, scenario) {
  const stages = replay.stageOrder.map((definition) => {
    const stage = scenario.stages.find((item) => item.id === definition.id);
    if (!stage) return null;

    const item = document.createElement("li");
    const button = createElement("button", "replay-stage");
    button.type = "button";
    button.dataset.state = stage.state;
    button.dataset.e2eStage = stage.id;
    button.setAttribute("aria-pressed", "false");
    button.setAttribute("aria-controls", "e2e-stage-detail");
    button.append(
      createElement("span", "", definition.step),
      createElement("strong", "", definition.label),
      createElement("small", "", E2E_STATE_LABELS[stage.state] || stage.state.toUpperCase()),
    );
    button.addEventListener("click", () => renderE2eStageDetail(stage.id));
    item.append(button);
    return item;
  }).filter(Boolean);

  replaceChildren(byId("e2e-stage-flow"), stages);
  byId("e2e-stage-flow").setAttribute(
    "aria-label",
    `Các bước của kịch bản ${scenario.label.replace(/^Xem /, "")}`,
  );
}

function renderE2eScenario(replay, scenarioId) {
  const scenario = replay.scenarios.find((item) => item.id === scenarioId);
  if (!scenario) return;

  state.selectedE2eScenario = scenario.id;
  state.selectedE2eStage = scenario.focusStage;
  document.querySelectorAll("[data-e2e-scenario]").forEach((button) => {
    const active = button.dataset.e2eScenario === scenario.id;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
  });

  const activeTab = byId(`e2e-tab-${scenario.id}`);
  byId("e2e-scenario-panel").setAttribute("aria-labelledby", activeTab.id);
  byId("e2e-scenario-tag").textContent = scenario.tag;
  byId("e2e-scenario-title").textContent = `${scenario.label.replace(/^Xem /, "")} — ${scenario.result.headline}`;
  byId("e2e-scenario-summary").textContent = scenario.summary;

  const status = byId("e2e-scenario-status");
  status.textContent = scenario.status.toUpperCase();
  status.dataset.state = scenario.tone;

  byId("e2e-result-headline").textContent = scenario.result.headline;
  byId("e2e-run-status").textContent = scenario.status;
  byId("e2e-network-mode").textContent = replay.networkExecutionEnabled
    ? "Không hợp lệ"
    : "Tắt trên UI";
  byId("e2e-proposal-cardinality").textContent = replay.oneProposalPerRun ? "1" : "—";
  byId("e2e-request-line").textContent = `${scenario.request.method} ${scenario.request.path}`;
  byId("e2e-request-risk").textContent = scenario.request.risk;
  byId("e2e-human-decision").textContent = scenario.request.humanDecision;
  byId("e2e-credential-boundary").textContent = scenario.request.credentialBoundary;
  byId("e2e-requests-sent").textContent = String(scenario.result.requestsSent);
  byId("e2e-guard-result").textContent = scenario.result.guard;
  byId("e2e-interpretation").textContent = scenario.result.interpretation;
  byId("e2e-safe-code").textContent = scenario.result.safeCode;

  renderE2eStages(replay, scenario);
  renderE2eStageDetail(scenario.focusStage);
}

function handleE2eScenarioKeydown(event) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const tabs = [...event.currentTarget.closest('[role="tablist"]').querySelectorAll('[role="tab"]')];
  const current = tabs.indexOf(event.currentTarget);
  let target = current;
  if (event.key === "ArrowLeft") target = (current - 1 + tabs.length) % tabs.length;
  if (event.key === "ArrowRight") target = (current + 1) % tabs.length;
  if (event.key === "Home") target = 0;
  if (event.key === "End") target = tabs.length - 1;
  event.preventDefault();
  tabs[target].focus();
  renderE2eScenario(state.data.e2eReplay, tabs[target].dataset.e2eScenario);
}

function renderE2eReplay(replay) {
  if (!replay || replay.mode !== "sanitized_replay" || replay.networkExecutionEnabled !== false) {
    byId("e2e-replay-notice").textContent = "Không có bản replay an toàn để hiển thị.";
    byId("e2e-scenario-panel").hidden = true;
    document.querySelector(".replay-evaluation").hidden = true;
    byId("e2e-scenario-tabs").querySelectorAll("button").forEach((button) => {
      button.disabled = true;
    });
    return;
  }

  byId("e2e-scenario-panel").hidden = false;
  document.querySelector(".replay-evaluation").hidden = false;
  byId("e2e-replay-notice").textContent = replay.notice;
  renderE2eEvaluation(replay.evaluation);

  const tabs = replay.scenarios.map((scenario, index) => {
    const button = createElement("button", "replay-scenario-tab", scenario.label);
    button.id = `e2e-tab-${scenario.id}`;
    button.type = "button";
    button.setAttribute("role", "tab");
    button.dataset.e2eScenario = scenario.id;
    button.setAttribute("aria-controls", "e2e-scenario-panel");
    button.setAttribute("aria-selected", "false");
    button.tabIndex = index === 0 ? 0 : -1;
    button.addEventListener("click", () => renderE2eScenario(replay, scenario.id));
    button.addEventListener("keydown", handleE2eScenarioKeydown);
    return button;
  });
  replaceChildren(byId("e2e-scenario-tabs"), tabs);
  renderE2eScenario(replay, replay.scenarios[0].id);
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
  setRuntimeLayer(
    "policy",
    allowed ? "allow" : "deny",
    allowed ? "ALLOW" : "DENY",
    allowed ? `${endpoint.id} · expected ${testCase.expectedStatus}` : receipt.reason,
  );
  setRuntimeLayer(
    "evidence",
    "dry-run",
    "DRY-RUN RECEIPT",
    `${receipt.decision.toUpperCase()} · proposal ${receipt.proposal_id}`,
  );
  selectRuntimeLayer("policy");
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
    restorePolicyAndEvidenceRadar();
    selectRuntimeLayer("policy");
    activateTab("proposal-output");
  }, 0);
}

async function checkHealth() {
  const button = byId("health-button");
  const status = byId("health-status");
  button.disabled = true;
  selectRuntimeLayer("gateway");
  button.classList.remove("is-ok", "is-error", "is-static");
  status.textContent = "Đang kiểm tra endpoint public cùng origin…";
  setRuntimeLayer("gateway", "checking", "CHECKING", "GET /health · credentials omitted");

  if (!isFullStackUiPath()) {
    button.classList.add("is-static");
    status.textContent = "Kênh static showcase; full stack được xác minh riêng trong CI.";
    setRuntimeLayer("gateway", "static", "STATIC", "Không có live backend trên kênh showcase");
    button.disabled = false;
    return;
  }

  if (!['http:', 'https:'].includes(window.location.protocol)) {
    button.classList.add("is-error");
    status.textContent = "Health check chỉ khả dụng khi dashboard được phục vụ qua HTTP(S).";
    setRuntimeLayer("gateway", "failed", "UNAVAILABLE", "Dashboard không được phục vụ qua HTTP(S)");
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
    setRuntimeLayer("gateway", "live", "LIVE", `${healthUrl.host}/health · HTTP ${response.status}`);
  } catch (_error) {
    button.classList.add("is-error");
    status.textContent = "Không kết nối được /health. Dashboard và dry-run vẫn hoạt động offline.";
    setRuntimeLayer("gateway", "failed", "FAILED", "Không xác minh được public /health");
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
  setRuntimeLayer("gateway", "static", "STATIC", "Không có live backend trên kênh showcase");
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
  document.querySelectorAll(".radar-hotspot").forEach((button) => {
    button.addEventListener("click", () => selectRuntimeLayer(button.dataset.runtimeLayer));
  });
  document.querySelectorAll(".code-tab").forEach((tab) => {
    tab.addEventListener("click", () => activateTab(tab.dataset.panel));
    tab.addEventListener("keydown", handleTabKeydown);
  });
}

async function initialize() {
  try {
    const response = await fetch("./dashboard-data.json?v=e2e-replay-4", { cache: "no-store", credentials: "omit" });
    if (!response.ok) throw new Error(`dashboard_data_${response.status}`);
    state.data = await response.json();
    renderMetrics(state.data.metrics);
    renderArchitecture(state.data.architecture);
    renderControls(state.data.controls);
    renderEvidence(state.data.evidence);
    renderRoadmap(state.data.roadmap);
    renderE2eReplay(state.data.e2eReplay);
    initializeRuntimeRadar();
    populateEndpoints();
    wireInteractions();
    configureHostingMode();
  } catch (_error) {
    byId("decision-summary").querySelector("strong").textContent = "Không tải được dữ liệu curated";
    byId("decision-summary").querySelector("p").textContent = "Hãy phục vụ thư mục static qua HTTP để dùng simulator. Nội dung tổng quan vẫn hiển thị.";
    byId("decision-badge").textContent = "OFFLINE";
    byId("decision-badge").className = "decision-badge is-deny";
    byId("proposal-form").querySelectorAll("input, select, textarea, button").forEach((control) => { control.disabled = true; });
    setRuntimeLayer("policy", "unavailable", "UNAVAILABLE", "Không tải được curated policy metadata");
    setRuntimeLayer("evidence", "unavailable", "UNAVAILABLE", "Không tải được evidence snapshot");
    setRuntimeLayer("gateway", "unchecked", "UNCHECKED", "Chưa thực hiện health check");
    byId("health-button").addEventListener("click", checkHealth);
    configureHostingMode();
  }
}

initialize();
