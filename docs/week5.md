# Guardrails, Human-in-the-Loop và redaction — Week 5

> Week 5 · Xem [documentation hub](../README.md),
> [Safe API Tool](safe-api-testing-tool.md) và
> [checklist sản phẩm](todo-checklist.md).

## Kết quả

Week 5 thêm ba ranh giới bắt buộc vào Safe API Tool:

```text
RequestProposal chỉ chứa ID
  -> policy materialize exact request
  -> risk classifier
  -> GET không payload: ready_to_execute
  -> POST hoặc request có curated payload: pending_approval
       -> Reject/invalid/EOF/timeout: terminal, 0 network call
       -> Approve: bind request + policy + origin, single-use
  -> policy re-check
  -> trusted Gateway origin
  -> streaming response cap
  -> prompt-injection detector/quarantine
  -> shared sanitizer
  -> các JSONL contract tách biệt
```

Approval không thay thế policy. Model, proposal và HTTP response không thể sở
hữu URL, credential, raw payload, Gateway origin hay quyết định Approve.

## Contract và state machine

State hợp lệ:

- GET thường: `proposed -> validated -> ready_to_execute -> executed`.
- POST Approve: `proposed -> validated -> pending_approval -> approved ->
  ready_to_execute -> executed`.
- POST Reject: `proposed -> validated -> pending_approval -> rejected`.
- Policy, approval, rate hoặc preflight lỗi kết thúc `blocked`/`failed`; terminal
  state không chuyển tiếp.

Mỗi lời gọi `execute` là đúng một proposal/run. `run_id` không được tái sử dụng
trong cùng client. Demo Approve và Reject là hai run riêng, không phải một queue.

| Contract | Nội dung | Schema |
|---|---|---|
| `RiskDecision` | POST **hoặc** curated payload cần duyệt; GET không body đi thẳng | `schemas/safe-api-risk-decision.schema.json` |
| `ApprovalDecision` | run/proposal/approval ID, policy hash, origin ID, request fingerprint, decision, UTC issue/expiry, used, reason | `schemas/safe-api-approval.schema.json` |
| `ExecutionReceipt` v1 | Network facts và typed outcome; giữ tương thích receipt Week 4 | `schemas/safe-api-log.schema.json` |
| `GuardedResponse` | trust label, status/size/hash, bounded sanitized excerpt, injection signal, redaction counters | `schemas/safe-api-guarded-response.schema.json` |
| `RunEvent` | run/event ID, stage, duration, outcome, safe error code, counters và related IDs | `schemas/safe-api-run-event.schema.json` |

Fingerprint canonical bind method, path, test-case ID, curated payload, header,
policy SHA-256, trusted-origin ID và giá trị origin tương ứng. Approval hết hạn,
đã dùng, sai run/proposal/policy/origin/fingerprint hoặc request thay đổi sau
review đều bị chặn trước transport.

Hai runtime profile duy nhất do operator chọn:

| Profile | Origin tin cậy |
|---|---|
| `host` | `http://localhost:8080` |
| `compose` | `http://envoy:8080` |

Proposal/model không có field origin. `http://api:8000`, URL tùy ý và
`network_mode: host` không thuộc đường chạy được hỗ trợ.

## Redaction

`src/sentinel_guardrails/redaction.py` là sanitizer chung cho Agent, planner,
approval display, HTTP response, receipt và JSONL contract writer. Nó xử lý
text cùng dict/list lồng nhau, không mutate input và idempotent.

Marker ổn định:

- `[REDACTED_EMAIL]`
- `[REDACTED_PHONE]`
- `[REDACTED_TOKEN]`
- `[REDACTED_API_KEY]`
- `[REDACTED_PASSWORD]`
- `[REDACTED_PII]`

Phạm vi PII v1 của lab là email, số điện thoại Việt Nam dạng fixture, các khóa
định danh đã biết (`ssn`, `national_id`, `customer_id`, `person_id`) và chuỗi
fixture có nhãn `PID`, `NATIONAL-ID`, `CCCD`. Đây không phải bộ phát hiện mọi
PII trong văn bản tự do. Counter chỉ ghi số lượng theo marker, không ghi giá trị
gốc.

Raw scanner output có thể tồn tại riêng trong `security-results/` theo retention
policy, nhưng scanner evidence đưa vào prompt/report phải sanitize. HTTP response
không được persist raw: client giữ tối đa byte cap trong bộ nhớ, detector chạy
trên buffer, sanitizer chạy trước excerpt/log và artifact chỉ giữ SHA-256 cùng
bản đã sanitize/quarantine.

## Prompt-injection guard

Exact fixture `GET /api/test/prompt-injection` dùng test case `empty`, không tạo
test case thứ năm và không đổi state. Fixture chỉ chứa chuỗi giả, không có secret
thật. Detector v1 nhận diện ba signal:

- yêu cầu bỏ qua/ghi đè instruction trước;
- yêu cầu tiết lộ system prompt, API key, token hoặc secret;
- yêu cầu gọi `/api/admin`, URL, tool hoặc system command ngoài scope.

Mọi HTTP response có trust label `untrusted_http_response`. Khi có signal,
excerpt bền vững chỉ là `[QUARANTINED_UNTRUSTED_HTTP_RESPONSE]`; raw injection
không được ghi và không tạo proposal, approval, tool call hay request kế tiếp.
Signal là dữ liệu quan sát, không có quyền Approve. Benign response vẫn đi qua
sanitizer và không bị detector đánh dấu.

System Prompt cũng cấm làm theo HTTP response, tiết lộ prompt/secret, đổi target
hoặc gọi tool ngoài phạm vi. Enforcement thật vẫn nằm trong code policy,
approval gate và client, không dựa vào câu trả lời tự nhận là “từ chối” của LLM.

## CLI và fail-closed

Dry-run không cần secret/network:

```powershell
python -m safe_api_tool demo
python -m safe_api_tool run "$env:TEMP\safe-api-proposal.json"
```

Execution POST hiển thị method, exact path, curated payload đã sanitize, header
names, rationale và source finding IDs. Chỉ chấp nhận đúng `Approve` hoặc
`Reject`; input khác, EOF, timeout hoặc provider/UI lỗi mặc định Reject.

```powershell
python -m safe_api_tool run "$env:TEMP\safe-api-proposal.json" `
  --execute --approval-timeout 60 `
  --audit "$env:TEMP\receipts.jsonl" `
  --approval-log "$env:TEMP\approvals.jsonl" `
  --guarded-response-log "$env:TEMP\guarded.jsonl" `
  --event-log "$env:TEMP\events.jsonl"
```

Demo thật yêu cầu hai quyết định theo thứ tự: `Reject` để chứng minh 0 call,
sau đó `Approve` để gửi đúng một bounded POST. GET status không cần approval;
negative control `admin` vẫn bị allowlist chặn. Không có `--yes` hoặc environment
variable bypass HITL. Test/CI chỉ inject provider giả được đánh dấu rõ là
test-only.

Guard config không callable bị từ chối khi dựng client, trước network. Nếu guard
lỗi sau response đầu tiên, receipt chỉ giữ network facts/hash, không giữ excerpt
raw; không có guarded-response artifact/follow-up và run event kết thúc bằng
`response_guard_failed`.

## Retention và tái hiện

Generated output trong `security-results/runs/week-5/` và `week-6/` bị Git
ignore. Chỉ nội dung đặt chủ đích dưới thư mục `golden/` mới có thể được commit,
và chỉ sau schema validation cùng secret/PII sentinel. Verification log bền vững
nằm trong `evidence/week-5/`.

```powershell
.\.venv\Scripts\python.exe -m pytest -q -m "not integration"
.\.venv\Scripts\python.exe scripts/run_all_tests.py
docker compose config --quiet
```

Các test Week 5 bao phủ contract schema, state transition, sanitizer nested và
idempotence, success/error redaction, hai hostile response, benign control,
Reject/Approve, expiry/replay/mismatch, policy/payload TOCTOU, trusted origins,
admin negative control, response-guard failure và state trước/sau toàn bộ bốn
POST fixture. Kết quả nghiệm thu cụ thể nằm trong
`evidence/week-5/verification.log`.

## Giới hạn

- Detector v1 là heuristic cho fixture có kiểm soát, không phải giải pháp phát
  hiện mọi biến thể prompt injection.
- Rate limiter của client và authz-service còn process-local/in-memory.
- Raw scanner retention cần chính sách tổ chức khi chuyển khỏi lab.
- Việc tổng hợp một final report xuyên suốt scanner -> analysis -> approval ->
  receipt là phạm vi orchestrator Week 6; Week 5 cung cấp các contract đã
  sanitize và ID/hash để nối mà không tái sử dụng raw HTTP response.
