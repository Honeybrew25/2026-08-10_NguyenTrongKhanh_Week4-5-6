# Kiến trúc Project Sentinel

## Mục tiêu thiết kế

Project Sentinel nối artefact Week 1–5 thành một luồng đầu-cuối có thể kiểm
chứng mà không tăng quyền cho model. Mỗi run xử lý đúng một proposal; Reject và
Approve luôn là hai run. Output được append vào workspace mới, liên kết bằng ID
và hash, không ghi đè baseline tốt.

## Data flow và trust boundary

| Stage | Input | Output | Chủ sở hữu quyết định |
|---|---|---|---|
| Scanner input | Bandit/ZAP JSON của run hiện tại | Bản retained + SHA-256 | Scanner/code |
| Normalize | Raw scanner facts | `normalized-findings.json` | Code/schema |
| Analysis | Facts + curated KB | Grounded JSONL | Model viết narrative; code giữ facts |
| Proposal | Một analysis group | Capability/test-case IDs | Deterministic planner |
| Policy/risk | IDs, header names | Materialized request/risk | Code/policy |
| Approval | Canonical request view | Approve/Reject contract | Con người |
| Request | Approval + policy re-check | Receipt | Client → Envoy only |
| Response guard | Bounded untrusted bytes | Quarantine/redacted excerpt | Code |
| Final report | Các contract riêng | Linked report + manifest/events | Code/schema |

HTTP response không được đưa trở lại planner, không thể sinh follow-up action
và không thể approve. Model không nhận raw URL/payload/credential, không được
quyết định runtime origin. Trusted origin chỉ có hai code-owned profile:
`host=http://localhost:8080` và `compose=http://envoy:8080`.

## State machine

```text
created -> inputs_retained -> normalized -> analyzed
                                      ├─ no findings -> reported
                                      └─ proposed
                                           ├─ dry/blocked -> reported
                                           ├─ pending_approval -> rejected -> reported
                                           └─ approved/GET -> executed -> reported

Mọi state chưa terminal -> failed -> reported
```

Execution boundary bên trong Safe API Tool chi tiết hơn:

```text
proposed -> validated -> ready_to_execute -> executed
                   └-> pending_approval -> approved -> ready_to_execute
                                          └-> rejected (terminal)
```

Approval gắn với `run_id`, proposal ID, policy hash, trusted origin, canonical
request fingerprint, expiry và single-use nonce. Sau Approve, policy được tính
lại; thay đổi proposal/policy/origin làm approval mất hiệu lực.

## Contract và tính toàn vẹn

- `project-sentinel-event.schema.json`: event từng stage, duration, counter,
  safe error code và related IDs.
- `project-sentinel-final-report.schema.json`: phân biệt scanner evidence, AI
  narrative, human decision, request fact và guarded response.
- `manifest.json`: hash mọi file trong workspace; raw scanner input được giữ
  trong `scanner-inputs/` với hash riêng.
- Approval, receipt v1 và guarded response vẫn là contract độc lập, tránh biến
  các trục `outcome`, `decision`, `injection flag`, `redaction count` thành một
  enum loại trừ nhau.

Status 200 chỉ được ghi là `verification_signal_not_exploit_proof`, không phải
bằng chứng khai thác hoặc xác nhận vulnerability. Narrative có
`analysis_method`; facts/provenance đến từ scanner và schema validation.

## Fail-closed và data minimization

- Invalid/empty input không gọi provider/tool; empty tạo output hợp lệ.
- Gateway preflight retry có deadline và không fallback sang backend.
- POST thiếu/reject/expired approval tạo 0 network call.
- Redirect bị tắt; request/response có timeout, size cap và rate cap.
- Redaction chạy trước model/log; response injection bị quarantine trước
  persist. Runtime response-guard failure không persist raw excerpt, không gọi
  model/follow-up và kết thúc run failed dù request đầu đã xảy ra.
- Exception được đổi thành stable safe code; không serialize raw exception.

## Compose và CI

`sentinel-runner` là one-shot profile, non-root, dùng runtime dependencies riêng
và mount policy/data/schema read-only; chỉ output Week 6 được ghi. Container
không nhận `.env` file và không publish port. TTY được giữ cho approval thật;
non-interactive EOF trở thành Reject.

CI chạy Bandit Low/full làm data scan và Bandit High làm release gate riêng.
ZAP passive `/health` là artefact DAST riêng, không được Safe API receipt thay
thế. Job Week 6 tải đúng Bandit/ZAP của cùng workflow, chạy deterministic
dry-run/evaluation, kiểm schema/hash/sentinel rồi upload artefact 14 ngày.

## Logging và metrics

Final report/event ghi total và stage duration, raw/normalized finding,
analysis group, request attempted/sent, Approve, Reject, injection flag,
redaction và error count. Provider/config version cùng policy/schema hash cho
phép so sánh run mà không ghi prompt hoặc credential.

## Giới hạn và rủi ro còn lại

- Keycloak dùng `start-dev`, HTTP local và secret trong environment: chỉ phù
  hợp lab, không phải production.
- Rate limiter client/authz là process-local, reset khi restart và không chia
  sẻ khi scale.
- Request-size/rate được lặp giữa policy/authz/Envoy; contract test bắt drift,
  nhưng chưa có distributed single source runtime.
- ZAP chỉ passive unauthenticated `/health`; chưa bao phủ protected API.
- Bandit chỉ quét `src/` và `scripts/`; chưa có dependency/container/config
  scanner.
- Regex prompt-injection/PII có false positive và false negative; chỉ cam kết
  các lớp fixture đã công bố, không phải DLP tổng quát.
- Gemini là tùy chọn ngoài release path; network/quota/cost không có SLO. CI và
  demo fallback dùng deterministic provider.
- Docker image/action pin version nhưng chưa pin digest/SHA ở mọi nơi.
- Dashboard là snapshot presentation, không phải observability backend hoặc
  credentialed API client.
