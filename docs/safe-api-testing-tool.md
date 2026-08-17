# Safe API Testing Tool — Week 4, hardened in Week 5

> Week 4 · Xem [documentation hub](../README.md),
> [báo cáo tuần](../reports/week-4.md) và
> [receipt demo](../security-results/runs/week-4/safe-api-demo.jsonl).
> Phần HITL, prompt-injection guard và redaction hiện hành nằm tại
> [tài liệu Week 5](week5-guardrails.md).

## Mục tiêu và ranh giới

Safe API Testing Tool cho phép Agent đề xuất rồi thực thi một số request GET
và POST an toàn qua Envoy. Tool không phải scanner khai thác: nó không nhận
URL tùy ý, không tạo payload phá hoại, không đổi dữ liệu thật và không truy cập
trực tiếp backend.

Luồng thực thi:

```text
grounded finding Week 3
  -> deterministic RequestProposal
  -> strict schema
  -> policy decision + risk classification
  -> HITL cho POST/curated payload
  -> bounded HTTP client
  -> Envoy
  -> ext_authz: API key + exact route + rate limit
  -> stateless FastAPI test surface
  -> response guard + shared redaction
  -> receipt/approval/guarded-response/event JSONL tách biệt
```

`RequestProposal` chỉ có `endpoint_id`, `test_case_id`, `rationale`,
`source_finding_ids` và `requested_headers`. URL, raw body và credential không
thuộc contract. Payload thật được code dựng từ catalog đã curate.

## Thành phần

| Thành phần | Source of truth |
|---|---|
| Allowlist, Gateway origin và budget | `config/safe-api-tool/policy.json` |
| Bốn payload an toàn | `data/safe-api-test-cases.json` |
| Proposal/policy/client/planner/audit | `src/safe_api_tool/` |
| API test stateless | `GET /api/test/status`, `GET /api/test/prompt-injection`, `POST /api/test/validate` |
| Enforcement phía Gateway | `config/envoy/envoy.yaml`, `src/authz_service/` |
| JSON contracts | `schemas/safe-api-*.schema.json` |
| Receipt mẫu | `security-results/runs/week-4/safe-api-demo.jsonl` |

Policy hiện tại cho phép tối đa 12 request/phút trên mỗi API key, method và
route; timeout 3 giây; request body 4 KiB; response 64 KiB; tối đa bốn custom
header và 256 byte cho mỗi header value.

## Kế thừa và truy vết từ Week 3

Planner đọc `security-results/security-analysis.jsonl`, giữ
`source_finding_ids` của nhóm đã grounded rồi tạo `RequestProposal`. Tool tính
fingerprint 16 ký tự từ canonical proposal; receipt ghi fingerprint đó cùng
policy SHA-256, endpoint/test-case ID và `x-request-id` để nối quyết định của
Tool với audit của authz-service.

Tên finding, explanation và verification steps của Week 3 có thể ảnh hưởng
việc chọn một `test_case_id` đã curate cùng rationale. Chúng không được chuyển
thành URL, raw body, API key hoặc header capability. Nếu finding chứa prompt
injection hoặc yêu cầu endpoint ngoài allowlist, deterministic planner vẫn chỉ
có thể chọn capability/test case đã định nghĩa; policy tiếp tục có quyền từ
chối trước transport.

## Contract matrix

| `endpoint_id` | Method/path | Test case hợp lệ | Expected status |
|---|---|---|---|
| `test-status` | `GET /api/test/status` | `empty` | 200 |
| `prompt-injection-fixture` | `GET /api/test/prompt-injection` | `empty` | 200 |
| `input-validation` | `POST /api/test/validate` | `long-string`, `special-characters`, `empty` | 200 |
| `input-validation` | `POST /api/test/validate` | `wrong-type` | 422 |

| Identity | Surface được phép | Credential |
|---|---|---|
| Anonymous | GET `/health`, GET metadata; GET/HEAD `/` và `/ui/*` | Không có |
| `safe-api-tool` | Đúng ba route trong policy ở bảng trên | API key riêng, bị Envoy consume |
| `agent-reader` | GET `/api/users` | JWT có `users:read` |
| `agent-admin` | GET `/api/users`, GET `/api/admin` | JWT có `users:read`, `admin:read` |
| Mọi trường hợp khác | Không có | Deny-by-default |

API key không thay thế JWT và không cấp quyền tới `/api/users` hoặc
`/api/admin`. Response `/api/admin` khai báo rõ
`authorization_boundary: "envoy_ext_authz"` và `required_scope: "admin:read"`;
backend không dùng boolean `authentication_enabled: false` dễ gây hiểu nhầm.
JWT cũng không tự cấp quyền cho safe test surface.

## Defense in depth

### Trước khi mở kết nối

- Agent chỉ chọn ID có capability hữu hạn.
- Pydantic và JSON Schema cấm field ngoài contract.
- Policy chỉ chấp nhận exact method/path dưới `/api/test/`.
- Cấm absolute URL, query, fragment, `%` encoding, `..`, backslash và double
  slash.
- Cấm `Host`, `Authorization`, `x-api-key`, hop-by-hop header và
  `X-Forwarded-*` do proposal điều khiển.
- Custom header value chỉ nhận printable ASCII để transport không phát sinh
  lỗi encoding ngoài typed execution contract.
- Body được serialize trước rồi kiểm tra kích thước.
- Local rate limiter dừng request vượt budget trước transport.
- Mọi POST hoặc materialized request có curated payload phải có approval còn
  hạn, single-use và khớp fingerprint sau policy re-check.

### Tại Gateway boundary

- Tool chỉ chọn một trong hai trusted profile: host
  `http://localhost:8080` hoặc Compose `http://envoy:8080`; backend
  `http://api:8000` không bao giờ là origin hợp lệ của client.
- `ext_authz` fail closed và đọc cùng policy versioned với Tool.
- API key riêng được băm SHA-256 và so sánh constant-time trong authz-service.
- API key chỉ được dùng cho ba exact route hiện có; không kế thừa quyền JWT
  `agent-reader` hoặc `agent-admin`.
- Rate limit được kiểm tra lại ở authz-service để client giả mạo không bypass
  limiter của Tool.
- Envoy giới hạn body 4 KiB trên đúng `POST /api/test/validate` trước
  `ext_authz`; request vượt cap bị trả 413 mà không tới authz hoặc ứng dụng.
- Khi allow, authz-service yêu cầu Envoy consume `x-api-key` trước upstream.
  Backend có canary fail-closed: nếu header này còn tồn tại, request trả 500.

### Khi đọc response và ghi log

- Client dùng `follow_redirects=False`, `trust_env=False` và yêu cầu
  `Accept-Encoding: identity`.
- Response được đọc theo stream và dừng đúng byte cap; không tải toàn bộ rồi
  mới kiểm tra kích thước.
- Timeout, connection error, 429, status sai contract và response truncated là
  typed outcome, không ghi raw exception.
- Receipt chỉ ghi tên header, byte count, SHA-256, status, latency và bounded
  excerpt. Toàn bộ response đã giữ lại được redact trước khi cắt excerpt để
  secret nằm qua ranh giới không lộ một phần; API key, Authorization value và
  raw request body không được ghi.
- Response là dữ liệu không tin cậy và không được đưa nguyên văn trở lại
  planner.
- Prompt-injection signal làm excerpt chuyển thành marker quarantine; không tạo
  proposal, approval hoặc request kế tiếp. Sanitizer chung che email, số điện
  thoại lab, token, API key, password và các trường PII đã biết.

## Threat model rút gọn

| Nguy cơ | Kiểm soát | Bằng chứng |
|---|---|---|
| SSRF/direct backend | Capability ID, origin cố định, không redirect, backend private | Unit + Docker integration |
| Endpoint/method cấm | Exact allowlist ở Tool và authz | `/api/admin`, route/method lạ bị deny |
| Path confusion | Canonical path check ở hai lớp | Encoded traversal/query/double slash tests |
| Credential override/leak | Header denylist, key inject nội bộ, Envoy consume, redaction | Backend canary + secret sentinel |
| Resource exhaustion | Request cap ở Tool + Envoy, response cap, timeout, RPM ở hai lớp | 413, streaming, timeout và 429 tests |
| Prompt injection | Response quarantine + narrative không sở hữu URL/body/header capability | Hai hostile response + benign control |
| HITL bypass/replay | Execution-boundary gate, fingerprint, expiry và single-use | Reject 0 call; Approve 1 call; mismatch/TOCTOU tests |
| Policy drift/malformed config | Một JSON policy, strict loader ở hai package, fail closed | Contract/schema/config-error tests |

## Sử dụng

Chuẩn bị `.env` từ `.env.example` và đặt một API key ngẫu nhiên tối thiểu 32
byte cho `SAFE_API_TOOL_API_KEY`. Không truyền key trên command line.

```powershell
python -m pip install --requirement requirements-dev.txt
docker compose up --build --detach --wait
```

Tạo proposal từ finding grounded đầu tiên:

```powershell
python -m safe_api_tool propose `
  --analysis security-results/security-analysis.jsonl `
  --output "$env:TEMP\safe-api-proposal.json"
```

Dry-run là mặc định và không cần secret hoặc network:

```powershell
python -m safe_api_tool run "$env:TEMP\safe-api-proposal.json"
python -m safe_api_tool demo
```

Chỉ `--execute` mới mở network. POST sẽ dừng để người vận hành nhập đúng
`Approve` hoặc `Reject`:

```powershell
python -m safe_api_tool run "$env:TEMP\safe-api-proposal.json" `
  --execute --audit "$env:TEMP\safe-api-receipts.jsonl" `
  --approval-log "$env:TEMP\safe-api-approvals.jsonl" `
  --guarded-response-log "$env:TEMP\safe-api-guarded.jsonl" `
  --event-log "$env:TEMP\safe-api-events.jsonl"

python -m safe_api_tool demo --execute `
  --audit "$env:TEMP\safe-api-demo.jsonl"
```

Demo thực hiện GET status, hai run POST riêng để chứng minh Reject rồi Approve,
và negative control `admin` bị policy chặn trước network. Không có `--yes` hoặc
biến môi trường bypass HITL. Kết thúc bằng:

```powershell
docker compose down --remove-orphans
```

## Typed outcomes

- `success`: request hoàn tất và HTTP status khớp test case.
- `unexpected_status`: Gateway/API trả status khác contract; CLI/demo fail thay
  vì báo đậu giả.
- `policy_denied`: capability bị chặn trước transport.
- `rate_limited`: local budget hoặc Gateway trả 429.
- `timeout`: hết timeout mà không lộ raw exception.
- `connection_error`: không kết nối được Gateway.
- `response_truncated`: response đã bị cắt đúng giới hạn nhưng vẫn có receipt.

CLI và CI chỉ trả success khi outcome là `success` và
`expected_status_matched=true`. Receipt bị truncate vẫn được lưu để điều tra
nhưng không làm demo đậu.

Exit code của CLI:

| Code | Ý nghĩa |
|---:|---|
| `0` | Proposal/dry-run hợp lệ, hoặc execution/demo khớp toàn bộ contract |
| `2` | Input, policy, catalog, credential hoặc cấu hình không hợp lệ |
| `3` | Một lệnh `run` bị policy từ chối trước transport |
| `4` | Execution/demo không khớp contract: HTTP status sai, timeout, 429, connection error hoặc response truncated |

Troubleshooting nhanh:

| Triệu chứng | Kiểm tra |
|---|---|
| Exit `2`, thiếu key | Chỉ với `--execute`: kiểm tra `SAFE_API_TOOL_API_KEY` trong `.env`; không truyền key qua CLI |
| HTTP 401 / exit `4` | Key của Tool và authz-service không khớp hoặc placeholder chưa được thay |
| HTTP 413 | Request vượt body cap 4 KiB; không tăng cap nếu chưa review policy và Envoy cùng lúc |
| Outcome `rate_limited` / HTTP 429 | Chờ cửa sổ một phút; không retry dồn dập |
| `connection_error` | Kiểm tra `docker compose ps` và public `/health`; không đổi origin sang backend trực tiếp |
| `policy_denied` / exit `3` | Đối chiếu exact endpoint/test-case/header với `policy.json`; không bypass bằng URL tùy ý |

## Kiểm thử và evidence

```powershell
python -m pytest -q -m "not integration"
python scripts/run_all_tests.py
python -m json.tool config/safe-api-tool/policy.json > $null
docker compose config --quiet
```

`run_all_tests.py` tạo secret tạm trong process, chạy toàn bộ Docker integration,
chạy `safe_api_tool demo --execute` với hai input test cố định `Reject` và
`Approve`, ghi bốn JSONL CI đã sanitize rồi dọn stack. GitHub Actions upload
chúng dưới artifact `week5-safe-api-guardrail-artifacts`.

Evidence bền vững trong repository:

| Artifact | Nội dung cần kiểm tra |
|---|---|
| `config/safe-api-tool/policy.json` | Exact routes, ba capability và resource budget |
| `data/safe-api-test-cases.json` | Bốn profile long/special/empty/wrong-type |
| `security-results/runs/week-4/safe-api-demo.jsonl` | GET 200, POST 200 và negative control bị deny trước transport |
| `evidence/week-4/verification.log` | Lệnh, môi trường và kết quả quality gates của run bàn giao |
| `evidence/week-5/verification.log` | Nghiệm thu HITL, redaction, prompt guard và full-stack hiện hành |
| `.github/workflows/security-scan.yml` | Secret tạm, live demo và bốn artifact upload trong CI |

`policy_sha256` hiện hành của model policy canonical là
`0181e74d35ced610750e1ced2e42f0e1733439d3ce830b6cb62cf2cfee7562a8`.
Receipt mẫu Week 4 giữ nguyên hash lịch sử cũ; không sửa receipt đó để giả lập
evidence mới. Hash byte của file JSON còn phụ thuộc newline/whitespace nên không
được so trực tiếp với canonical model hash.

Checklist review Week 4:

- Proposal chỉ chứa năm field theo schema; không có URL, raw body hoặc secret.
- Dry-run là mặc định; `--execute` chỉ bật execution mode, không phải approval.
- POST vẫn cần quyết định HITL hợp lệ ngay tại execution boundary.
- Tool và authz cùng đọc một policy, chỉ cho exact method/path/test case.
- Backend không publish host port; request hợp lệ phải đi qua Envoy.
- API key được inject nội bộ, so sánh constant-time, consume trước upstream và
  không xuất hiện trong receipt/audit.
- Request/response/timeout/RPM đều có cap và lỗi được ánh xạ thành typed
  outcome.
- CLI/CI chỉ báo đậu khi status khớp contract; negative control phải bị chặn.

## Giới hạn đã biết

- Limiter phía authz hiện là process-local, phù hợp một replica của lab. Nếu
  scale ngang phải thay bằng distributed store hoặc Gateway rate-limit service.
- `timeout_seconds` áp dụng riêng cho connect/read/write của HTTP client; route
  Envoy có ceiling 5 giây. Một hard deadline xuyên suốt nhiều chunk sẽ cần
  transport/deadline controller riêng nếu chuyển khỏi phạm vi lab.
- Planner hiện deterministic để CI tái lập được; chưa cho LLM trực tiếp sở hữu
  capability.
- Runtime origin chỉ có profile `host` và `compose`; môi trường khác cần thêm
  profile tin cậy bằng code/config review, không nhận URL từ proposal.
- ZAP CI là passive unauthenticated baseline seed từ `/health`; standard spider
  có thể thấy public root/UI nhưng không nhận Agent token, không gửi curated
  Safe API payload và không bao phủ protected API. Safety contract Week 4 được
  kiểm chứng bởi Tool/integration tests riêng; receipt đó không được gọi là
  authenticated DAST.
