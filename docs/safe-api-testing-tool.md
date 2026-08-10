# Safe API Testing Tool — Week 4

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
  -> policy decision / dry-run
  -> bounded HTTP client
  -> Envoy
  -> ext_authz: API key + exact route + rate limit
  -> stateless FastAPI test surface
  -> bounded/redacted JSONL receipt
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
| API test stateless | `GET /api/test/status`, `POST /api/test/validate` |
| Enforcement phía Gateway | `config/envoy/envoy.yaml`, `src/authz_service/` |
| JSON contracts | `schemas/safe-api-*.schema.json` |
| Receipt mẫu | `security-results/runs/week-4/safe-api-demo.jsonl` |

Policy hiện tại cho phép tối đa 12 request/phút trên mỗi API key, method và
route; timeout 3 giây; request body 4 KiB; response 64 KiB; tối đa bốn custom
header và 256 byte cho mỗi header value.

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

### Tại Gateway boundary

- Tool chỉ có fixed origin `http://localhost:8080`; backend không publish port
  ra host.
- `ext_authz` fail closed và đọc cùng policy versioned với Tool.
- API key riêng được băm SHA-256 và so sánh constant-time trong authz-service.
- API key chỉ được dùng cho hai route Week 4; không kế thừa quyền JWT
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

## Threat model rút gọn

| Nguy cơ | Kiểm soát | Bằng chứng |
|---|---|---|
| SSRF/direct backend | Capability ID, origin cố định, không redirect, backend private | Unit + Docker integration |
| Endpoint/method cấm | Exact allowlist ở Tool và authz | `/api/admin`, route/method lạ bị deny |
| Path confusion | Canonical path check ở hai lớp | Encoded traversal/query/double slash tests |
| Credential override/leak | Header denylist, key inject nội bộ, Envoy consume, redaction | Backend canary + secret sentinel |
| Resource exhaustion | Request cap ở Tool + Envoy, response cap, timeout, RPM ở hai lớp | 413, streaming, timeout và 429 tests |
| Prompt injection | Narrative không sở hữu URL/body/header capability | Poisoned-finding planner test |
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

Chỉ `--execute` mới mở network:

```powershell
python -m safe_api_tool run "$env:TEMP\safe-api-proposal.json" `
  --execute --audit "$env:TEMP\safe-api-receipts.jsonl"

python -m safe_api_tool demo --execute `
  --audit "$env:TEMP\safe-api-demo.jsonl"
```

Demo thực hiện GET status, một POST do planner đề xuất và negative control
`admin` bị policy chặn trước network. Kết thúc bằng:

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

## Kiểm thử và evidence

```powershell
python -m pytest -q -m "not integration"
python scripts/run_all_tests.py
python -m json.tool config/safe-api-tool/policy.json > $null
docker compose config --quiet
```

`run_all_tests.py` tạo secret tạm trong process, chạy toàn bộ Docker integration,
chạy `safe_api_tool demo --execute`, ghi receipt CI đã sanitize rồi dọn stack.
GitHub Actions upload receipt dưới artifact `week4-safe-api-demo-receipts`.

## Giới hạn đã biết

- Limiter phía authz hiện là process-local, phù hợp một replica của lab. Nếu
  scale ngang phải thay bằng distributed store hoặc Gateway rate-limit service.
- `timeout_seconds` áp dụng riêng cho connect/read/write của HTTP client; route
  Envoy có ceiling 5 giây. Một hard deadline xuyên suốt nhiều chunk sẽ cần
  transport/deadline controller riêng nếu chuyển khỏi phạm vi lab.
- Planner hiện deterministic để CI tái lập được; chưa cho LLM trực tiếp sở hữu
  capability.
- Gateway origin được pin cho môi trường local staging; triển khai môi trường
  khác cần policy riêng và kiểm tra origin tương ứng.
- ZAP baseline hiện vẫn chỉ kiểm tra `/health`; safety contract của Week 4 được
  kiểm chứng bởi Tool và integration tests riêng.
