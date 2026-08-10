# Báo cáo Week 4 — Safe API Testing qua Gateway

## Mục tiêu

Cho phép Agent đề xuất và thực thi GET/POST an toàn qua API Gateway, với API
key riêng, exact allowlist, resource budget, error handling và log không lộ
secret.

## Quá trình

- Giữ Envoy và `ext_authz` fail-closed làm Gateway; bổ sung API-key identity
  `safe-api-tool` mà không thay đổi quyền JWT reader/admin hiện có.
- Tạo policy versioned, JSON Schema và catalog bốn payload an toàn. Proposal
  chỉ chọn `endpoint_id`/`test_case_id`; code sở hữu URL, body và credential.
- Thêm hai API test stateless, local + Gateway rate limit, timeout, request cap
  ở cả Tool/Envoy, streaming response cap, redirect-off và typed outcomes.
- Nối finding grounded Week 3 vào deterministic planner, CLI dry-run mặc định,
  explicit `--execute` và one-command demo.
- Thêm secret sentinel, negative/adversarial tests, backend canary kiểm tra
  Envoy đã consume API key và CI artifact cho receipt demo.

## Kết quả

- **120 non-integration test pass**; full Docker suite **140 test pass**.
- Demo thật qua Envoy tạo ba receipt: GET 200, POST 200 và capability `admin`
  bị `policy_denied` trước network.
- Key sai/thiếu bị 401; route/method lạ bị deny; body vượt 4 KiB bị Gateway trả
  413 trước authz/app; burst trả typed 429; status sai, timeout, connection
  error và oversized response đều có outcome kiểm soát.
- API key không xuất hiện trong tool receipt hoặc authz audit; backend canary
  chứng minh credential đã bị Envoy loại bỏ trước upstream.
- Receipt mẫu nằm tại
  `security-results/runs/week-4/safe-api-demo.jsonl`; policy hash của run là
  `a969dab49a01609707d4084330284790928bd445e282effea165d2edac1c947d`.

## Việc tiếp theo

Khi scale nhiều authz replica, thay limiter process-local bằng distributed
rate limiter. ZAP authenticated/allowlisted coverage và chọn proposal bằng LLM
có thể mở rộng sau, nhưng LLM vẫn không được sở hữu URL hoặc raw payload.
