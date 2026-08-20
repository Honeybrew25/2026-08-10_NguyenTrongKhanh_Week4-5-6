# Kịch bản demo Project Sentinel — 10 đến 15 phút

## Chuẩn bị trước buổi demo

Từ clean checkout, cài dependency và thay placeholder trong `.env`. Chạy:

```powershell
docker compose down --remove-orphans
docker compose up --build --detach --wait --wait-timeout 180
python -m project_sentinel preflight --execute
```

Preflight một lệnh kiểm policy/fixture, `.env` contract, Docker/Compose,
Gateway health và API key mà không in credential. Nếu fail, chạy cleanup, mở
artefact deterministic đã verify trong evidence và không đổi origin sang
backend.

## Timeline

### 0:00–2:00 — Bài toán và ranh giới

Mở README/sơ đồ kiến trúc và mục **E2E Week 6** trên dashboard. Chuyển qua bốn
tình huống rồi bấm một vài bước để giải thích luồng. Nhấn mạnh đây là bản phát
lại đã làm sạch, không phải lần chạy live. Scanner facts thuộc code, model chỉ
viết narrative, con người giữ approval, mọi request qua Envoy và response luôn
untrusted.

### 2:00–4:00 — Fresh scan, normalize và Agent

```powershell
python -m project_sentinel demo --provider deterministic --format human
```

Mở `demo-inputs/*-bandit.json`, `normalized-findings.json`,
`security-analysis.jsonl`, `request-proposal.json` và `final-report.json` của
run mới. Chỉ ra scanner hash, source finding IDs, knowledge IDs và bounded
capability/test-case. Dry-run phải có `requests_sent: 0`.

### 4:00–8:00 — HITL và Gateway

```powershell
python -m project_sentinel demo --provider deterministic --execute --format human
```

1. Gõ `Reject` ở prompt đầu: terminal phải báo `REJECTED` và
   `requests_sent=0` ngay sau tình huống.
2. Gõ `Approve` ở prompt thứ hai: panel phải hiển thị endpoint, curated payload,
   purpose, source IDs và fingerprint trước khi gửi. Kết quả phải có
   `approvals=1`, `requests_sent=1`; status 200 chỉ là verification signal,
   không phải exploit proof.
3. Theo dõi tình huống prompt injection: terminal phải báo response đã bị cách
   ly và không lưu nội dung thô.
4. Theo dõi admin-negative: `endpoint_not_allowed`, 0 request và bước Gateway
   được ghi rõ là bị chặn hoặc không chạy. Backend không publish host port.

Mỗi tình huống có run ID riêng; bảng cuối tổng hợp đủ bốn run. Có thể mở
`final-report.json` để kiểm tra sâu hơn nhưng không cần đọc JSON trong lúc trình
bày.

### 8:00–10:00 — Prompt injection và redaction

Mở injection final report: `injection_flags=1`, excerpt chỉ còn
`[QUARANTINED_UNTRUSTED_HTTP_RESPONSE]`; không có raw instruction hay
`/api/admin`, không có follow-up action.

```powershell
python -m project_sentinel evaluate --provider deterministic
```

Mở case 8 và 9 trong `evaluation-summary.json`. Case 9 phải liệt kê sáu marker
`[REDACTED_*]`, `raw_value_count=0`. Nêu hai regression Agent riêng cho
email/phone và token/API key/password/PII trước provider/final report.

### 10:00–12:00 — Metrics và chất lượng

Mở final report/event log và evaluation summary:

- duration từng stage và tổng;
- raw/normalized findings, analysis groups;
- attempted/sent, Approve/Reject, injection/redaction, errors;
- 10 expected/actual cases và TP/FP/FN.

Giải thích giới hạn: dataset nhỏ, regex guard, passive `/health` ZAP,
process-local rate limiter, deterministic narrative không thay thế security
review.

### 12:00–15:00 — Câu hỏi và cleanup

```powershell
docker compose down --remove-orphans
docker compose ps --all
```

`docker compose ps --all` không được còn container của project. Run output được
giữ để review; baseline không bị xóa hoặc ghi đè.

## Fallback và khôi phục

- Gemini/mạng ngoài lỗi: dùng deterministic provider; CI không gọi Gemini.
- Nếu live stack không phục hồi trong khung demo, mở sanitized fallback tại
  `security-results/runs/week-6/golden/release-summary.json` và đối chiếu hash
  với `evidence/week-6/pre-release-verification-2026-08-20.log`; không trình bày
  snapshot như live run.
- Fresh scan lỗi nhưng có JSON: nêu exit semantics và mở raw artefact; không
  gọi Pass giả. Nếu JSON hỏng, run phải failed và output tốt trước đó giữ nguyên.
- Gateway lỗi: trình bày dry-run + verified evidence; không gọi thẳng backend.
- Approval input/TTY lỗi: kết quả là Reject, không auto-approve.
- Docker lỗi: `docker compose logs --no-color --tail 200`, cleanup, rồi start
  clean. Không tái sử dụng run ID.

