# Project Sentinel — TODO checklist hoàn thiện sản phẩm

Nguồn yêu cầu: [`docs/todo`](todo). Tài liệu này là nguồn theo dõi duy nhất cho
kế hoạch hoàn thiện sản phẩm; các báo cáo Week 1–4 là lịch sử và không được sửa.

- Ngày rà soát gần nhất: 20/08/2026 (Asia/Bangkok)
- Baseline lịch sử: commit `b32cd0d`; base HEAD của lượt pre-release hiện tại:
  `ea98afa`
- Phạm vi: kế thừa Week 1–4, hoàn thiện Week 5–6 và release cuối kỳ
- Mục tiêu: một luồng an toàn, tái hiện được từ scanner đến báo cáo cuối; không
  mở rộng sang khai thác thực tế, GraphRAG hoặc Multi-Agent phức tạp

## 0. Cập nhật pre-release 20/08/2026

Working tree hiện tại đã qua toàn bộ gate kỹ thuật local:

- fresh Bandit Low `41 findings -> 6 grounded groups`; High gate = 0;
- evaluation 10/10, gồm 5 case Agent và 5 case hành vi; TP=6, FP=0, FN=0;
- 216 non-integration test và 244 full-stack test đạt, không warning;
- Reject=0 request, Approve=1 request, response injection bị quarantine và
  `/api/admin` bị chặn trước network;
- schema, manifest/hash, secret/PII sentinel, Compose cleanup và link tài liệu
  đều đạt.

Evidence: [`pre-release-verification-2026-08-20.log`](../evidence/week-6/pre-release-verification-2026-08-20.log).
Đây chưa phải final release vì thay đổi chưa được commit/push theo yêu cầu hiện
tại. Các việc thật sự còn chờ là peer clean-checkout (`DOC-08`), rehearsal được
người nghiệm thu xác nhận (`DEMO-12`) và rerun trên final clean commit/hosted CI
(`DOC-09`, `REL-07`, `REL-11`). Dùng
[`release-acceptance.md`](release-acceptance.md) để ghi các xác nhận đó.

## 1. Cách dùng checklist

- `[x]`: đã có artefact và đã có bằng chứng kiểm tra phù hợp.
- `[ ]`: chưa làm, mới làm một phần, hoặc phải nghiệm thu lại sau thay đổi.
- `P0`: bắt buộc để hoàn thành sản phẩm; `P1`: nên làm để tăng chất lượng;
  `P2`: mở rộng, không nằm trên đường găng.
- Chỉ chuyển một mục sang `[x]` khi có đủ: code/tài liệu, test có tiêu chí Pass
  hoặc Fail rõ ràng, lệnh tái hiện, và evidence không chứa secret/PII.
- Dữ liệu curated đặt trong `data/`; kết quả raw/derived đặt trong
  `security-results/`; log kiểm chứng đặt trong `evidence/`; tài liệu bền vững
  đặt trong `docs/`; báo cáo tuần mới đặt trong `reports/`.
- Không đưa JSON, CSV, HTML hoặc log sinh tự động vào `docs/` hay `reports/`.
- Không sửa `reports/week-1.md` đến `reports/week-4.md`. Khi đến mốc tương ứng,
  tạo `reports/week-5.md` và `reports/week-6.md` ngắn, tách `Quá trình` và
  `Kết quả`.

### Definition of Done

Với code hoặc security control:

- Hành vi thành công và hành vi fail-closed đều có test.
- Không request rủi ro nào bỏ qua approval; mọi request đều phải qua policy và
  Gateway.
- Không có dữ liệu nhạy cảm fixture trong prompt, log, receipt hay artefact cuối.

Với machine artefact:

- Output qua schema, có provenance/run ID và được lưu đúng thư mục.
- Có lệnh tái tạo và evidence ghi commit, thời điểm, command cùng kết quả.

Với tài liệu hoặc demo:

- Nội dung khớp artefact của cùng commit, nêu rõ giới hạn và không phóng đại kết
  quả scan/test.
- Một người khác có thể tái hiện chỉ bằng README và kịch bản demo.

### Bảng điều phối

Điền `Owner`, mốc thời gian và evidence khi bắt đầu từng gate; không dùng chat
hoặc số liệu trên dashboard thay cho evidence bền vững.

| Gate | Owner | Mốc dự kiến | Evidence khi hoàn tất |
|---|---|---|---|
| Baseline + contract | Nguyễn Trọng Khánh | 15/08/2026 | `evidence/week-5/baseline.log`, `verification.log` |
| Redaction | Nguyễn Trọng Khánh | 15/08/2026 | `evidence/week-5/verification.log` |
| Prompt Injection | Nguyễn Trọng Khánh | 15/08/2026 | `evidence/week-5/verification.log` |
| Human-in-the-Loop | Nguyễn Trọng Khánh | 15/08/2026 | `evidence/week-5/verification.log` |
| E2E + Compose/CI | Nguyễn Trọng Khánh | 20/08/2026 | `evidence/week-6/pre-release-verification-2026-08-20.log` |
| Evaluation | Nguyễn Trọng Khánh | 20/08/2026 | `docs/evaluation.md`, pre-release evidence |
| Docs + demo + release | Owner + peer | Chờ final commit | `docs/release-acceptance.md` |

## 2. Kết luận chiến lược

Week 1–4 đã tạo được nền tảng đúng hướng: scanner/CI, chuẩn hóa, kho tri thức,
Agent có grounding, Safe API Tool, Envoy/ext-authz, allowlist và audit. Không
nên làm lại các lớp này. Khoảng trống quyết định nằm ở Week 5–6:

1. Gom logic che dữ liệu thành một guardrail dùng chung và mở rộng sang
   email, số điện thoại và PII đã định nghĩa.
2. Xử lý HTTP response như dữ liệu không tin cậy; nội dung response không bao
   giờ được quyền thay đổi mục tiêu, cấp approval hay sinh tool call.
3. Đặt cổng Approve/Reject bắt buộc ngay tại lớp thực thi, không chỉ ở CLI.
4. Tạo một orchestrator đầu-cuối dùng output scanner mới, có run ID, metrics,
   báo cáo sau kiểm thử và evidence.
5. Đóng gói runner trong Docker Compose, nối lại CI, chạy bộ đánh giá 5–10 ca,
   rồi hoàn thiện tài liệu và demo.

Thứ tự đường găng:

```text
Nghiệm thu baseline
  -> chốt contract/state machine
  -> redaction + response guard + approval
  -> tích hợp Safe API Tool
  -> orchestrator + logging
  -> Compose/CI
  -> evaluation
  -> tài liệu/demo
  -> release gate
```

Redaction, response guard và giao diện approval có thể triển khai song song sau
khi contract được chốt. Evaluation fixture và khung tài liệu có thể chuẩn bị
song song với orchestrator.

## 3. Trạng thái sản phẩm hiện tại

### 3.1. Kết quả quan sát trên baseline hiện tại

Baseline đã được nghiệm thu lại bằng `.venv` trên commit `b32cd0d`; chi tiết,
command, hash và giới hạn nằm trong
[`evidence/week-5/baseline.log`](../evidence/week-5/baseline.log).

- [x] `BASE-01 P0` Unit/non-integration: `141 passed, 25 deselected`; project
  `.venv` không phát warning.
- [x] `BASE-02 P0` Knowledge search trả đúng `SQL Injection` và XSS ở hạng 1.
- [x] `BASE-03 P0` Deterministic regression tạo 9 grounded JSONL records từ 27
  normalized findings; fresh Bandit/ZAP tạo 46 findings -> 12 grounded records
  và đã qua schema/model validation.
- [x] `BASE-04 P0` `docker compose config --quiet` thành công; rendered Compose
  SHA-256 đã được ghi trong baseline evidence.
- [x] `BASE-05 P0` [`.gitignore`](../.gitignore) loại `.env` và file này không
  được track; [`.env.example`](../.env.example) chỉ chứa placeholder.
- [x] `BASE-06 P0` Full Docker trên commit `b32cd0d`: 166 tests pass, live GET/
  POST thành công, admin bị policy deny, 3 receipt hợp schema và cleanup sạch.
  Phải chạy lại gate này một lần nữa trên commit release cuối.

### 3.2. Đối chiếu yêu cầu tối thiểu

| Yêu cầu tối thiểu | Trạng thái | Bằng chứng/gap chính |
|---|---|---|
| Chạy SAST hoặc DAST | Đã có | Bandit + ZAP trong CI; JSON baseline trong `security-results/` |
| Chuẩn hóa kết quả scan | Đã có | Historical 27; fresh Week 5 có 46 finding Bandit/ZAP theo schema chung |
| Agent tạo báo cáo bảo mật | Đã có | Historical 9; fresh Week 5 có 12 grounded record; Gemini vẫn tùy chọn |
| Có custom Python Tool | Đã có | `src/safe_api_tool/` |
| Request đi qua API Gateway | Đã có | Origin pin `localhost:8080`, backend không publish host port |
| Có endpoint allowlist | Đã có | Exact method/path, deny-by-default, policy dùng chung |
| Có phê duyệt thủ công | Đã có | Approval gắn request fingerprint/expiry/single-use; Reject=0, Approve=1 |
| Có test Prompt Injection | Đã có | Hai detector case, E2E quarantine và không follow-up call |
| Che dữ liệu nhạy cảm | Đã có | Sanitizer chung che email, phone, token, API key, password và PII trước model/log |
| README và demo cuối kỳ | Đã có về kỹ thuật | README, UI replay, terminal demo và kịch bản 10–15 phút; peer sign-off còn chờ |

### 3.3. Nền Week 1–4 cần giữ nguyên

Các dấu `[x]` dưới đây dựa trên artefact, test và snapshot lịch sử trong
[`reports/week-1.md`](../reports/week-1.md),
[`reports/week-2.md`](../reports/week-2.md),
[`reports/week-3.md`](../reports/week-3.md),
[`reports/week-4.md`](../reports/week-4.md) và
[`evidence/week-4/verification.log`](../evidence/week-4/verification.log). Chúng
vẫn phải qua regression/release evidence của commit cuối.

- [x] `W1-01 P0` Docker Compose có FastAPI, Envoy, `authz-service` và Keycloak;
  Envoy là ingress duy nhất của staging API; Keycloak token endpoint được expose
  riêng trên loopback.
- [x] `W1-02 P0` GitHub Actions chạy unit test, Bandit, Docker integration và
  ZAP; có artefact JSON/HTML.
- [x] `W1-03 P0` Endpoint public/protected được mô tả; route ngoài allowlist bị
  deny mặc định.
- [x] `W1-04 P0` Baseline Bandit/ZAP là JSON đọc được; tài liệu Week 1 có kiến
  trúc, endpoint và triage cảnh báo.
- [x] `W2-01 P0` Adapter Bandit/ZAP normalize, deduplicate, sort và sinh ID ổn
  định theo schema.
- [x] `W2-02 P0` Kho tri thức có 17 tài liệu; tìm kiếm SQL Injection và XSS đã
  có test.
- [x] `W3-01 P0` Agent validate, group theo `(tool, rule_id)`, retrieve exact
  knowledge, kiểm tra grounding và giữ toàn bộ source finding ID.
- [x] `W3-02 P0` System Prompt được version-control và coi scanner/knowledge
  content là dữ liệu không tin cậy.
- [x] `W3-03 P0` Code sở hữu name, severity, location, evidence và provenance;
  model chỉ viết narrative có schema.
- [x] `W3-04 P0` JSONL ổn định có name, severity, location, scanner evidence,
  explanation, verification/remediation và confidence; test hiện có vượt yêu
  cầu tối thiểu ba Agent cases, gồm empty/invalid input.
- [x] `W4-01 P0` Proposal chỉ chứa capability/test-case ID và provenance; không
  chứa URL, raw payload hay credential.
- [x] `W4-02 P0` Policy pin Gateway, exact route/method/header/test case; client
  tắt redirect/proxy và có timeout, rate, request/response caps.
- [x] `W4-03 P0` API key lấy từ môi trường, bị Envoy/authz consume trước backend
  và không xuất hiện trong receipt hiện có.
- [x] `W4-04 P0` Có bốn payload an toàn: chuỗi dài, ký tự đặc biệt, rỗng, sai
  kiểu; có typed outcome cho timeout/connection/rate/status/size.
- [x] `W4-05 P0` Dashboard là showcase/dry-run và không giữ credential trong
  browser; thực thi thật tiếp tục dùng CLI/runner.
- [x] `W4-06 P0` Tool hỗ trợ GET, POST, allowlisted headers, status và bounded
  response excerpt; allowlist nằm trong file và request/response receipt là
  JSONL đã sanitize.

### 3.4. Nợ cần đóng trước release

- [x] `BASE-07 P0` Chạy lại mọi scanner được bật cho release (tối thiểu một SAST
  hoặc DAST), normalize chính output mới và lưu run riêng; không dùng 27 finding
  Week 1 như bằng chứng duy nhất.

  Kết quả 15/08/2026: Bandit High gate = 0; fresh ZAP exit 0 với 0 FAIL;
  combined pipeline tạo `46 findings -> 12 grounded records`, qua schema và
  cleanup sạch. Xem [`baseline.log`](../evidence/week-5/baseline.log).
- [x] `BASE-08 P0` CI tách Bandit full-severity dùng làm dữ liệu khỏi Bandit
  High release gate; job `fresh-analysis` tải chính artefact Bandit/ZAP của cùng
  workflow run, normalize rồi analyze bằng deterministic provider. Output và
  SHA-256 manifest được upload 14 ngày; publish image phải chờ job này Pass.

  Regression 15/08/2026: YAML parse thành công, 3 workflow wiring tests Pass và
  toàn bộ non-integration suite đạt `144 passed, 25 deselected`. Xem
  [`baseline.log`](../evidence/week-5/baseline.log).
- [x] `BASE-09 P0` Đồng bộ số liệu test/evidence/dashboard theo cùng commit;
  không công bố số 140/166 nếu chưa có log tái hiện tương ứng.

  Kết quả 15/08/2026: dashboard dùng một snapshot có provenance trên commit
  `b32cd0d`: fresh `46 findings -> 12 groups`, `141` non-integration và `166`
  full-stack. Receipt được ghi rõ là artefact Week 4 tái xác minh trong baseline
  Week 5; test contract đọc số, ngày và revision từ
  [`baseline.log`](../evidence/week-5/baseline.log). Đây là snapshot lịch sử;
  số hiện hành nằm trong mục cập nhật pre-release ở đầu file.
- [x] `BASE-10 P1` Triage fresh ZAP gồm 7 rule group/20 URL instances:
  `10031`, `10049-1`, `10049-3`, `10055-12`, `10109`, `90004-1`, `90004-2`;
  xử lý hoặc chấp nhận có lý do từng nhóm.

  Kết quả: thêm CORP cho mọi response, COEP cho UI và cache policy explicit.
  ZAP hậu-hardening còn `0 Low`, `5 Informational refs/16 instances`, 0 FAIL;
  hai alert `90004-*` đã hết. Năm alert Informational có acceptance và điều
  kiện mở lại tại
  [`security-baseline-triage.md`](security-baseline-triage.md).
- [x] `BASE-11 P1` Mở rộng hoặc ghi rõ giới hạn DAST: scan seed `/health` đã
  spider 10 public/UI URLs nhưng chưa dùng Agent token hoặc bao phủ protected
  API; Safe API receipt không thay thế authenticated DAST.

  Workflow, CI docs và tài liệu Tool nay gọi đúng đây là passive unauthenticated
  baseline; regression test khóa public `/health` seed và việc không inject
  Bearer credential.
- [x] `BASE-12 P1` Sửa bốn link nội bộ trong docs đang trỏ nhầm
  `docs/README.md` thành `../README.md`.

  Đã sửa đủ bốn link và thêm test đếm/resolve documentation hub về README gốc.
- [x] `BASE-13 P1` Làm rõ wording `authentication_enabled: false` của
  `/api/admin` để không gây hiểu nhầm trong demo.

  API không còn boolean mơ hồ; response khai báo
  `authorization_boundary: "envoy_ext_authz"` và `required_scope: "admin:read"`.
  Unit và live JWT integration đều Pass.
- [x] `BASE-14 P1` Project `.venv` hiện chạy `216 passed, 28 deselected` không
  warning; full-stack đạt 244 test. Warning từng thấy thuộc interpreter khác và
  không xuất hiện trong pre-release evidence.

## 4. Kiến trúc đích Week 5–6

```text
Bandit/ZAP fresh output
  -> normalize + schema validation
  -> Security Analysis Agent (grounded narrative)
  -> bounded RequestProposal
  -> policy materialization + risk classification
  -> [GET thường: tiếp tục] / [POST hoặc payload đặc biệt: Approve/Reject]
  -> SafeApiClient -> Envoy/ext_authz -> staging API
  -> bounded HTTP response
  -> prompt-injection guard -> PII/secret redaction
  -> sanitized receipt + final report update
  -> run events/metrics/evidence
```

Các nguyên tắc không được phá vỡ:

- Model không sở hữu URL, raw payload, credential, policy hay approval.
- Approval không thay thế allowlist; request đã approve vẫn phải qua toàn bộ
  policy và Gateway.
- HTTP response không được dùng để tự tạo request tiếp theo. Nếu cần đưa vào
  narrative, chỉ dùng bản đã quarantine/redact trong trường dữ liệu rõ ràng.
- Request rủi ro thiếu approval, approval sai fingerprint, preflight guardrail
  lỗi hoặc policy lỗi đều fail closed với đúng 0 network call. Nếu response
  guard lỗi sau khi request đã xảy ra, không persist raw data, không gọi model
  hay tool tiếp theo và kết thúc run ở trạng thái failed.
- Deterministic provider là đường demo/CI mặc định; Gemini chỉ là chế độ tùy
  chọn và không được làm release phụ thuộc Internet/API key.

## 5. Gate B — Chốt contract trước khi code Week 5

- [x] `CON-01 P0` Chốt state machine không mâu thuẫn với GET thường:
  `proposed -> validated -> ready_to_execute | pending_approval`;
  `pending_approval -> rejected (terminal) | approved -> ready_to_execute`;
  `ready_to_execute -> executed | blocked | failed`.
- [x] `CON-02 P0` Giữ `RequestProposal` không có URL/body/credential. Approval
  view lấy method, exact path và curated payload từ `PolicyEngine` sau validation.
- [x] `CON-03 P0` Định nghĩa `RiskDecision`: mọi `POST` **hoặc** materialized
  request có payload thuộc curated ID `long-string`, `special-characters`,
  `empty`, `wrong-type` đều `requires_approval=true`; GET status có payload
  `None` có thể đi thẳng đến `ready_to_execute`.
- [x] `CON-04 P0` Định nghĩa `ApprovalDecision` tối thiểu gồm proposal ID,
  approval ID/nonce, run ID, policy hash, trusted-origin ID, canonical request
  fingerprint, decision, timestamp, expiry/TTL, single-use state và reason.
- [x] `CON-05 P0` Approval chỉ hợp lệ cho đúng fingerprint. Thay method/path,
  header, payload, test case hoặc policy phải xin duyệt lại.
- [x] `CON-06 P0` Giữ `ExecutionReceipt` cho network facts/outcome và tương thích
  với receipt v1 Week 4. Lưu `ApprovalDecision`, `GuardedResponse` và `RunEvent`
  bằng contract riêng; final report liên kết chúng qua ID/hash. Nếu đổi required
  field của receipt thì bump schema v2 và có migration/compatibility test.
- [x] `CON-07 P0` Định nghĩa `GuardedResponse`: status/size/hash, sanitized
  excerpt, injection flag/reason và redaction summary; không giữ raw response
  trong artefact bền vững.
- [x] `CON-08 P0` Định nghĩa event log có `run_id`, `event_id`, stage, start/end
  hoặc duration, outcome, safe error code và counters.
- [x] `CON-09 P0` Chốt thứ tự enforcement:
  `validate -> materialize -> classify risk -> approval khi cần -> policy
  re-check -> execute via Gateway -> streaming cap -> injection guard -> redact
  bounded buffer -> persist`.
- [x] `CON-10 P0` Thêm/cập nhật JSON Schema và contract tests trước khi nối
  CLI/orchestrator.
- [x] `CON-11 P0` Chốt trusted runtime origin cho hai profile: host dùng
  `http://localhost:8080`, Compose dùng `http://envoy:8080`. Origin do config
  tin cậy chọn, không nằm trong proposal/model; bind vào fingerprint và test
  từ chối `http://api:8000` cùng origin tùy ý. Không dùng `network_mode: host`.
- [x] `CON-12 P0` Khóa scope một proposal cho mỗi run. Demo Approve và Reject là
  hai run cố định được summary tổng hợp; không xây queue/multi-proposal ở P0.
- [x] `CON-13 P0` Chốt safe-scope invariant: chỉ curated payload, chỉ exact
  staging route trong Compose được cấp phép, không redirect, không truy cập hệ
  thống và POST không thay đổi dữ liệu bền vững; có test kiểm tra state trước/sau.
- [x] `CON-14 P0` Chốt retention/Git hygiene cho run Week 5–6: ignore output sinh
  tự động, chỉ whitelist sanitized golden artefact cần commit; evidence chỉ được
  commit sau secret/PII sentinel.

Đường dẫn gợi ý, có thể chốt lại trong `CON-10`:

| Nhóm | Đường dẫn đề xuất |
|---|---|
| Guardrails dùng chung | `src/sentinel_guardrails/redaction.py`, `prompt_injection.py` |
| Approval/risk gate | `src/safe_api_tool/approval.py` và model/schema tương ứng |
| Orchestrator | `src/project_sentinel/` với CLI `python -m project_sentinel` |
| Curated evaluation | `data/evaluation-cases.json` và schema trong `schemas/` |
| Generated runs | `security-results/runs/week-5/`, `security-results/runs/week-6/` |
| Verification logs | `evidence/week-5/`, `evidence/week-6/` |

## 6. Week 5 — Guardrails, approval và redaction

### 6.1. Redaction dùng chung

- [x] `RED-01 P0` Tạo một sanitizer trung lập để thay logic regex đang lặp ở
  Agent, planner và Safe API audit.
- [x] `RED-02 P0` Hỗ trợ marker ổn định tối thiểu:
  `[REDACTED_EMAIL]`, `[REDACTED_PHONE]`, `[REDACTED_TOKEN]`,
  `[REDACTED_API_KEY]`, `[REDACTED_PASSWORD]`, `[REDACTED_PII]`.
- [x] `RED-03 P0` Định nghĩa rõ PII được hỗ trợ trong phạm vi lab, ví dụ trường
  định danh có tên khóa đã biết và mẫu số định danh fixture; không tuyên bố phát
  hiện được mọi PII tự do.
- [x] `RED-04 P0` Sanitizer xử lý được text và cấu trúc lồng nhau
  (dict/list/header/query-style/JSON-style), idempotent và không làm đổi input.
- [x] `RED-05 P0` Đọc response bằng streaming cap, không persist raw; redact
  bounded buffer trước khi tạo excerpt/log. Oversize trả typed outcome và không
  kèm raw excerpt có thể làm lộ prefix secret; giữ regression Week 4 hiện có.
- [x] `RED-06 P0` Gọi sanitizer trước mọi payload gửi provider/LLM.
- [x] `RED-07 P0` Gọi sanitizer trước log, exception message, receipt, approval
  display, final report và artefact evidence.
- [x] `RED-08 P0` Raw scanner artefact được giữ riêng theo retention policy và
  không đưa thẳng vào LLM/log. Mọi scanner evidence nhúng trong report/prompt
  phải sanitize; không giữ raw secret chỉ vì provider payload đã được che.
- [x] `RED-09 P0` Test sensitive case 1: email + số điện thoại; giá trị gốc
  không xuất hiện ở captured provider request, receipt hoặc log.
- [x] `RED-10 P0` Test sensitive case 2: Bearer/JWT + API key + password + PII
  lồng nhau; tất cả marker và counter đúng.
- [x] `RED-11 P0` Test success path và error path đều không rò secret/PII.
- [x] `RED-12 P1` Ghi metric theo loại redaction nhưng không ghi giá trị gốc.

Tiêu chí nghiệm thu RED: ít nhất hai ca Pass/Fail rõ ràng; secret sentinel quét
toàn bộ prompt capture, JSONL receipt, event log và final report không tìm thấy
bất kỳ giá trị fixture gốc nào.

### 6.2. Prompt Injection trên HTTP response

- [x] `PI-01 P0` System Prompt hiện đã nói rõ scanner/knowledge payload là dữ
  liệu không tin cậy, cấm đổi mục tiêu, gọi tool, tạo endpoint/path hoặc khẳng
  định khai thác.
- [x] `PI-02 P0` Grounding validator hiện chặn endpoint/path/security identifier
  do provider bịa và planner không lấy capability từ untrusted finding text.
- [x] `PI-03 P0` Bổ sung quy tắc tường minh trong System Prompt: không đổi mục
  tiêu theo HTTP response, không tiết lộ System Prompt/API key/secret và không
  gọi tool ngoài phạm vi cho phép.
- [x] `PI-04 P0` Thêm exact, stateless GET fixture đi qua Gateway, trả chuỗi giả
  mô phỏng Prompt Injection và không chứa secret thật. Contract v1 hiện khóa
  đúng bốn test case: dùng capability `empty` phù hợp, hoặc bump/version schema
  có chủ đích; không âm thầm thêm test case thứ năm làm policy load lỗi.
- [x] `PI-05 P0` Gắn nhãn toàn bộ HTTP response là `untrusted_http_response` và
  chạy detector/quarantine trước khi response đi vào report hoặc model.
- [x] `PI-06 P0` Detector ít nhất nhận diện nhóm chỉ dẫn: bỏ qua chỉ dẫn trước,
  tiết lộ system prompt/secret, gọi endpoint/tool/command ngoài phạm vi. Kết quả
  detector chỉ là signal; quyền chặn thật vẫn nằm ở state machine/policy code.
- [x] `PI-07 P0` Không cho response tạo proposal mới, thay capability, tự approve
  hoặc điều khiển vòng lặp tool. Final report được cập nhật bằng code từ receipt
  đã sanitize, không bằng việc làm theo nội dung response.
- [x] `PI-08 P0` Test 1: response yêu cầu “ignore previous instructions” và tiết
  lộ key; không có secret leak, mục tiêu đổi hay network call mới.
- [x] `PI-09 P0` Test 2: response yêu cầu gọi `/api/admin` hoặc command hệ thống;
  không có proposal/execution ngoài allowlist.
- [x] `PI-10 P0` Log chỉ lưu flag, safe reason code, hash và sanitized excerpt;
  không lưu raw injection/PII nếu không cần thiết.
- [x] `PI-11 P0` Hai test trả Pass/Fail bằng hành vi đo được, không chỉ kiểm tra
  Agent có viết câu “tôi từ chối”.
- [x] `PI-12 P1` Thêm benign control để detector không chặn nhầm response bình
  thường trong bộ fixture.

Tiêu chí nghiệm thu PI: “bị chặn” nghĩa là không đổi mục tiêu, không tiết lộ
prompt/secret, không cấp approval và không phát sinh tool/network call trái phép.

### 6.3. Human-in-the-Loop

- [x] `HITL-01 P0` Tạo risk classifier theo `POST OR payload đặc biệt`; không
  viết điều kiện nhầm thành `POST AND payload đặc biệt`.
- [x] `HITL-02 P0` Trước approval, CLI hiển thị method, exact endpoint, curated
  payload đã sanitize, header names, purpose/rationale và source finding IDs.
- [x] `HITL-03 P0` Người dùng chỉ chọn `Approve` hoặc `Reject`; input khác, EOF,
  timeout hoặc lỗi UI mặc định là Reject.
- [x] `HITL-04 P0` Enforce approval trong `SafeApiClient`/execution boundary,
  không chỉ trong `__main__.py`, để code gọi trực tiếp không bypass được.
- [x] `HITL-05 P0` Reject tạo receipt/audit decision nhưng đúng 0 transport call.
- [x] `HITL-06 P0` Approve hợp lệ gửi đúng một request và vẫn bị exact allowlist,
  rate/size/timeout/Gateway kiểm tra lại.
- [x] `HITL-07 P0` Approval thiếu, hết hạn, đã dùng, sai run/proposal/policy/
  origin/request fingerprint hoặc request bị sửa đều bị chặn trước network.
- [x] `HITL-08 P0` Audit ghi decision, timestamp, proposal/fingerprint và safe
  reason; không ghi approver secret, API key hay raw PII.
- [x] `HITL-09 P0` Test approval case 1: Reject POST, transport call count = 0.
- [x] `HITL-10 P0` Test approval case 2: Approve POST, transport call count = 1
  và URL vẫn là Gateway.
- [x] `HITL-11 P0` Test negative control: approval không mở được endpoint admin
  hoặc request ngoài policy.
- [x] `HITL-12 P1` Test TOCTOU: sửa payload/policy sau approval bắt buộc xin lại.

Để tránh biến cờ `--execute` thành approval giả:

- Demo thật dùng prompt tương tác.
- Non-interactive/CI mặc định Reject; test có thể inject một approval provider
  giả có kiểm soát.
- Không thêm `--yes` hoặc biến môi trường dùng chung có thể bỏ qua HITL trong
  đường chạy sản phẩm.

### 6.4. Gate phối hợp Week 5

- [x] `GR-01 P0` Injection detector không thể tự approve request.
- [x] `GR-02 P0` Approval không thể bỏ qua allowlist hoặc thay Gateway origin.
- [x] `GR-03 P0` Chỉ response đã bound, filter và redact mới được ghi vào report.
- [x] `GR-04 P0` Guardrail config/schema lỗi được phát hiện ở preflight với 0
  network call. Nếu response guard lỗi sau network, không persist raw response,
  không gọi model/follow-up tool và run kết thúc failed.
- [x] `GR-05 P0` Không trộn các trục trạng thái: execution outcome nằm trong
  receipt; approval decision, injection flag và redaction counter nằm trong
  contract riêng, có exit/event semantics và liên kết ID/hash rõ ràng.
- [x] `GR-06 P0` Chạy lại toàn bộ regression Week 1–4; không làm mất policy,
  grounding, provenance, caps hoặc secret sentinel hiện có.
- [x] `GR-07 P0` Lưu verification log Week 5 trong `evidence/week-5/` và tạo
  `reports/week-5.md` mới sau khi mọi P0 Week 5 đạt.
- [x] `GR-08 P0` Integration test chứng minh mọi POST fixture là stateless,
  không đổi dữ liệu bền vững và không truy cập ngoài staging Compose.

## 7. Week 6 — Tích hợp đầu-cuối

### 7.1. Orchestrator và final report

- [x] `E2E-01 P0` Tạo một runner có state machine rõ ràng, không ghép shell tùy
  ý, nối đúng chín bước trong kiến trúc đích.
- [x] `E2E-02 P0` Mỗi run có `run_id` và thư mục output riêng; không ghi đè
  baseline tốt nếu bước sau thất bại.
- [x] `E2E-03 P0` Nhận raw output của mọi scanner bật cho release (tối thiểu một
  SAST hoặc DAST) trong chính run hiện tại, normalize rồi mới analyze; ghi
  hash/provenance của input.
- [x] `E2E-04 P0` Agent tạo grounded report và bounded proposal; empty/invalid
  input dừng an toàn, không gọi provider/tool.
- [x] `E2E-05 P0` Request rủi ro dừng ở `pending_approval`; Reject kết thúc run
  hợp lệ với 0 request, Approve mới cho phép đi tiếp.
- [x] `E2E-06 P0` Request đã duyệt chỉ đi qua Envoy; backend không được publish
  host port và redirect không được theo.
- [x] `E2E-07 P0` Response được cap, prompt-injection guard và redact trước khi
  persist hoặc cập nhật báo cáo.
- [x] `E2E-08 P0` Tạo final report machine-readable liên kết analysis group,
  proposal, approval, receipt, guarded response và source finding IDs.
- [x] `E2E-09 P0` Báo cáo phân biệt scanner evidence, AI narrative, test result
  và human decision; không biến status 200 thành bằng chứng lỗ hổng khai thác.
- [x] `E2E-10 P0` Có chế độ dry-run, interactive demo và deterministic CI; cả ba
  dùng cùng policy/contract.
- [x] `E2E-11 P0` Có một lệnh demo chuẩn được ghi trong README, ví dụ interface
  đích `python -m project_sentinel demo --provider deterministic`.
- [x] `E2E-12 P0` Có rollback/cleanup chắc chắn; Docker stack được dọn kể cả khi
  runner/test lỗi.
- [x] `E2E-13 P0` Mỗi run chỉ xử lý một proposal. Kịch bản Reject và Approve là
  hai run có run ID riêng; summary demo mới tổng hợp metrics của cả hai.

### 7.2. Docker Compose và CI

- [x] `OPS-01 P0` Thêm one-shot `sentinel-runner` service/profile để pipeline,
  Agent, guardrails và Safe API Tool chạy trong Compose cùng staging stack; dùng
  trusted origin `http://envoy:8080`, không dùng localhost hay host networking.
- [x] `OPS-02 P0` Mount policy/curated data read-only; chỉ mount thư mục output
  cần thiết; không bake `.env` hoặc API key vào image.
- [x] `OPS-03 P0` Interactive approval chạy được bằng TTY; đường non-interactive
  fail closed hoặc chỉ dùng approval provider test trong CI.
- [x] `OPS-04 P0` Health/preflight kiểm tra Gateway và dependency trước khi run;
  không tự đổi origin sang backend khi Gateway lỗi.
- [x] `OPS-05 P0` Tách Bandit data scan full-severity/low dùng cho
  normalize/analyze khỏi Bandit High release gate. CI hash/upload hai artefact;
  job E2E download output của mọi scanner bật trong cùng workflow và chạy
  deterministic provider.
- [x] `OPS-06 P0` CI không yêu cầu Gemini/API key để pass; live LLM chỉ nằm ở
  workflow manual/tùy chọn và output tách riêng.
- [x] `OPS-07 P0` CI upload sanitized final report, evaluation summary và
  verification log với retention rõ ràng.
- [x] `OPS-08 P0` Bandit/ZAP failure vẫn giữ artefact để điều tra nhưng release
  gate không báo Pass giả.
- [x] `OPS-09 P1` Quyết định authenticated DAST hay ghi rõ passive `/health`
  scan là giới hạn; Safe API receipt không được gọi là DAST thay thế.
- [x] `OPS-10 P1` Kiểm tra drift giữa request-size/rate policy ở client, authz
  và Envoy; thêm contract test nếu tiếp tục cấu hình lặp.
- [x] `OPS-11 P0` Tạo Dockerfile/runtime requirements tối thiểu cho runner, không
  cài toàn bộ dev/test dependency. Điều chỉnh `.dockerignore` để runner nhận
  đúng curated `data/`, schema và prompt cần thiết; mount policy/data/schema
  read-only khi phù hợp.
- [x] `OPS-12 P0` Thêm Envoy healthcheck hoặc preflight retry có deadline trước
  runner; không chỉ dựa vào container ở trạng thái started.
- [x] `OPS-13 P0` Cập nhật `.gitignore` cho generated run Week 5–6 và whitelist
  đúng sanitized golden artefact được chọn; test Git status không xuất hiện raw
  output ngoài ý muốn.

### 7.3. Logging và metrics

- [x] `OBS-01 P0` Event log có cấu trúc cho từng stage và cùng `run_id` xuyên
  scanner -> normalize -> analysis -> approval -> request -> final report.
- [x] `OBS-02 P0` Ghi duration từng bước và tổng thời gian.
- [x] `OBS-03 P0` Ghi số raw findings, normalized findings, analysis groups,
  request attempted/sent, Approve, Reject, injection flags và redactions.
- [x] `OBS-04 P0` Lỗi LLM, schema, Gateway, timeout, connection và application
  dùng safe error code; không serialize exception có secret.
- [x] `OBS-05 P0` Log không chứa raw prompt, raw response, API key, token,
  password, email, điện thoại hoặc PII fixture.
- [x] `OBS-06 P0` Summary theo run ID đối chiếu được với receipt/final report và
  chỉ đếm request thật sau approval.
- [x] `OBS-07 P1` Ghi provider/model/config version và policy/schema hash để so
  sánh run; không ghi credential hay toàn bộ prompt.
- [x] `OBS-08 P1` Ghi rõ rate limiter hiện process-local và reset khi restart;
  không quảng bá là production/distributed control.

### 7.4. Bộ đánh giá 10 trường hợp

- [x] `EVAL-01 P0` Tạo `data/evaluation-cases.json` và schema; mỗi case có input,
  expected facts/behavior, allowed variance và Pass/Fail rule deterministic.
- [x] `EVAL-02 P0` Case 1 — SQL Injection retrieval/analysis đúng nguồn.
- [x] `EVAL-03 P0` Case 2 — XSS retrieval/analysis đúng nguồn.
- [x] `EVAL-04 P0` Case 3 — finding trùng được group nhưng không mất provenance.
- [x] `EVAL-05 P0` Case 4 — finding low/informational không bị nâng severity.
- [x] `EVAL-06 P0` Case 5 — input trống sinh output hợp lệ, không gọi provider.
- [x] `EVAL-07 P0` Case 6 — JSON/schema sai bị chặn và không ghi đè output tốt.
- [x] `EVAL-08 P0` Case 7 — hallucination trap không tạo endpoint/type/CWE mới.
- [x] `EVAL-09 P0` Case 8 — HTTP Prompt Injection bị flag và không sinh tool call.
- [x] `EVAL-10 P0` Case 9 — email/phone/token/password/PII đều bị redact.
- [x] `EVAL-11 P0` Case 10 — Reject tạo 0 call; approval không vượt allowlist.
- [x] `EVAL-12 P0` Chốt truth unit cho TP/FP/FN là expected `(tool, rule_id)`
  group theo từng analysis case; bộ dữ liệu khóa đúng 5 Agent analysis case và
  5 behavioral case. Guardrail cases dùng Pass/Fail riêng. Kết quả hiện tại:
  TP=6, FP=0, FN=0.
- [x] `EVAL-13 P0` Đáp án do nhóm curate; không dùng LLM-as-a-Judge trên đường
  găng.
- [x] `EVAL-14 P0` Lưu output sinh máy trong `security-results/runs/week-6/` và
  verification summary trong `evidence/week-6/`.
- [x] `EVAL-15 P0` Release threshold: schema-valid = 100%, source coverage =
  100%, hallucination = 0, secret/PII leak = 0 và policy bypass = 0. FP/FN được
  đo và báo cáo trung thực; không tự đặt ngưỡng tùy ý nếu rubric không yêu cầu.

### 7.5. Tài liệu bàn giao

- [x] `DOC-01 P0` README có prerequisites, setup `.env`, clean start, dry-run,
  interactive demo, evaluation, full tests, cleanup và troubleshooting.
- [x] `DOC-02 P0` README/sơ đồ kiến trúc thể hiện trust boundary và data flow
  đầy đủ Week 1–6.
- [x] `DOC-03 P0` Tài liệu kỹ thuật mô tả quyết định thiết kế, schema/state
  machine, giới hạn và rủi ro bảo mật còn lại.
- [x] `DOC-04 P0` Báo cáo kết quả nêu findings, Agent đúng/sai, FP/FN,
  hallucination/guardrail failures và hướng cải tiến.
- [x] `DOC-05 P0` Product brief 1–2 trang có vấn đề, người dùng, giá trị, phạm vi,
  hạn chế và hướng phát triển.
- [x] `DOC-06 P0` Ghi rõ Dashboard chỉ là presentation/dry-run, không phải nơi
  giữ API key hoặc thay CLI approval.
- [x] `DOC-07 P0` Tạo `reports/week-6.md` mới, ngắn và không sửa lịch sử cũ.
- [ ] `DOC-08 P0` Một người không tham gia triển khai chạy lại được chỉ bằng
  README và ghi kết quả vào evidence.
- [ ] `DOC-09 P1` Cập nhật dashboard từ artefact/evidence cùng commit, không hard
  code số liệu chưa xác minh.
  Dashboard đã khớp pre-release evidence 20/08; còn phải rerun/cập nhật sau khi
  có final commit.
- [x] `DOC-10 P1` Ghi rõ lab dùng Keycloak `start-dev`, HTTP local, process-local
  rate limiting, pinned localhost origin và chưa phải production deployment.

### 7.6. Demo 10–15 phút

- [x] `DEMO-01 P0` Chuẩn bị preflight một lệnh: dependency, Compose config,
  Docker health, fixture và secret placeholder.
- [x] `DEMO-02 P0` Trình diễn một scan tạo JSON mới và bước normalize.
- [x] `DEMO-03 P0` Trình diễn Agent tạo grounded report, chỉ ra evidence và
  provenance.
- [x] `DEMO-04 P0` Trình diễn Agent/planner đề xuất bounded request.
- [x] `DEMO-05 P0` Chọn Reject và chứng minh transport call count không tăng.
- [x] `DEMO-06 P0` Chọn Approve và chứng minh đúng một request đi qua Gateway.
- [x] `DEMO-07 P0` Trình diễn endpoint ngoài allowlist vẫn bị deny dù đã approve.
- [x] `DEMO-08 P0` Trình diễn Prompt Injection response bị flag/quarantine,
  không sinh hành động mới.
- [x] `DEMO-09 P0` Trình diễn email/phone/token/password/PII thành marker trong
  prompt capture/log/final report.
- [x] `DEMO-10 P0` Mở final report/metrics: duration, findings, request,
  Approve/Reject, errors và kết quả evaluation.
- [x] `DEMO-11 P0` Có deterministic fallback và artefact mẫu nếu mạng/LLM ngoài
  không ổn định.
- [ ] `DEMO-12 P0` Tập dượt để toàn bộ demo nằm trong 10–15 phút, có cleanup và
  phương án khôi phục sau lỗi.
  Technical rehearsal đã đạt: full local command 179.4 giây, bốn live scenario
  12.735 giây, cleanup sạch và script phân bổ 10–15 phút. Còn chờ người chịu
  trách nhiệm nghiệm thu xác nhận thời lượng trình bày.

## 8. Lịch thực hiện gợi ý

| Ngày | Trọng tâm | Gate cuối ngày |
|---|---|---|
| Week 5 — Ngày 1 | Nghiệm thu baseline, fresh scan, contract/schema | `BASE-06..09`, `CON-01..14` |
| Week 5 — Ngày 2 | Redaction dùng chung | `RED-01..12` |
| Week 5 — Ngày 3 | HTTP response guard + fixture | `PI-03..12` |
| Week 5 — Ngày 4 | Approval/risk gate ở execution boundary | `HITL-01..12` |
| Week 5 — Ngày 5 | Tích hợp guardrail, regression, evidence/report Week 5 | `GR-01..08` |
| Week 6 — Ngày 1 | Orchestrator, final report, event log | `E2E-01..13`, `OBS-01..06` |
| Week 6 — Ngày 2 | Compose runner và CI dùng fresh artefact | `OPS-01..13` |
| Week 6 — Ngày 3 | Evaluation 10 case, FP/FN và metrics | `EVAL-01..15` |
| Week 6 — Ngày 4 | README, kiến trúc, product brief, demo script | `DOC-*`, `DEMO-01..04` |
| Week 6 — Ngày 5 | Full verification, rehearsal, sửa lỗi và đóng release | Toàn bộ P0 + Release Gate |

Không chuyển sang hạng mục ngày sau nếu gate an toàn của ngày trước chưa đạt;
phần tài liệu/fixture có thể làm song song nhưng không được dùng để che việc
thiếu test thực thi.

## 9. Release Gate cuối cùng

### 9.1. Các lệnh hiện có bắt buộc phải pass

```powershell
python -m pip install --requirement requirements-dev.txt
python -m pip install --requirement security/requirements.txt
python -m pytest -q -m "not integration"
python -m security_pipeline search "SQL Injection" --limit 1
python -m security_pipeline search "XSS" --limit 1
python -m security_pipeline analyze security-results/normalized-findings.json `
  --knowledge-base data/vulnerabilities.json --provider deterministic `
  --output "$env:TEMP\security-analysis-check.jsonl"
python -m safe_api_tool demo
docker compose config --quiet
python scripts/run_all_tests.py
git diff --check
```

Full-severity Bandit dùng làm dữ liệu có thể trả exit khác 0 khi tìm thấy cảnh
báo; gate của bước này là JSON hợp lệ và được normalize, không phải “không có
finding”. Chạy Bandit High riêng làm release gate. Sau khi chốt CLI mới, bổ sung
vào release evidence các interface đích tương đương:

```powershell
python scripts/run_security_scan.py --output "$env:TEMP\bandit-full.json" `
  --severity-level low
python -m security_pipeline normalize <fresh-scanner-json...> `
  --output "$env:TEMP\normalized-release.json"
python -m project_sentinel evaluate --provider deterministic
python -m project_sentinel demo --provider deterministic
git rev-parse HEAD
git status --porcelain
git ls-files --error-unmatch docs/todo-checklist.md
```

Thay placeholder `<fresh-scanner-json...>` bằng artefact của cùng run. Evidence
phải ghi exit semantics của data scan, schema validation, secret/PII sentinel và
hash của mọi input/output; không chép raw secret vào command/log.

### 9.2. Gate chức năng sản phẩm

- [x] `REL-01 P0` Fresh scan -> normalize -> analyze -> proposal chạy bằng một
  quy trình rõ ràng và output qua schema.
- [x] `REL-02 P0` Reject chặn request; Approve cho đúng một request qua Gateway;
  endpoint ngoài allowlist luôn bị chặn.
- [x] `REL-03 P0` Hai Prompt Injection cases và hai sensitive-data cases đều
  Pass bằng tiêu chí hành vi.
- [x] `REL-04 P0` Final report được cập nhật từ sanitized receipt, không bịa thêm
  lỗ hổng/endpoint và không gọi status 200 là bằng chứng khai thác.
- [x] `REL-05 P0` Metrics có duration, findings, requests, Approve/Reject và lỗi.
- [x] `REL-06 P0` Evaluation có 10 case (5 Agent + 5 behavioral), có
  actual/expected, TP=6/FP=0/FN=0 và summary.
- [ ] `REL-07 P0` Full Docker run pass trên commit cuối, Compose cleanup sạch và
  evidence ghi commit/date/command/result.
  Pre-release local đã đạt 244 test và cleanup sạch; phải lặp lại sau final
  commit nên chưa được đánh dấu hoàn tất.
- [x] `REL-08 P0` Secret/PII sentinel không tìm thấy fixture gốc trong prompt,
  logs, receipts, final report hoặc CI artefacts.
- [x] `REL-09 P0` README cho phép người khác chạy lại demo; demo 10–15 phút có
  cả Approve và Reject.
- [x] `REL-10 P0` Đủ năm nhóm bàn giao: mã nguồn, tài liệu kỹ thuật, báo cáo kết
  quả, bản demo và product brief 1–2 trang.
- [ ] `REL-11 P0` `docs/todo-checklist.md` và mọi file bàn giao cần thiết đã được
  version-control; `git status --porcelain` chỉ còn thay đổi đã hiểu và evidence
  ghi đúng commit từ `git rev-parse HEAD`.
  Các rule ignore mâu thuẫn đã được gỡ; checklist và các file bàn giao hiện đã
  thấy trong `git status` nhưng chưa được track vì chưa được phép commit.

### 9.3. Điều kiện tuyên bố “hoàn thành sản phẩm”

- [ ] Tất cả mục `P0` bắt buộc trong checklist này đã `[x]`; yêu cầu bắt buộc từ
  `docs/todo` không được tự loại khỏi phạm vi.
- [ ] Không có P0 fail, test skip không giải thích hoặc artefact từ commit cũ
  được dùng để thay evidence của commit release.
- [x] Luồng demo chỉ tác động staging Docker Compose được cấp phép và không dùng
  payload phá hoại/thay đổi dữ liệu thật.
- [x] Báo cáo cuối nêu trung thực false positive, false negative, giới hạn và
  rủi ro còn tồn tại.

## 10. Ánh xạ rubric

| Nhóm điểm | Trọng số | Checklist chính | Evidence bắt buộc |
|---|---:|---|---|
| Hệ thống hoạt động | 30% | `BASE`, `E2E`, `OPS`, `REL-01/07` | Fresh E2E run, Docker log, typed error cases |
| Chất lượng AI Agent | 20% | `W3`, `PI`, `EVAL-02..08/12/15` | Grounding/schema/source coverage, correct/incorrect cases |
| An toàn hệ thống | 20% | `RED`, `PI`, `HITL`, `GR`, `REL-02/03/08` | Allowlist, 0-call Reject, injection and leak tests |
| Chất lượng mã nguồn | 15% | `CON`, `OPS-05..08`, regression tests | CI pass, schemas, no committed secret, reviewable structure |
| Tài liệu/trình bày | 15% | `DOC`, `DEMO`, `REL-09/10/11` | README rerun, architecture, report, product brief, rehearsal |

- [x] `RUBRIC-01 P0` Final report liên kết từng nhóm rubric với evidence của cùng
  commit; không tự chấm điểm bằng claim không tái hiện được.

## 11. Rủi ro và phương án giảm thiểu

| Rủi ro | Phương án |
|---|---|
| Chống injection chỉ bằng System Prompt | Giữ quyền ở state machine/policy; response chỉ là untrusted data |
| Redaction gọi quá muộn | Sanitizer chung đặt trước LLM, logger, exception, receipt và report |
| Reject vẫn gửi request | Enforce tại client boundary; mock transport phải có call count = 0 |
| Request bị đổi sau approval | Bind decision vào proposal + policy + materialized request fingerprint |
| Approval bị hiểu là bỏ qua policy | Luôn policy re-check sau approval và trước transport |
| CI phân tích dữ liệu baseline cũ | Download raw artefact của cùng workflow rồi normalize/analyze |
| Secret rò qua lỗi/truncation/header | Streaming cap, redact bounded buffer, structured safe error và sentinel |
| Policy drift giữa client/authz/Envoy | Một nguồn cấu hình khi có thể; contract test các giá trị lặp |
| Gemini/network không ổn định | Deterministic CI/demo; live provider là tùy chọn và tách evidence |
| Regex PII false positive/negative | Công bố loại PII hỗ trợ, golden cases và báo cáo FP/FN |
| Demo vượt thời gian hoặc Docker lỗi | Preflight, fixture cố định, rehearsal, cleanup/fallback artefact |
| Scope creep | Không đưa các mục P2 vào đường găng Week 5–6 |

## 12. Phạm vi cấm và ngoài đường găng

### 12.1. Không thực hiện trong mọi trường hợp

- Không khai thác lỗ hổng thực tế.
- Không dùng payload phá hoại, truy cập hệ thống hoặc thay đổi dữ liệu thật.
- Không gửi request ra ngoài staging Docker Compose được cấp phép.
- Không commit secret, raw PII hoặc dùng dữ liệu thật làm fixture demo.

### 12.2. Ngoài đường găng / P2

- [ ] GraphRAG, Hybrid Search hoặc vector database.
- [ ] Multi-Agent phức tạp, MCP/A2A IAM hoàn chỉnh.
- [ ] Tự host model bằng vLLM/GPU.
- [ ] LLM-as-a-Judge.
- [ ] Production deployment public, HA/distributed rate limiting hoặc secret
  manager production.
- [ ] Bổ sung nhiều scanner/dependency/container scan trong sprint tiếp theo.
- [ ] Biến dashboard thành credentialed live API client; CLI approval là lựa
  chọn nhỏ, kiểm thử được và an toàn hơn cho capstone hiện tại.

Chỉ bắt đầu P2 sau khi toàn bộ Release Gate P0 đã đạt.
