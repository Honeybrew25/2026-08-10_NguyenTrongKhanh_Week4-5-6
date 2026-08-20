# Project Sentinel dashboard

> Dashboard trình bày chuỗi Week 1 → Week 6 từ snapshot evidence đã xác minh. Bắt đầu tại
> [documentation hub](../README.md) để xem source, artifact và kịch bản demo.

## Mục tiêu

Dashboard biến flow Week 1–6 thành một trang có thể trình bày trong buổi demo.
Phần E2E cho xem lại bốn lần chạy mẫu theo từng bước nhưng không phê duyệt hoặc
gửi request thật. Nó không phải API client có credential, không phải
observability backend và không thay thế `project_sentinel`/`safe_api_tool` CLI.

## Hai chế độ từ cùng một source

| Chế độ | URL | Hành vi |
|---|---|---|
| Full stack local | `http://localhost:8080/ui/` | Serve qua Envoy/FastAPI; có thể kiểm tra public `/health` cùng origin |
| Static showcase | root của static host | Render metrics, E2E replay, evidence và dry-run; không gọi backend |

Source nằm trong `src/app/static/`:

- `index.html`: semantic layout, form, fallback content và CSP meta.
- `styles.css`: responsive desktop/mobile, focus state và reduced motion.
- `app.js`: render dữ liệu, E2E replay và policy dry-run hoàn toàn local.
- `dashboard-data.json`: bản trình bày có contract được test với policy,
  catalog, receipt và golden snapshot thật trong repository.

## Security boundary

- Form chỉ chọn hai capability và bốn test case đã curate; không có URL, raw
  payload hoặc API-key input.
- Custom header value chỉ nhận printable ASCII giống runtime contract.
- JavaScript chỉ fetch `dashboard-data.json` và, ở full-stack mode, public
  `/health` cùng origin với `credentials: omit` và redirect bị cấm.
- E2E viewer chỉ đọc snapshot đã làm sạch. Các tab tình huống và nút từng bước
  không gọi API, không giữ raw HTTP response và không có nút Approve thật.
- Dữ liệu do người dùng nhập được đưa vào DOM bằng `textContent`, không dùng
  `innerHTML`, `eval`, cookie hoặc browser storage.
- FastAPI thêm CSP, `nosniff`, `DENY` framing, no-referrer, COOP/COEP/CORP và
  Permissions Policy trên `/` cùng `/ui/*`.
- HTML/JSON/health dùng `Cache-Control: no-store`; hai static asset JS/CSS công
  khai chỉ cache 5 phút và có version query.
- Authz chỉ public GET/HEAD cho exact UI surface; method ghi dữ liệu và path
  không canonical vẫn deny-by-default.
- Backend canary trả lỗi nếu `x-api-key` lọt qua Envoy; integration test chứng
  minh header được consume trước StaticFiles và không xuất hiện trong audit.

## Grounding của số liệu

- `41 findings` lấy từ fresh Bandit Low run ngày 20/08/2026; Bandit High gate
  không có finding High.
- `6 groups` lấy từ deterministic analysis của chính 41 finding đó.
- `216` test thường và `244` test đầy đủ lấy từ
  `evidence/week-6/pre-release-verification-2026-08-20.log`. Evidence ghi base
  HEAD `ea98afa`, working tree còn dirty và không tự nhận là final commit.
- Capability/test case/policy hash được contract-test với
  `config/safe-api-tool/policy.json` và `data/safe-api-test-cases.json`.
- Ba event evidence dùng request ID/outcome thật từ
  `security-results/runs/week-4/safe-api-demo.jsonl`, không phải event giả lập.
- Snapshot Week 6 hiện tại chỉ được cập nhật sau full local gate. Nguồn chuẩn là
  `evidence/week-6/pre-release-verification-2026-08-20.log`, evaluation summary
  và final report của cùng lượt review; dashboard không tự lấy số từ chat hoặc
  generated run chưa verify. Sau khi có final commit vẫn phải chạy lại hosted
  CI và cập nhật evidence của chính commit đó.

## Bản phát lại E2E Week 6

Viewer có bốn tình huống đã được kiểm chứng:

| Tình huống | Kết quả | Request đã gửi |
|---|---|---:|
| Người dùng từ chối | Dừng trước khi gửi | 0 |
| Người dùng phê duyệt | Hoàn thành qua Gateway | 1 |
| HTTP response chứa prompt injection | Nội dung bị cách ly | 1 |
| Đề xuất gọi `/api/admin` | Policy chặn trước khi gửi | 0 |

Mỗi tình huống đi qua cùng tám bước: nhận kết quả scan, chuẩn hóa, phân tích,
tạo đề xuất, phê duyệt, gửi qua Gateway, kiểm tra response và tạo báo cáo cuối.
Người xem có thể chọn từng bước để đọc trạng thái và lý do. Badge
`BẢN PHÁT LẠI · KHÔNG GỬI REQUEST` luôn hiện để tránh nhầm với lần chạy live.

Dữ liệu viewer nằm tại `dashboard-data.json.e2eReplay` và được contract-test
với `security-results/runs/week-6/golden/release-summary.json`. Test cũng ghim
thứ tự tám bước, bốn tình huống, số request, evaluation 10/10 (TP=6, FP=0,
FN=0) và kiểm tra không có raw prompt injection, secret hoặc PII trong bản phát
lại.

## Radar `policy.runtime`

Radar là trạng thái ba lớp có nguồn dữ liệu riêng, không phải security score
hay scanner thời gian thực:

| Vòng | Trạng thái được biểu diễn | Nguồn dữ liệu |
|---|---|---|
| Ngoài — Gateway | `UNCHECKED`, `LIVE`, `STATIC`, `FAILED` | Same-origin `GET /health`; static host không tuyên bố live |
| Giữa — Policy | `VERIFIED`, `ALLOW`, `DENY`, `UNAVAILABLE` | Policy version/SHA, capability và test-case contract trong `dashboard-data.json` |
| Trong — Evidence | `VERIFIED SNAPSHOT`, `DRY-RUN RECEIPT`, `UNAVAILABLE` | Durable Week 4 receipts và receipt tạo bởi simulator |

Màu xanh lá biểu thị live/verified/allow, cyan biểu thị snapshot hoặc dry-run,
vàng biểu thị controlled deny/checking, đỏ biểu thị lỗi hoặc metadata không
khả dụng, và xám là chưa kiểm tra. `DENY` là policy hoạt động đúng nên được
hiển thị vàng thay vì coi là lỗi hệ thống.

`dashboard-data.json.runtimeRadar` liên kết ba vòng với origin, policy
SHA/version, số capability/test case và tổng hợp evidence. Contract test buộc
metadata này khớp policy, catalog và receipt hiện có. JavaScript chỉ chuyển
Gateway sang `LIVE` sau response `/health` hợp lệ; GitHub Pages luôn dùng
`STATIC SNAPSHOT`. Policy dry-run cập nhật vòng Policy cùng Evidence nhưng
không đổi trạng thái Gateway và không mở network.

Ba nhãn `Gateway`, `Policy` và `Evidence` trên radar là button có thể click,
focus bằng phím Tab và kích hoạt bằng Enter/Space. Mỗi button mở inspector hiển
thị nguồn, trạng thái và chi tiết của đúng vòng; `aria-pressed` cùng vùng
`aria-live` giúp screen reader nhận biết layer đang chọn. Asset URL có version
query để browser không giữ JavaScript/CSS cũ sau khi dashboard được rebuild
hoặc deploy lại.

## Chạy local

Qua full stack:

```powershell
docker compose up --build --detach --wait
Start-Process "http://localhost:8080/ui/"
```

Chỉ preview static:

```powershell
python -m http.server 4173 --bind 127.0.0.1 --directory src/app/static
```

Kết thúc bằng `docker compose down --remove-orphans` nếu đã chạy Compose.

## Deployment governance

`.github/workflows/deploy-ui-pages.yml` chỉ có `workflow_dispatch`, chỉ deploy
từ `main` và nên đặt required reviewer cho environment `github-pages`. Không
commit, push hoặc chạy workflow này nếu chưa được chủ repository đồng ý rõ
ràng. Pipeline kiểm thử và artifact Week 3–6 được mô tả tại [CI/CD](ci-cd.md).
