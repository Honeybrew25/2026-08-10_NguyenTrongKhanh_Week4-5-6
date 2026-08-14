# Project Sentinel dashboard

> Dashboard trình bày chuỗi Week 3 → Week 4. Bắt đầu tại
> [documentation hub](README.md) để xem source, artifact và kịch bản demo.

## Mục tiêu

Dashboard biến flow Week 1–4 thành một trang có thể trình bày trong buổi demo
mà không làm rộng trust boundary. Nó không phải API client có credential và
không thay thế `safe_api_tool` CLI.

## Hai chế độ từ cùng một source

| Chế độ | URL | Hành vi |
|---|---|---|
| Full stack local | `http://localhost:8080/ui/` | Serve qua Envoy/FastAPI; có thể kiểm tra public `/health` cùng origin |
| Static showcase | root của static host | Render metrics, architecture, evidence và dry-run; không gọi backend |

Source nằm trong `src/app/static/`:

- `index.html`: semantic layout, form, fallback content và CSP meta.
- `styles.css`: responsive desktop/mobile, focus state và reduced motion.
- `app.js`: render curated data và policy dry-run hoàn toàn local.
- `dashboard-data.json`: bản trình bày có contract được test với policy,
  catalog và receipt thật trong repository.

## Security boundary

- Form chỉ chọn hai capability và bốn test case đã curate; không có URL, raw
  payload hoặc API-key input.
- Custom header value chỉ nhận printable ASCII giống runtime contract.
- JavaScript chỉ fetch `dashboard-data.json` và, ở full-stack mode, public
  `/health` cùng origin với `credentials: omit` và redirect bị cấm.
- Dữ liệu do người dùng nhập được đưa vào DOM bằng `textContent`, không dùng
  `innerHTML`, `eval`, cookie hoặc browser storage.
- FastAPI thêm CSP, `nosniff`, `DENY` framing, no-referrer, COOP/CORP và
  Permissions Policy trên `/` cùng `/ui/*`.
- Authz chỉ public GET/HEAD cho exact UI surface; method ghi dữ liệu và path
  không canonical vẫn deny-by-default.
- Backend canary trả lỗi nếu `x-api-key` lọt qua Envoy; integration test chứng
  minh header được consume trước StaticFiles và không xuất hiện trong audit.

## Grounding của số liệu

- `27 findings` lấy từ normalized baseline.
- `9 groups` lấy từ deterministic Week 3 JSONL.
- Capability/test case/policy hash được contract-test với
  `config/safe-api-tool/policy.json` và `data/safe-api-test-cases.json`.
- Ba event evidence dùng request ID/outcome thật từ
  `security-results/runs/week-4/safe-api-demo.jsonl`, không phải event giả lập.
- Snapshot hiện tại là 141 non-integration test và 166 full-stack test; phải
  cập nhật lại dashboard sau full verification nếu suite thay đổi.

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
ràng. Pipeline kiểm thử và artifact Week 3–4 được mô tả tại [CI/CD](ci-cd.md).
