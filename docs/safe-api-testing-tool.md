# Công cụ kiểm thử API an toàn

> Week 4 · Xem [hướng dẫn chính](../README.md),
> [báo cáo tuần](../reports/week-4.md),
> [kết quả demo](../security-results/runs/week-4/safe-api-demo.jsonl) và
> [các lớp bảo vệ thêm ở Week 5](week5.md).

## Mục đích

Safe API Testing Tool cho bộ phân tích chọn một số bài kiểm tra GET/POST có sẵn
rồi gửi qua Envoy. Nó không nhận địa chỉ tùy ý, không tạo dữ liệu phá hoại,
không sửa dữ liệu thật và không kết nối thẳng vào ứng dụng phía sau Envoy.

Mỗi đề xuất chỉ có `endpoint_id`, `test_case_id`, `rationale`,
`source_finding_ids` và `requested_headers`. Địa chỉ, dữ liệu gửi và thông tin
đăng nhập không nằm trong đề xuất; chương trình tự tạo dữ liệu từ danh sách đã
duyệt. POST hoặc yêu cầu có dữ liệu phải được người vận hành chọn `Approve`
ngay trước khi gửi.

Danh sách cho phép nằm tại `config/safe-api-tool/policy.json`; bốn mẫu dữ liệu
tại `data/safe-api-test-cases.json`; mã công cụ tại `src/safe_api_tool/`; quy
định định dạng tại `schemas/safe-api-*.schema.json`. Công cụ và authz-service
dùng cùng một danh sách.

Giới hạn hiện tại: 12 yêu cầu/phút cho mỗi API key, phương thức và đường dẫn;
chờ tối đa 3 giây; yêu cầu 4 KiB; phản hồi 64 KiB; tối đa bốn trường HTTP tùy
chọn và 256 byte cho mỗi giá trị.

## Liên kết với cảnh báo Week 3

Bộ chọn mẫu đọc `security-results/security-analysis.jsonl` và giữ
`source_finding_ids`. Mỗi đề xuất có dấu vân tay 16 ký tự; nhật ký lưu dấu này,
SHA-256 của danh sách cho phép, ID bài kiểm tra và `x-request-id` để truy ngược
quyết định. Nội dung Week 3 chỉ giúp chọn bài kiểm tra có sẵn, không thể tạo địa
chỉ, dữ liệu gửi, API key hay trường HTTP mới. Chỉ dẫn độc hại và đường dẫn
ngoài danh sách vẫn bị chặn trước khi kết nối.

## API và quyền

| `endpoint_id` | Phương thức/đường dẫn | Mẫu thử hợp lệ | Mã cần nhận |
|---|---|---|---|
| `test-status` | `GET /api/test/status` | `empty` | 200 |
| `prompt-injection-fixture` | `GET /api/test/prompt-injection` | `empty` | 200 |
| `input-validation` | `POST /api/test/validate` | `long-string`, `special-characters`, `empty` | 200 |
| `input-validation` | `POST /api/test/validate` | `wrong-type` | 422 |

| Danh tính | Được phép | Xác thực |
|---|---|---|
| Không đăng nhập | GET `/health`, GET metadata; GET/HEAD `/` và `/ui/*` | Không có |
| `safe-api-tool` | Đúng ba đường dẫn trên | API key riêng, bị Envoy xóa trước ứng dụng |
| `agent-reader` | GET `/api/users` | JWT có `users:read` |
| `agent-admin` | GET `/api/users`, GET `/api/admin` | JWT có `users:read`, `admin:read` |
| Trường hợp khác | Không có | Mặc định từ chối |

API key của Tool không mở `/api/users` hay `/api/admin`; JWT không mở ba API
thử nghiệm. `/api/admin` ghi rõ
`authorization_boundary: "envoy_ext_authz"` và
`required_scope: "admin:read"`, không dùng cờ
`authentication_enabled: false` dễ gây hiểu nhầm.

## Quy tắc an toàn

Trước khi gửi:

- Chỉ nhận ID và trường có trong định dạng đã định. Phương thức và đường dẫn
  phải khớp chính xác một mục dưới `/api/test/`.
- Chặn địa chỉ đầy đủ, tham số URL, phần neo, mã hóa `%`, `..`, dấu gạch chéo
  ngược và dấu gạch chéo kép. Đề xuất không được đặt `Host`, `Authorization`,
  `x-api-key`, trường giữa các proxy hoặc `X-Forwarded-*`; trường tùy chọn chỉ
  nhận ký tự ASCII có thể in.
- Dữ liệu gửi được tạo rồi kiểm tra kích thước. Công cụ chặn yêu cầu vượt tần suất trước
  khi kết nối.
- Phê duyệt cho POST hoặc yêu cầu có dữ liệu phải còn hạn, chỉ dùng một lần và
  khớp dấu vân tay sau lần kiểm tra danh sách cuối. Kiểm thử xác nhận `Reject`
  gửi 0 yêu cầu, `Approve` gửi
  đúng 1; bản hết hạn, dùng lại hoặc bị thay đổi đều thất bại.

Tại cổng Envoy:

- Công cụ chỉ dùng `http://localhost:8080` khi chạy trên máy hoặc
  `http://envoy:8080` trong Compose. `http://api:8000` không bao giờ hợp lệ và
  ứng dụng không mở cổng trực tiếp ra máy.
- `ext_authz` mặc định từ chối khi lỗi. authz-service băm API key bằng SHA-256,
  so sánh theo cách không làm lộ thời gian và chỉ cho đúng ba đường dẫn. Công cụ tự
  chèn key; key không có quyền `agent-reader` hay `agent-admin`.
- authz-service kiểm tra lại tần suất. Envoy chặn body lớn hơn 4 KiB trên
  `POST /api/test/validate` bằng 413 trước authz và ứng dụng.
- Envoy phải xóa `x-api-key` trước khi chuyển yêu cầu. Nếu ứng dụng còn thấy
  trường này, nó trả 500 để tránh chạy sai cấu hình.

Khi nhận phản hồi và ghi nhật ký:

- Chương trình gửi yêu cầu dùng `follow_redirects=False`, `trust_env=False` và
  `Accept-Encoding: identity`. Phản hồi được đọc từng phần và dừng ở giới hạn
  byte.
- Hết thời gian, lỗi kết nối, 429, sai mã trả về và phản hồi bị cắt có kết quả riêng;
  không ghi lỗi hệ thống thô.
- Biên nhận chỉ lưu tên trường HTTP, số byte, SHA-256, mã trả về, thời gian và
  đoạn trích. Phản hồi được che dữ liệu trước khi cắt; API key, giá trị
  `Authorization` và dữ liệu thô không được ghi.
- Phản hồi không được đưa nguyên văn lại cho bộ chọn mẫu. Dấu hiệu chỉ dẫn độc
  hại bị cách ly và không thể tạo đề xuất, phê duyệt hay yêu cầu tiếp theo. Bộ
  lọc che email, số điện thoại lab, token, API key, mật khẩu và các trường dữ liệu
  cá nhân đã biết.

Các kiểm thử còn xác nhận phương thức/đường dẫn lạ và `/api/admin` bị chặn; key
không tới ứng dụng; yêu cầu lớn trả 413; phản hồi lớn, hết thời gian và 429 được
giới hạn; hai phản hồi độc hại bị cách ly nhưng phản hồi bình thường không bị
chặn. Danh sách cho phép bị lỗi hoặc sai định dạng luôn bị từ chối.

## Cách chạy

Tạo `.env` từ `.env.example`; đặt `SAFE_API_TOOL_API_KEY` ngẫu nhiên, dài tối
thiểu 32 byte. Không truyền key trên command line.

```powershell
python -m pip install --requirement requirements-dev.txt
docker compose up --build --detach --wait
```

Tạo đề xuất từ cảnh báo đầu tiên có nguồn:

```powershell
python -m safe_api_tool propose `
  --analysis security-results/security-analysis.jsonl `
  --output "$env:TEMP\safe-api-proposal.json"
```

Mặc định chỉ kiểm tra, không cần secret hoặc network:

```powershell
python -m safe_api_tool run "$env:TEMP\safe-api-proposal.json"
python -m safe_api_tool demo
```

Chỉ `--execute` mới gửi yêu cầu. Với POST, nhập đúng `Approve` hoặc `Reject`:

```powershell
python -m safe_api_tool run "$env:TEMP\safe-api-proposal.json" `
  --execute --audit "$env:TEMP\safe-api-receipts.jsonl" `
  --approval-log "$env:TEMP\safe-api-approvals.jsonl" `
  --guarded-response-log "$env:TEMP\safe-api-guarded.jsonl" `
  --event-log "$env:TEMP\safe-api-events.jsonl"

python -m safe_api_tool demo --execute `
  --audit "$env:TEMP\safe-api-demo.jsonl"
```

Demo chạy GET, POST `Reject`, POST `Approve` và xác nhận `admin` bị chặn trước
khi gửi. Không có `--yes` hoặc biến môi trường để bỏ qua phê duyệt. Dọn hệ thống:

```powershell
docker compose down --remove-orphans
```

## Kết quả và mã trả về

| Kết quả | Ý nghĩa |
|---|---|
| `success` | Hoàn tất, mã HTTP đúng |
| `unexpected_status` | Mã HTTP khác dự kiến |
| `policy_denied` | Bị chặn trước khi gửi |
| `rate_limited` | Công cụ chặn hoặc Envoy trả 429 |
| `timeout` | Hết thời gian chờ |
| `connection_error` | Không nối được Envoy |
| `response_truncated` | Phản hồi bị cắt; biên nhận vẫn được lưu |

CLI/CI chỉ đạt khi `success` và `expected_status_matched=true`. Phản hồi bị cắt
không làm demo đạt.

| Mã | Ý nghĩa |
|---:|---|
| `0` | Đề xuất hoặc lần chạy thử hợp lệ; lần chạy thật đúng yêu cầu |
| `2` | Dữ liệu, danh sách cho phép, danh mục, thông tin đăng nhập hoặc cấu hình sai |
| `3` | Lệnh `run` bị chặn trước khi gửi |
| `4` | Sai mã HTTP, hết thời gian, 429, lỗi kết nối hoặc phản hồi bị cắt |

## Kiểm thử và bằng chứng

```powershell
python -m pytest -q -m "not integration"
python scripts/run_all_tests.py
python -m json.tool config/safe-api-tool/policy.json > $null
docker compose config --quiet
```

`run_all_tests.py` tạo thông tin bí mật tạm, chạy kiểm thử Docker và demo
`Reject`/`Approve`, lưu bốn JSONL đã che dữ liệu rồi dọn hệ thống. GitHub
Actions tải chúng lên
`week5-safe-api-guardrail-artifacts`.

| Bằng chứng | Nội dung |
|---|---|
| `config/safe-api-tool/policy.json` | Đường dẫn, ba quyền và giới hạn |
| `data/safe-api-test-cases.json` | Bốn mẫu long/special/empty/wrong-type |
| `security-results/runs/week-4/safe-api-demo.jsonl` | GET 200, POST 200, trường hợp cấm bị chặn trước khi gửi |
| `evidence/week-4/verification.log` | Lệnh, môi trường và kết quả Week 4 |
| `evidence/week-5/verification.log` | Phê duyệt, che dữ liệu, chặn chỉ dẫn xấu và hệ thống đầy đủ |
| `.github/workflows/security-scan.yml` | Thông tin bí mật tạm, demo thật và bốn file kết quả CI |

SHA-256 của danh sách cho phép đã chuẩn hóa là
`0181e74d35ced610750e1ced2e42f0e1733439d3ce830b6cb62cf2cfee7562a8`.
Kết quả mẫu Week 4 giữ mã lịch sử cũ; không sửa nó thành bằng chứng mới. Mã
SHA-256 của file JSON có thể đổi do cách xuống dòng hoặc khoảng trắng nên không
so trực tiếp với mã của danh sách đã chuẩn hóa.

## Giới hạn

- Bộ giới hạn authz-service chỉ dùng bộ nhớ của một tiến trình, phù hợp một bản
  chạy trong lab. Nhiều bản chạy cần kho dùng chung hoặc dịch vụ tại Envoy.
- `timeout_seconds` áp dụng riêng cho kết nối/đọc/ghi; đường dẫn Envoy có trần
  5 giây. Chưa có một thời hạn chung cho phản hồi gồm nhiều phần.
- Bộ chọn mẫu chạy theo quy tắc cố định để CI lặp lại được; AI không tự nắm quyền
  gọi API.
- Chỉ có hai địa chỉ tin cậy `host` và `compose`. Môi trường khác phải thêm qua
  xem xét, không nhận URL từ đề xuất.
- ZAP CI chỉ quét thụ động, không đăng nhập, bắt đầu từ `/health`; nó không có
  token của bộ phân tích, không gửi dữ liệu mẫu và không kiểm tra API cần quyền.
  Quyền của công cụ được kiểm tra riêng; biên nhận này không phải kết quả quét
  có đăng nhập.
