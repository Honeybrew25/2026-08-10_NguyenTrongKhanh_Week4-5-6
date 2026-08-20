# Kiến trúc Project Sentinel

## Hệ thống làm gì?

Project Sentinel gộp kết quả quét, giải thích cảnh báo, đề xuất phép kiểm tra an
toàn và lưu báo cáo. Code quyết định đường dẫn và lúc cần người dùng đồng ý.

## Luồng xử lý

| Bước | Việc thực hiện | Kết quả |
|---|---|---|
| 1. Nhận dữ liệu | Đọc JSON mới từ Bandit hoặc ZAP | Bản sao và mã SHA-256 |
| 2. Chuẩn hóa | Đưa các công cụ quét về cùng một mẫu | `normalized-findings.json` |
| 3. Phân tích | Gộp cảnh báo giống nhau và tra kho kiến thức | Báo cáo JSONL có nguồn |
| 4. Đề xuất | Chọn một phép kiểm tra có sẵn | Mã chức năng và mẫu thử |
| 5. Kiểm tra | Xác nhận loại yêu cầu HTTP, đường dẫn và dữ liệu gửi | Cho phép, cần duyệt hoặc chặn |
| 6. Phê duyệt | Hiện đầy đủ yêu cầu để người dùng chọn | Approve hoặc Reject |
| 7. Gửi yêu cầu | Gửi qua Envoy, không gọi thẳng ứng dụng | Biên nhận đã làm sạch |
| 8. Lập báo cáo | Gộp kết quả từng bước | Báo cáo cuối và số liệu |

Phản hồi HTTP không thể tạo yêu cầu mới. AI không nhận API key, địa chỉ gốc hay
dữ liệu gửi tùy ý.

Code chọn sẵn địa chỉ chạy:

- chạy trên máy: `http://localhost:8080`;
- chạy trong Compose: `http://envoy:8080`.

## Các đường dẫn API hiện hành

Envoy là cổng vào duy nhất của API thử nghiệm. Keycloak chỉ mở cổng `8081` trên
máy để cấp token trong lab.

| Loại | Đường dẫn | Quyền truy cập | Mục đích |
|---|---|---|---|
| `GET`, `HEAD` | `/`, `/ui`, `/ui/*` | Công khai | Mở giao diện. |
| `GET` | `/health` | Công khai | Kiểm tra sẵn sàng. |
| `GET` | `/.well-known/oauth-protected-resource` | Công khai | Mô tả OAuth. |
| `GET` | `/api/users` | Token có `users:read` | Đọc dữ liệu mẫu. |
| `GET` | `/api/admin` | Token có `admin:read` | API quản trị mẫu; công cụ kiểm thử không được gọi. |
| `GET` | `/api/test/status` | API key của công cụ | Kiểm tra trạng thái. |
| `GET` | `/api/test/prompt-injection` | API key của công cụ | Trả nội dung giả lập để thử bộ lọc. |
| `POST` | `/api/test/validate` | API key và phê duyệt khi cần | Kiểm dữ liệu mẫu, không lưu dữ liệu. |

Ba đường dẫn `/api/test/*` chỉ nhận mẫu có sẵn; yêu cầu khác bị chặn. Envoy bỏ
API key trước khi chuyển đến ứng dụng.

## Quy tắc an toàn

- Reject, phê duyệt hết hạn hoặc không khớp đều dừng trước khi gửi.
- Sau Approve, danh sách cho phép được kiểm lại.
- Yêu cầu không tự chuyển hướng và bị giới hạn thời gian, tốc độ, kích thước.
- Dữ liệu nhạy cảm được che trước khi gửi AI hoặc ghi nhật ký.
- Phản hồi đáng ngờ bị cách ly, không lưu bản thô.
- Lỗi được đổi thành mã ngắn, không lưu chi tiết hệ thống.
- HTTP 200 chỉ cho biết đường dẫn đã trả lời, không chứng minh có lỗ hổng.

Phê duyệt gắn với `run_id`, nội dung, quy tắc và thời hạn nên không dùng lại được.

## Kết quả được lưu

Mỗi lần chạy có một thư mục riêng. Các file chính gồm:

- `pipeline-events.jsonl`: từng bước và thời gian chạy;
- `security-analysis.jsonl`: các nhóm cảnh báo có nguồn;
- `final-report.json`: kết quả cuối;
- `manifest.json`: mã SHA-256 của các file.

`run_id` nối các file. Trước khi làm bằng chứng, file được kiểm định dạng và dữ
liệu nhạy cảm. Báo cáo tách dữ liệu quét, phần AI, quyết định và kết quả gửi.

## Docker, CI và giao diện

Compose chạy Keycloak, API, `authz-service`, Envoy và `runner`. Runner không
chạy bằng root, không mở cổng và chỉ đọc file cần thiết.

CI dùng Bandit Low làm dữ liệu, Bandit High để chặn phát hành và ZAP quét thụ
động từ `/health`. Kết quả được kiểm định dạng và SHA-256 trước khi tải lên.

Giao diện chỉ phát lại dữ liệu sạch; không giữ API key hay Approve thật.

## Giới hạn hiện tại

- Keycloak dùng `start-dev` và HTTP local, chỉ phù hợp lab.
- Bộ giới hạn số yêu cầu lưu trong từng tiến trình và mất khi khởi động lại.
- ZAP chưa quét các API cần đăng nhập; Bandit chưa kiểm tra thư viện và image Docker.
- Bộ lọc dựa vào mẫu chữ nên có thể nhận nhầm hoặc bỏ sót.
- Gemini là tùy chọn; release mặc định dùng kết quả cố định để dễ lặp lại.
- Một số image/action mới ghim theo phiên bản, chưa ghim SHA hoặc digest.
- Bản cuối cần commit sạch, CI GitHub đạt và một người khác chạy lại.
