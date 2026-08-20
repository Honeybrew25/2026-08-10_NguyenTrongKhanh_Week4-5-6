# Kết quả quét ZAP

Ngày 15/08/2026, ZAP `2.17.0` quét thụ động từ `GET /health` qua Envoy. Không
có token hoặc Safe API key nên ZAP chỉ thấy các trang công khai.

| Thời điểm | Loại cảnh báo | Vị trí | Low | Thông tin | Console |
|---|---:|---:|---:|---:|---|
| Trước khi sửa | 7 | 20 | 2 | 5 | 0 FAIL, 5 WARN, 62 PASS |
| Sau khi sửa | 5 | 16 | 0 | 5 | 0 FAIL, 4 WARN, 63 PASS |

Nguồn: `security-results/runs/week-5/zap-fresh.json` (trước),
`zap-hardening.json`, `zap-hardening.html` (sau) và
`evidence/week-5/baseline.log` (tổng hợp).

## Quyết định cho từng cảnh báo ban đầu

| Mã | Trước | Kết luận | Lý do; khi nào xem lại |
|---|---:|---|---|
| `90004-2` COEP missing/invalid | Low · 3 | **Đã sửa** | UI đã có header COEP; ZAP không còn báo. Kiểm lại nếu dùng tài nguyên từ tên miền khác. |
| `90004-1` CORP missing/invalid | Low · 1 | **Đã sửa** | Mọi phản hồi, cả `/health`, đã có header CORP; kiểm thử và ZAP đều đạt. |
| `10055-12` CSP header & meta | Info · 3 | **Chấp nhận** | Pages dùng thẻ meta, Envoy dùng header; cả hai mặc định chặn. Kiểm lại nếu hai cấu hình lệch nhau. |
| `10109` Modern Web Application | Info · 3 | **Chấp nhận** | Đây là gợi ý dùng Client Spider, không phải lỗ hổng. Quét có đăng nhập nằm ngoài lần này. |
| `10049-1` Non-Storable Content | Info · 2 | **Chấp nhận** | HTML, JSON và health không lưu tạm để tránh giữ dữ liệu khi chạy. |
| `10049-3` Storable and Cacheable Content | Info · 5 | **Chấp nhận, đã giảm** | Chỉ JS/CSS công khai được lưu 5 phút và có mã phiên bản; không chứa thông tin đăng nhập. |
| `10031` User Controllable HTML Attribute | Info · 3 | **Cảnh báo nhầm** | Tham số URL không xuất hiện lại trong HTML; JavaScript dùng `textContent` và CSP chặn script viết thẳng. Kiểm lại nếu sau này hiển thị tham số URL. |

Hai cảnh báo Low đã sửa. Năm cảnh báo còn lại ở mức Informational và có lý do
chấp nhận. Cờ `-I` không biến chúng thành “Pass”; bằng chứng vẫn phải giữ JSON,
SHA-256 và số cảnh báo.

## Giới hạn

ZAP thấy 10 địa chỉ công khai nhưng không gọi `/api/users`, `/api/admin` hoặc
ba đường dẫn Safe API cần key. Các phần này có kiểm thử riêng, không phải kết
quả ZAP. Muốn quét có đăng nhập, cần tài khoản riêng, giới hạn đúng đường dẫn và
che dữ liệu nhạy cảm trước khi lưu.
