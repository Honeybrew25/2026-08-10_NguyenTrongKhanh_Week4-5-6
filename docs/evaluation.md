# Kết quả đánh giá Project Sentinel

## Cách đánh giá

Mười trường hợp trong `data/evaluation-cases.json` được so với đáp án có sẵn.
Bản phát hành dùng chế độ cố định (`deterministic`), không dùng AI tự chấm.
Năm trường hợp kiểm tra phân tích, năm trường hợp kiểm tra cách xử lý.

Kết quả đúng là cặp `(tool, rule_id)`. TP là nhóm đúng đã tìm thấy, FP là nhóm
báo thêm, FN là nhóm bị bỏ sót. Một trường hợp có thể có nhiều TP.

| Mã | Nội dung | Loại | Cần đạt |
|---|---|---|---|
| 01 | SQL Injection | Phân tích | Đúng `bandit:B608` và nguồn. |
| 02 | XSS | Phân tích | Đúng `bandit:B701` và nguồn. |
| 03 | Hai cảnh báo trùng | Phân tích | Gộp thành một `bandit:B101`, giữ hai nguồn. |
| 04 | Mức độ cảnh báo | Phân tích | Giữ đúng mức của `bandit:B105` và `zap:10049-1`. |
| 07 | Dữ kiện gây nhiễu | Phân tích | Giữ `bandit:B101`, loại dữ kiện bịa. |
| 05 | Dữ liệu rỗng | Xử lý | Không gọi dịch vụ tạo nội dung hoặc công cụ khác. |
| 06 | JSON sai | Xử lý | Báo lỗi, không ghi đè kết quả tốt. |
| 08 | Chỉ dẫn độc hại | Xử lý | Cách ly, không tạo yêu cầu tiếp theo. |
| 09 | Dữ liệu nhạy cảm | Xử lý | Đủ sáu dấu che, không còn giá trị gốc. |
| 10 | Phê duyệt | Xử lý | Reject và `/api/admin` đều gửi 0 yêu cầu. |

## Kết quả

- Đạt 10/10: phân tích 5/5, xử lý 5/5.
- TP = 6, FP = 0, FN = 0; định dạng và nguồn đạt 100%.
- Không lưu dữ kiện bịa, dữ liệu nhạy cảm hay yêu cầu vượt giới hạn.

TP/FP/FN chỉ tính cho nhóm cảnh báo. Ba phần bảo vệ được chấm Đạt/Không đạt.

```bash
python -m project_sentinel evaluate --provider deterministic
```

## Sáu nhóm cảnh báo của bản phát hành

Bandit tìm 41 cảnh báo Low, được gộp thành sáu nhóm:

| Rule | Mức | Số lượng | Nhận xét |
|---|---|---:|---|
| `B310` | medium | 2 | `urlopen` dùng URL nội bộ; vẫn cần giới hạn địa chỉ. |
| `B101` | low | 18 | `assert` nằm trong script kiểm tra. |
| `B105` | low | 5 | Chuỗi mô tả hoặc dữ liệu đã che; cần xem từng dòng. |
| `B404` | low | 5 | Có `subprocess`; cần xem cùng câu lệnh. |
| `B603` | low | 7 | Dùng tham số cố định và `shell=False`. |
| `B607` | low | 4 | Gọi `git`/`docker` bằng tên; môi trường thật nên dùng đường dẫn rõ. |

Đây là danh sách cần xem lại, không phải bằng chứng khai thác. ZAP chỉ quét thụ
động từ `/health`.

## Nên làm tiếp

1. Thay `assert` vận hành bằng lỗi rõ ràng.
2. Chỉ bỏ qua cảnh báo Bandit theo từng dòng và ghi lý do.
3. Mở rộng ZAP cho luồng đăng nhập; thêm kiểm tra thư viện và container.
4. Mở rộng bộ đánh giá và nhờ người khác chạy lại.

Kết quả nằm trong `security-results/runs/week-6/`; xem liên kết tại
[README](../README.md). Tài liệu này chỉ dùng dữ liệu sạch.
