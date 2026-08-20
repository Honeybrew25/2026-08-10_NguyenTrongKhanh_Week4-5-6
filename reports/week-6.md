# Báo cáo tuần 6 - Tích hợp và đánh giá Project Sentinel

## Mục tiêu

Trong tuần 6, em nối scanner, normalizer, Security Analysis Agent, approval,
Gateway và response guard thành một sản phẩm đầu-cuối có final report, metrics,
evaluation và lệnh demo tái hiện được.

## Quá trình

- Nối kết quả quét, phần giải thích, đề xuất kiểm tra, phê duyệt và báo cáo cuối
  thành một luồng thống nhất.
- Chỉ cho phép các mẫu kiểm tra đã chuẩn bị sẵn. AI không được tự chọn địa chỉ,
  tự phê duyệt hoặc gửi yêu cầu.
- Thêm bốn tình huống demo: từ chối, phê duyệt, phản hồi có chỉ dẫn xấu và truy
  cập đường dẫn quản trị.
- Thêm CI Week 6 dùng Bandit/ZAP artefact cùng workflow, schema/hash/sentinel
  gate, product brief, kiến trúc.

## Kết quả

- Bandit tìm 41 cảnh báo mức Low, được gộp thành 6 nhóm; không có cảnh báo High.
- Bộ đánh giá đạt 10/10: 5 trường hợp phân tích và 5 trường hợp xử lý. Kết quả
  TP=6, FP=0, FN=0; không thấy dữ kiện bịa, rò rỉ dữ liệu hoặc vượt quy tắc.
- Kiểm thử trên máy đạt 216 bài. Bằng chứng Docker gần nhất ghi nhận 244 bài đạt
  và môi trường được dọn sạch sau khi chạy.
- Khi chọn `Reject`, hệ thống không gửi yêu cầu. Khi chọn `Approve`, hệ thống chỉ
  gửi đúng một yêu cầu qua Envoy.
- Phản hồi chứa chỉ dẫn xấu bị cách ly; đường dẫn `/api/admin` bị chặn trước khi
  gửi.

## Kết luận

Sản phẩm hiện đủ để demo và bàn giao trong môi trường học tập. Tuy nhiên, ZAP
mới quét thụ động, Keycloak còn chạy chế độ phát triển và giới hạn số yêu cầu
chưa dùng chung khi mở rộng. Trước khi gọi là bản phát hành cuối, dự án vẫn cần
CI đạt trên commit sạch và một người khác chạy lại theo README.
