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

- Kết quả TP=6, FP=0, FN=0; không thấy dữ kiện bịa, rò rỉ dữ liệu hoặc vượt quy tắc.
- Khi chọn `Reject`, hệ thống không gửi yêu cầu. Khi chọn `Approve`, hệ thống chỉ
  gửi đúng một yêu cầu qua Envoy.
- Phản hồi chứa chỉ dẫn xấu bị cách ly; đường dẫn `/api/admin` bị chặn trước khi
  gửi.

## Kết luận

Project Sentinel đi từ một ứng dụng có kết quả quét rời rạc thành một sản phẩm
có quy trình rõ ràng: nhận cảnh báo, gộp dữ liệu, giải thích, đề xuất kiểm tra,
xin phê duyệt và lưu báo cáo cuối.
