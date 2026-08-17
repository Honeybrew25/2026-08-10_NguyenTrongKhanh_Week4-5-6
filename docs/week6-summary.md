# Tuần 6 — Bản tóm tắt dễ hiểu

## Tuần này làm gì?

Tuần 6 nối các phần đã xây dựng thành một quy trình hoàn chỉnh:

1. nhận kết quả quét bảo mật;
2. gộp các cảnh báo giống nhau;
3. tạo phần giải thích và đề xuất kiểm tra;
4. hỏi người dùng khi cần phê duyệt;
5. gửi yêu cầu an toàn qua cổng bảo vệ;
6. lưu kết quả và tạo báo cáo cuối cùng.

Dự án cũng có lệnh demo, bộ đánh giá 10 trường hợp và cách chạy bằng Docker.
Mỗi lần chạy đều lưu mã nhận diện, thời gian và dấu kiểm tra file để có thể đối
chiếu lại về sau.

## Kết quả

- 41 cảnh báo mới được gộp thành 6 nhóm dễ theo dõi.
- Bộ đánh giá đạt 10/10 trường hợp, không bỏ sót hoặc báo nhầm trong dữ liệu
  mẫu.
- 200 bài kiểm thử thông thường và 228 bài kiểm thử đầy đủ đã đạt.
- Chọn `Reject` không gửi yêu cầu; chọn `Approve` gửi đúng một yêu cầu.
- Nội dung cố hướng dẫn AI làm sai bị cách ly và đường dẫn quản trị bị chặn.
- Báo cáo cuối phân biệt rõ dữ liệu từ công cụ quét, phần giải thích của AI,
  quyết định của người dùng và kết quả gửi yêu cầu.

## Trạng thái sản phẩm

Các chức năng chính của tuần 6 đã hoàn thành và có bằng chứng chạy thử. Tuy
nhiên, đây vẫn là môi trường lab: ZAP mới kiểm tra thụ động đường dẫn `/health`,
Keycloak dùng chế độ phát triển và giới hạn số yêu cầu được lưu trong từng tiến
trình.

Trước khi chốt bản phát hành, chủ dự án vẫn cần xem lại thay đổi, chạy buổi demo
theo thời gian thật và lưu mã phiên bản cuối cùng.

Xem [báo cáo gốc](../reports/week-6.md),
[bằng chứng kiểm thử](../evidence/week-6/verification.log) và
[các bước xác nhận cuối](release-acceptance.md).
