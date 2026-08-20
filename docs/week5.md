# Tuần 5 — Thêm lớp bảo vệ

## Đã làm

Tuần 5 thêm ba cách bảo vệ khi kiểm thử API:

- che email, số điện thoại, mật khẩu và mã truy cập trước khi gửi cho AI;
- coi câu lệnh đáng ngờ trong phản hồi website là dữ liệu, không làm theo;
- hỏi người dùng trước khi gửi yêu cầu có thể thay đổi dữ liệu.

`Reject` không gửi gì. `Approve` chỉ gửi yêu cầu đã hiển thị qua cổng bảo vệ.
Mỗi lần phê duyệt có thời hạn, dùng một lần và không dùng cho yêu cầu khác.

## Kết quả

- 183 bài kiểm thử thông thường và 211 bài kiểm thử đầy đủ với Docker đã đạt.
- Thử nghiệm thật: `Reject` gửi 0 yêu cầu, `Approve` gửi đúng 1 yêu cầu an toàn;
  đường dẫn quản trị vẫn bị chặn.
- File kết quả không chứa dữ liệu nhạy cảm mẫu.
- Lần quét phát hành không có lỗi mức High.

AI không thể tự chọn địa chỉ, tự phê duyệt hoặc mở rộng phạm vi. Đây vẫn là lab:
công cụ chỉ nhận ra mẫu câu lệnh đã biết, chưa thay thế hệ thống bảo mật thật.
