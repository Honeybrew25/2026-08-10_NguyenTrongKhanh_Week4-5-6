# Báo cáo tuần 5 - Guardrails và Human-in-the-Loop

## Mục tiêu

Trong tuần 5, em bổ sung các ranh giới để HTTP response không điều khiển Agent,
dữ liệu nhạy cảm không đi vào prompt/log và POST chỉ được thực thi sau quyết
định Approve hợp lệ của người dùng.

## Quá trình

Hệ thống được bổ sung ba lớp bảo vệ chính:

- che email, số điện thoại, mật khẩu và mã truy cập trước khi gửi cho AI hoặc
  ghi vào báo cáo;
- không làm theo các câu lệnh đáng ngờ nằm trong nội dung trả về từ website;
- hỏi người dùng trước khi gửi yêu cầu có thể làm thay đổi dữ liệu.

Khi người dùng chọn `Reject`, hệ thống dừng lại và không gửi yêu cầu. Khi chọn
`Approve`, hệ thống chỉ gửi đúng yêu cầu đã được hiển thị, trong phạm vi cho
phép và qua cổng bảo vệ. Quyết định phê duyệt có thời hạn, chỉ dùng một lần và
không thể chuyển sang yêu cầu khác.

## Kết quả

- 183 bài kiểm thử thông thường đã đạt.
- 211 bài kiểm thử đầy đủ với Docker đã đạt.
- Thử nghiệm thực tế xác nhận `Reject` không gửi yêu cầu và `Approve` chỉ gửi
  đúng một yêu cầu an toàn.
- Đường dẫn quản trị vẫn bị chặn.
- Các file kết quả đã được kiểm tra và không chứa thông tin nhạy cảm mẫu.
- Không phát hiện lỗi mức nghiêm trọng cao trong lần quét phát hành.

## Kết luận

Sau tuần 5, AI không thể tự chọn địa chỉ, tự phê duyệt hoặc tự mở rộng phạm vi
kiểm thử. Nội dung từ website cũng chỉ được xem là dữ liệu tham khảo, không
được phép điều khiển hệ thống.



