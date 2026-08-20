# Tuần 5

## Tuần này làm gì?

Tuần 5 tập trung làm cho việc kiểm thử API an toàn hơn. Hệ thống được bổ sung
ba lớp bảo vệ chính:

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

## Ý nghĩa

Sau tuần 5, AI không thể tự chọn địa chỉ, tự phê duyệt hoặc tự mở rộng phạm vi
kiểm thử. Nội dung từ website cũng chỉ được xem là dữ liệu tham khảo, không
được phép điều khiển hệ thống.

Đây vẫn là sản phẩm thử nghiệm trong môi trường lab. Bộ nhận diện câu lệnh đáng
ngờ chỉ bao phủ các mẫu đã xác định và chưa thay thế một giải pháp bảo mật dùng
cho môi trường thật.

