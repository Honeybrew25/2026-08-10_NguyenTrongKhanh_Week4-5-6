# Báo cáo tuần 5 - Guardrails và Human-in-the-Loop

## Mục tiêu

Bổ sung các ranh giới để HTTP response không điều khiển Agent,
dữ liệu nhạy cảm không đi vào prompt/log và POST chỉ được thực thi sau quyết
định Approve hợp lệ của người dùng.

## Quá trình

- Tạo sanitizer dùng chung cho Agent, planner, CLI, approval, response và log;
  hỗ trợ email, số điện thoại lab, token, API key, password và PII có khóa/mẫu
  đã định nghĩa.
- Tạo state machine cùng contract riêng cho risk, approval, guarded response
  và run event..- Thêm exact GET fixture mô phỏng prompt injection, detector/quarantine và
  benign control. Response không thể sinh proposal, tự approve hoặc gọi thêm
  endpoint/tool.
- Đổi demo thật thành hai run tách biệt: Reject để chứng minh không gọi mạng,
  sau đó Approve để gửi đúng một bounded POST qua Envoy.

## Kết quả

- Che email, số điện thoại, mật khẩu và mã truy cập trước khi gửi cho AI hoặc
  ghi vào báo cáo;
- Không làm theo các câu lệnh đáng ngờ nằm trong nội dung trả về từ website;
- Hỏi người dùng trước khi gửi yêu cầu có thể làm thay đổi dữ liệu.
- Thử nghiệm thực tế xác nhận `Reject` không gửi yêu cầu và `Approve` chỉ gửi
  đúng một yêu cầu an toàn.

## Kết luận

Với việc chống Prompt Injection AI không thể tự chọn mục tiêu, tự phê duyệt hoặc tự mở rộng phạm vi
kiểm thử. Mọi nội dung từ website chỉ được xem là dữ liệu tham khảo, không
được phép điều khiển hệ thống.
Đối với request POST hoặc request có payload đặc biệt cần con người đưa ra quyết định.
Dữ liệu nhạy cảm không xuất hiện trong prompt hoặc log.


