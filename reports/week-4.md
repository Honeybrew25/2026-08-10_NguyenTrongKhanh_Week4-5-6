# Báo cáo Week 4 — Safe API Testing qua Gateway

## Mục tiêu

Cho phép Agent đề xuất và thực thi GET/POST an toàn qua API Gateway, với API
key riêng, exact allowlist, resource budget, error handling và log không lộ
secret.

## Quá trình

- Giữ Envoy + ext_authz làm cổng bảo vệ chính, đồng thời thêm API key riêng cho safe-api-tool mà không làm thay đổi quyền JWT hiện có.
- Tạo bộ policy và schema rõ ràng để tool chỉ được chọn các bài test an toàn có sẵn; URL, dữ liệu gửi đi và thông tin đăng nhập đều do code kiểm soát.
- Bổ sung 2 API test an toàn, kèm các giới hạn như rate limit, timeout, kích thước request/response và tắt redirect để tránh hành vi ngoài dự kiến.
- Dùng các finding đã được xác minh để tự động lập kế hoạch test, nhưng CLI mặc định chỉ chạy thử; muốn chạy thật phải dùng --execute.
- Thêm các lớp kiểm tra an toàn như phát hiện secret, test tình huống xấu, canary kiểm tra API key và lưu kết quả demo trong CI để dễ kiểm chứng.

## Kết quả

- **120 non-integration test pass**; full Docker suite **140 test pass**.
- Demo thật qua Envoy tạo ba receipt: GET 200, POST 200 và capability `admin`
  bị `policy_denied` trước network.
- Key sai/thiếu bị 401; route/method lạ bị deny; body vượt 4 KiB bị Gateway trả
  413 trước authz/app; burst trả typed 429; status sai, timeout, connection
  error và oversized response đều có outcome kiểm soát.

## Kết luận

Qua 4 tuần, hệ thống đi từ thu thập dữ liệu quét → chuẩn hóa → phân tích → kiểm thử an toàn. Agent chỉ hỗ trợ chọn và thực hiện các bước xác minh đã được giới hạn sẵn, còn URL, dữ liệu kiểm thử và thông tin đăng nhập vẫn do hệ thống kiểm soát, giúp quá trình an toàn và dễ kiểm chứng hơn.
