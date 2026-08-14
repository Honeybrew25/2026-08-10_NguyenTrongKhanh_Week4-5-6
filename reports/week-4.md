# Báo cáo tuần 4 - Kiểm thử API an toàn qua Gateway

## Mục tiêu

Trong tuần 4, em xây dựng chức năng giúp Agent thực hiện các yêu cầu GET/POST an
toàn qua API Gateway. Agent chỉ được chạy những bài kiểm thử đã cho phép và
không làm lộ API key trong log.

## Quá trình

- Em giữ Envoy và `ext_authz` làm lớp bảo vệ chính, đồng thời thêm API key riêng
  cho `safe-api-tool` mà không ảnh hưởng đến cơ chế JWT hiện có.
- Tạo policy để kiểm soát bài test, URL, dữ liệu và thông tin đăng nhập mà
  Agent được sử dụng.
- Bổ sung hai bài test GET/POST với giới hạn về số lần gọi, thời gian chờ và
  kích thước dữ liệu. Hệ thống chỉ chạy thật khi có tùy chọn `--execute`.
- Kiểm tra việc che secret trong log, xử lý các trường hợp lỗi và lưu
  kết quả chạy thử trong CI.

## Kết quả

- Kết quả được trình bày tại [UI Dashboard](https://honeybrew25.github.io/2026-08-10_NguyenTrongKhanh_Week4-5-6/);
  cách chạy trên máy có trong [tài liệu Dashboard](../docs/ui-dashboard.md).
- Khi thử qua Envoy, yêu cầu GET và POST hợp lệ đều trả về 200; yêu cầu quyền
  `admin` bị chặn trước khi kết nối ra ngoài.
- Hệ thống xử lý đúng các trường hợp API key sai (401), dữ liệu quá lớn (413),
  gọi quá nhiều lần (429), sai đường dẫn/phương thức và lỗi kết nối.

## Kết luận

Hệ thống đã có quy trình từ thu thập, phân tích lỗ hổng đến kiểm thử lại qua API.
Agent giúp tự động hóa công việc nhưng vẫn hoạt động trong phạm vi an toàn đã
được cấu hình.
