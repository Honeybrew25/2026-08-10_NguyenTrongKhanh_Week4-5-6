# Báo cáo bổ sung - Kết luận toàn dự án Project Sentinel

## Mục tiêu

Tổng kết quá trình từ tuần 1 đến tuần 6, đồng thời nêu rõ
kết quả đã đạt, điểm mạnh và phần còn giới hạn.

## Quá trình

- Tuần 1 tạo môi trường chạy bằng Docker và lấy kết quả thật từ Bandit, ZAP.
- Tuần 2 đưa hai loại báo cáo về cùng một dạng và tạo kho tra cứu lỗi bảo mật.
- Tuần 3 gộp các cảnh báo giống nhau, giải thích vấn đề nhưng vẫn giữ nguồn ban
  đầu để kiểm tra lại.
- Tuần 4 thêm công cụ kiểm tra API, chỉ dùng đường dẫn và dữ liệu đã chuẩn bị.
- Tuần 5 bổ sung che dữ liệu nhạy cảm, cách ly chỉ dẫn xấu và yêu cầu người dùng
  phê duyệt trước khi gửi.
- Tuần 6 nối tất cả thành một luồng demo hoàn chỉnh, có đánh giá, báo cáo và
  giao diện trình bày.

## Kết quả

- Bandit tìm 41 cảnh báo mức Low, được gộp thành 6 nhóm; không có mức High.
- Bộ đánh giá đạt 10/10 với TP=6, FP=0, FN=0.
- Kiểm thử trên máy đạt 216 bài; bằng chứng Docker gần nhất ghi nhận 244 bài đạt.
- `Reject` không gửi yêu cầu; `Approve` chỉ gửi đúng một yêu cầu qua Envoy.
- Phản hồi chứa chỉ dẫn xấu bị cách ly; `/api/admin` bị chặn trước khi gửi.
- Kết quả chạy lặp đã được dọn, chỉ giữ dữ liệu chuẩn và bộ kết quả cuối.

## Kết luận

Project Sentinel đi từ một ứng dụng có kết quả quét rời rạc thành một sản phẩm
có quy trình rõ ràng: nhận cảnh báo, gộp dữ liệu, giải thích, đề xuất kiểm tra,
xin phê duyệt và lưu báo cáo cuối. Mỗi tuần giải quyết một phần của bài toán nên
kết quả cuối có thể giải thích và kiểm tra lại, thay vì chỉ là một bản demo AI.

Điểm quan trọng nhất của sản phẩm là AI không được tự quyết định hành động. AI
chỉ hỗ trợ giải thích; code giới hạn đường dẫn và dữ liệu; người dùng quyết định
có gửi hay không; Envoy kiểm tra lại trước khi yêu cầu đến ứng dụng. Mỗi bước
đều có nguồn và kết quả đối chiếu. Đây là phần thể hiện rõ tư duy an toàn của dự
án và cũng là giá trị chính khi trình bày với mentor.

Sản phẩm hiện đủ để demo và bàn giao trong môi trường học tập. Tuy nhiên, ZAP
mới quét thụ động, Keycloak còn chạy chế độ phát triển và giới hạn số yêu cầu
chưa dùng chung khi mở rộng. Trước khi gọi là bản phát hành cuối, dự án vẫn cần
CI đạt trên commit sạch và một người khác chạy lại theo README.
