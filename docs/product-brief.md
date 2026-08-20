# Tóm tắt sản phẩm — Project Sentinel

## 1. Vấn đề

Bandit và ZAP tạo báo cáo khác nhau, còn AI có thể giải thích sai hoặc làm theo
chỉ dẫn xấu. Project Sentinel gộp các báo cáo và minh họa kiểm thử an toàn,
không tự khai thác lỗ hổng.

## 2. Người dùng

- Sinh viên hoặc nhóm bảo mật cần demo toàn bộ quy trình.
- Lập trình viên cần báo cáo dễ đọc và có nguồn.
- Người nghiệm thu cần kết quả cùng lệnh chạy lại.

## 3. Giải pháp

Hệ thống đưa kết quả Bandit/ZAP về cùng một dạng, gộp cảnh báo trùng và tạo báo
cáo. Phần AI chỉ giải thích dữ kiện.

Trước khi gửi, code kiểm tra đường dẫn và mẫu thử, chờ `Approve`, rồi kiểm tra
lại tại Envoy. Chỉ dẫn độc hại bị cách ly, dữ liệu nhạy cảm bị che. Mỗi lần chạy
có mã để nối nguồn, quyết định và kết quả.

## 4. Phạm vi hiện tại

Sản phẩm gồm:

- quét Bandit và ZAP thụ động trong CI;
- kho kiến thức 17 tài liệu và chế độ phân tích cố định hoặc Gemini;
- bốn mẫu thử có sẵn, không cho nhập URL hay nội dung tùy ý;
- phê duyệt `Approve/Reject`, có thời hạn và dùng một lần;
- Envoy, dịch vụ kiểm quyền, Keycloak và API key cho lab;
- cách ly chỉ dẫn độc hại, che dữ liệu, báo cáo và nhật ký;
- bộ đánh giá 10 trường hợp, kiểm thử tự động và giao diện demo.

Có thể chạy thử không gửi yêu cầu. Giao diện chỉ phát lại dữ liệu sạch; thao
tác thật chạy trên terminal.

Không thuộc phạm vi: khai thác thật, môi trường thật, nhiều AI tự phối hợp, GPU
riêng hoặc dùng AI tự chấm AI.

## 5. Điều kiện hoàn thành

- Kết quả quét mới được xử lý trong cùng lần chạy và có mã đối chiếu.
- Dữ liệu sai hoặc lỗi dịch vụ tạo nội dung/cổng Envoy đều dừng an toàn.
- `Reject` gửi 0 yêu cầu; `Approve` gửi đúng 1 yêu cầu qua Envoy.
- Đường dẫn ngoài danh sách gửi 0 yêu cầu và không tự chuyển hướng.
- Nội dung xấu và dữ liệu nhạy cảm không có trong báo cáo cuối.
- Bộ đánh giá đạt 10/10, TP=6, FP=0, FN=0 và giữ đủ nguồn.
- Người khác có thể làm theo README, chạy lại và dọn môi trường sạch.

## 6. Hạn chế và hướng phát triển

Đây là môi trường học tập: Keycloak chạy chế độ dev, dùng HTTP nội bộ; giới hạn
tốc độ theo từng tiến trình; ZAP chưa đăng nhập. Bộ lọc dựa vào mẫu chữ và dữ
liệu đánh giá còn nhỏ. Gemini không dùng trong bản phát hành.

Bước tiếp theo là quét ZAP có đăng nhập, kiểm tra thư viện/image Docker, quản lý
thông tin bí mật tốt hơn và mở rộng bộ đánh giá. Mọi phần AI mới vẫn phải giữ
phê duyệt và nhật ký.
