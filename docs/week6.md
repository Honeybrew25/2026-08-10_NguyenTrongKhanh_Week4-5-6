# Tuần 6 — Hoàn thiện quy trình demo

> Bắt đầu từ [README](../README.md) để chạy demo và xem bằng chứng.

## Đã làm

Tuần 6 nối các phần trước thành một quy trình:

1. nhận kết quả quét;
2. gộp cảnh báo giống nhau;
3. tạo giải thích và đề xuất kiểm tra;
4. hỏi người dùng khi cần;
5. gửi yêu cầu qua cổng bảo vệ;
6. lưu kết quả và tạo báo cáo.

Có lệnh demo, 10 trường hợp đánh giá và cách chạy Docker. Mỗi lần chạy lưu mã,
thời gian và dấu kiểm tra file.

## Kết quả

- 41 cảnh báo được gộp thành 6 nhóm.
- Đánh giá đạt 10/10: 5 trường hợp Agent, 5 trường hợp xử lý; TP=6, FP=0, FN=0.
- 216 bài kiểm thử thông thường và 244 bài kiểm thử đầy đủ đã đạt.
- `Reject` gửi 0 yêu cầu; `Approve` gửi đúng 1 yêu cầu.
- Câu lệnh đáng ngờ bị cách ly; đường dẫn quản trị bị chặn.
- Báo cáo tách dữ liệu quét, phần AI viết, quyết định và kết quả.
- Giao diện và terminal trình bày bốn tình huống qua tám bước; JSON được giữ
  riêng cho script và CI.

## Giao diện E2E

Mục **E2E Week 6** phát lại bốn tình huống: từ chối, phê duyệt, câu lệnh đáng
ngờ và truy cập quản trị. Bấm từng bước để biết quy trình tiếp tục hay dừng.

Giao diện dùng dữ liệu mẫu sạch; không nhận API key, phê duyệt hoặc gửi yêu
cầu thật. Muốn chạy thật, dùng lệnh trong `README.md`.

## Trạng thái

Các chức năng chính đã có bằng chứng local. Giới hạn của lab: ZAP chỉ quét thụ
động `/health`, Keycloak chạy chế độ phát triển, số yêu cầu được nhớ riêng theo
từng tiến trình.

Bản cuối còn chờ commit sạch, CI trên GitHub và người khác chạy lại từ README.
Xem [phiếu nghiệm thu](release-acceptance.md).
