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
- 235 bài kiểm thử thông thường đạt sau lần mở rộng dashboard; lượt demo thật
  đủ tám tình huống cũng đạt kỳ vọng.
- `Reject` gửi 0 yêu cầu; `Approve` gửi đúng 1 yêu cầu.
- Câu lệnh đáng ngờ bị cách ly; đường dẫn quản trị bị chặn.
- Báo cáo tách dữ liệu quét, phần AI viết, quyết định và kết quả.
- Giao diện phát lại tám tình huống đã xác minh; mỗi tình huống được trình bày
  qua tám bước và có nguồn của lượt demo.

## Giao diện E2E

Mục **E2E Week 6** có tám tab. Bốn tab đầu kiểm tra từ chối, phê duyệt, câu
lệnh đáng ngờ và truy cập quản trị. Bốn tab sau kiểm tra endpoint trạng thái,
dữ liệu sai kiểu, test case sai phạm vi và header không được phép. Thẻ **RUN**
ghi rõ lượt demo tạo ra dữ liệu đang xem.

Giao diện dùng dữ liệu mẫu sạch; không nhận API key, phê duyệt hoặc gửi yêu
cầu thật. Muốn chạy cả tám tình huống, dùng `--scenario-set extended` theo
hướng dẫn trong `README.md`, nhập `Reject`, `Approve`, `Approve`, rồi tạo lại
dữ liệu giao diện bằng:

```bash
python scripts/build_dashboard_replay.py "<demo-summary>"
```

Script chỉ nhận bản tổng kết `extended` đủ tám tình huống. Giao diện local cần
refresh hoặc build lại container. GitHub Pages chỉ cập nhật sau khi thay đổi
được commit, đưa vào `main` và workflow deploy hoàn tất.

## Trạng thái

Các chức năng chính đã có bằng chứng local. Giới hạn của lab: ZAP chỉ quét thụ
động `/health`, Keycloak chạy chế độ phát triển, số yêu cầu được nhớ riêng theo
từng tiến trình.

Bản cuối còn chờ commit sạch, CI trên GitHub và người khác chạy lại từ README.
Xem [phiếu nghiệm thu](release-acceptance.md).
