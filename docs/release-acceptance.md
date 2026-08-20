# Phiếu nghiệm thu bản bàn giao

Các mục sau vẫn **chờ xác nhận**. Chỉ cập nhật
[`todo-checklist.md`](todo-checklist.md) khi có bằng chứng.

| Mục | Người xác nhận | Trạng thái |
|---|---|---|
| `DOC-08` — chạy lại từ bản mã mới tải về | Người kiểm tra độc lập | Chờ |
| `DOC-09`, `REL-07`, `REL-11` — commit cuối, CI và Git theo dõi đủ file | Chủ project | Chờ |
| `DEMO-12` — diễn tập demo | Người thực hiện hoặc người kiểm tra | Chờ |

## 1. Commit cuối và CI (`DOC-09`, `REL-07`, `REL-11`)

- Nhánh: ____________________
- Commit SHA: ____________________
- Link CI: ____________________
- Kết quả kiểm thử đầy đủ với Docker: ____________________
- Bằng chứng gắn với commit: ____________________
- Kết quả dọn môi trường: ____________________
- Người/ngày xác nhận: ____________________

Lệnh kiểm tra:

```powershell
git diff --check
git status --porcelain
git rev-parse HEAD
git ls-files --error-unmatch docs/todo-checklist.md docs/release-acceptance.md
python scripts/run_all_tests.py
```

Đạt khi cây làm việc sạch, Git theo dõi đủ file, Docker và CI đạt trên commit
cuối. Không sửa bằng chứng cũ.

## 2. Người khác chạy lại (`DOC-08`)

Người không tham gia code làm theo [README](../README.md) từ thư mục mới, không
dùng lại kết quả hay môi trường ảo cũ.

- Người kiểm tra/ngày/môi trường: ____________________
- Commit đã tải về: ____________________
- Cài đặt và preflight: ____________________
- Chạy thử ở chế độ cố định: ____________________
- Đánh giá 10 trường hợp: ____________________
- Kiểm thử đầy đủ với Docker và dọn môi trường: ____________________
- Bước khó hiểu hoặc lỗi: ____________________
- Kết luận `DOC-08`: Pass / Fail

Không ghi `.env`, thông tin bí mật hoặc dữ liệu cá nhân vào phiếu.

## 3. Diễn tập demo (`DEMO-12`)

Phần kỹ thuật đã chạy theo [`demo-script.md`](demo-script.md):

- Ngày chạy: 20/08/2026.
- Tổng thời gian: 179,4 giây; bốn tình huống thật mất 12,735 giây.
- Bằng chứng: [`pre-release-verification-2026-08-20.log`](../evidence/week-6/pre-release-verification-2026-08-20.log).
- Reject gửi 0 yêu cầu: Đạt.
- Approve gửi đúng 1 yêu cầu: Đạt.
- `/api/admin` bị chặn trước khi gửi: Đạt.
- Chỉ dẫn độc hại bị cách ly, dữ liệu nhạy cảm được che: Đạt.
- Dọn môi trường và phương án dự phòng: Đạt.

Kết quả tự động chưa tự đóng `DEMO-12`. Người nghiệm thu điền thêm:

- Người kiểm tra/ngày: ____________________
- Thời lượng trình bày: ____________________
- Phản hồi hoặc lỗi cần sửa: ____________________
- Kết luận `DEMO-12`: Pass / Fail

Chỉ đóng mục này sau khi người chịu trách nhiệm chấp nhận bằng chứng, thời lượng
và các bước an toàn.
