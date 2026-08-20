# Phiếu nghiệm thu bản bàn giao

Phiếu này chỉ dành cho những gate không thể tự đóng trong lúc đang sửa project.
Mọi mục bên dưới hiện ở trạng thái **chờ xác nhận**. Người xác nhận điền bằng
chứng thật rồi mới cập nhật [`todo-checklist.md`](todo-checklist.md).

| Gate | Người xác nhận | Trạng thái |
|---|---|---|
| `DOC-08` — chạy lại từ clean checkout | Peer độc lập | Chờ |
| `DOC-09`, `REL-07`, `REL-11` — final commit, hosted CI và file được quản lý bởi Git | Owner | Chờ |
| `DEMO-12` — diễn tập demo | Người thực hiện/peer theo yêu cầu nghiệm thu | Chờ |

## 1. Final commit và hosted CI (`DOC-09`, `REL-07`, `REL-11`)

Owner chỉ xác nhận sau khi đã commit toàn bộ file bàn giao và đẩy đúng nhánh để
hosted CI chạy trên chính commit đó.

- Nhánh: ____________________
- Final commit SHA: ____________________
- URL hosted CI: ____________________
- Kết quả full Docker trên final commit: ____________________
- Evidence mới gắn với commit: ____________________
- Kết quả cleanup: ____________________
- Người/ngày xác nhận: ____________________

Lệnh kiểm tra tối thiểu:

```powershell
git diff --check
git status --porcelain
git rev-parse HEAD
git ls-files --error-unmatch docs/todo-checklist.md docs/release-acceptance.md
python scripts/run_all_tests.py
```

Điều kiện đóng gate: working tree sạch; mọi file bàn giao được Git theo dõi;
full Docker và hosted CI cùng đạt trên final commit; evidence ghi đúng commit
đó. Không sửa evidence cũ để thay đổi revision lịch sử.

## 2. Peer chạy lại từ clean checkout (`DOC-08`)

Peer không tham gia triển khai làm theo [`README.md`](../README.md) trong một
thư mục checkout mới, không dùng artifact hoặc môi trường ảo từ workspace của
người phát triển.

- Peer/ngày/môi trường: ____________________
- Commit được checkout: ____________________
- Cài đặt và preflight: ____________________
- Deterministic dry-run: ____________________
- Evaluation: ____________________
- Full Docker và cleanup: ____________________
- Bước khó hiểu hoặc lỗi tái lập: ____________________
- Kết luận `DOC-08`: Pass / Fail

Không ghi secret, nội dung `.env` hoặc PII thô vào phiếu/evidence.

## 3. Diễn tập demo (`DEMO-12`)

### Technical rehearsal

Chạy đúng [`demo-script.md`](demo-script.md), bấm giờ và lưu evidence kỹ thuật.
Việc đã chạy tự động không đồng nghĩa gate được tự động đánh dấu đạt.

- Người chạy/ngày: local automated rehearsal, 20/08/2026
- Tổng thời gian kỹ thuật: 179.4 giây gồm stack lifecycle; bốn live scenario
  dùng 12.735 giây
- Evidence: [`pre-release-verification-2026-08-20.log`](../evidence/week-6/pre-release-verification-2026-08-20.log)
- Reject không gửi request: Pass
- Approve gửi đúng một request: Pass
- Admin bị chặn trước network: Pass
- Prompt injection được quarantine và dữ liệu nhạy cảm được redact: Pass
- Cleanup và phương án fallback: Pass

### Trình bày với peer (nếu yêu cầu nghiệm thu)

- Peer/ngày: ____________________
- Thời lượng: ____________________
- Phản hồi hoặc lỗi cần sửa: ____________________
- Kết luận `DEMO-12`: Pass / Fail

Chỉ đóng `DEMO-12` sau khi người chịu trách nhiệm nghiệm thu đã xem evidence,
xác nhận thời lượng phù hợp và không có control bắt buộc nào bị bỏ qua.
