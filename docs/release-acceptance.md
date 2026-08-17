# Release acceptance còn cần owner/peer xác nhận

Code, automated evaluation và live Docker controls Week 6 đã có evidence. Ba
gate sau không được tự xác nhận bởi người triển khai và vì vậy vẫn mở trong
`docs/todo-checklist.md`.

## 1. Peer rerun (`DOC-08`)

Người không tham gia triển khai làm theo README từ clean checkout, sau đó ghi:

- Tên/ngày/môi trường: ____________________
- `project_sentinel preflight`: Pass / Fail
- deterministic dry-run: Pass / Fail
- evaluation 10 case: Pass / Fail
- full Docker + cleanup: Pass / Fail
- Vướng mắc hoặc bước README chưa rõ: ____________________

Không đưa secret, `.env` hoặc raw PII vào biên bản.

## 2. Rehearsal 10–15 phút (`DEMO-12`)

Chạy đúng `docs/demo-script.md` bằng đồng hồ:

- Bắt đầu/kết thúc: ____________________
- Tổng thời gian: ____________________
- Reject=0, Approve=1, admin=0: Pass / Fail
- Injection quarantine và redaction marker: Pass / Fail
- Cleanup sạch: Pass / Fail
- Fallback đã thử: Pass / Fail

Chỉ tick `DEMO-12` khi tổng thời gian nằm trong 10–15 phút và không bỏ control.

## 3. Version-control release (`DOC-09`, `REL-07`, `REL-11`)

Owner review toàn bộ thay đổi Week 5–6, stage/commit theo policy của repository,
sau đó chạy lại:

```powershell
git diff --check
git rev-parse HEAD
git status --porcelain
git ls-files --error-unmatch docs/todo-checklist.md
python -m pytest -q -m "not integration"
python scripts/run_all_tests.py
```

Dashboard, evidence và report phải thuộc cùng release commit; `git status` sạch
hoặc chỉ còn thay đổi được giải thích trong evidence mới. Không sửa log hiện tại
để giả base revision đã commit—tạo lần verification mới trên commit thật.
