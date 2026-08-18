# Project Sentinel — Week 5

Branch `week-5` tập trung làm cho việc kiểm thử API an toàn hơn trước khi ghép
thành sản phẩm hoàn chỉnh ở Week 6.

Hệ thống có thể:

- che email, số điện thoại, mật khẩu và mã truy cập khỏi AI và file log;
- xem nội dung trả về từ website là dữ liệu không đáng tin cậy;
- cách ly nội dung cố hướng dẫn AI làm sai;
- yêu cầu người dùng chọn `Approve` hoặc `Reject` trước khi gửi POST;
- chỉ cho phép đúng đường dẫn và dữ liệu kiểm thử đã định nghĩa sẵn;
- chặn yêu cầu quản trị hoặc yêu cầu nằm ngoài phạm vi.

Giao diện web chỉ dùng để trình bày. Việc phê duyệt và gửi yêu cầu được thực
hiện bằng dòng lệnh.

## Cài đặt lần đầu

Cần có Python 3.11+, Git và Docker Compose.

Trên PowerShell/Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --requirement requirements-dev.txt
python -m pip install --requirement security/requirements.txt
Copy-Item .env.example .env
```

Trên Bash/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --requirement requirements-dev.txt
python -m pip install --requirement security/requirements.txt
cp .env.example .env
```

Mở `.env` và thay các giá trị bắt đầu bằng `replace-with-`.
`SAFE_API_TOOL_API_KEY` cần dài ít nhất 32 ký tự. Không đưa `.env` lên Git.

Kiểm tra cấu hình:

```bash
docker version
docker compose version
docker compose config --quiet
```

## Chạy demo Week 5

Demo chỉ kiểm tra policy, không gửi yêu cầu mạng:

```bash
python -m safe_api_tool demo
```

Demo đầy đủ:

```bash
docker compose down --remove-orphans
docker compose up --build --detach --wait --wait-timeout 180
python -m safe_api_tool demo --execute
```

Khi chương trình hỏi, nhập theo thứ tự:

1. `Reject` để xác nhận không có POST nào được gửi.
2. `Approve` để gửi đúng một POST an toàn qua Gateway.

Kết quả của demo được ghi trong bốn file:

- `security-results/runs/week-5/safe-api-receipts.jsonl`: kết quả thực thi và
  mã HTTP;
- `security-results/runs/week-5/approval-decisions.jsonl`: quyết định Reject
  hoặc Approve;
- `security-results/runs/week-5/guarded-responses.jsonl`: phản hồi đã được kiểm
  tra prompt injection và che dữ liệu nhạy cảm;
- `security-results/runs/week-5/run-events.jsonl`: các bước xử lý của từng lần
  chạy.

Các file log chỉ giữ dữ liệu đã che và không lưu API key. Những file có hậu tố
`-ci` được tạo bởi full test/CI, không phải bởi lệnh demo thủ công ở trên.

## Kiểm thử

Kiểm thử nhanh của riêng snapshot:

```bash
python -m pytest -q -m "not integration"
```

Kết quả kiểm tra : `177 passed, 28 deselected`.

Kiểm thử đầy đủ với Docker:

```bash
python scripts/run_all_tests.py
```

Dừng và dọn hệ thống:

```bash
docker compose down --remove-orphans
docker compose ps --all
```

## Tài liệu

- [Thiết kế bảo vệ Week 5](docs/week5.md)
- [Kết quả kiểm tra nền](docs/security-baseline-triage.md)
- [Công cụ kiểm thử API](docs/safe-api-testing-tool.md)
- [Báo cáo Week 5](reports/week-5.md)
- [Bằng chứng kiểm thử](evidence/week-5/verification.log)
