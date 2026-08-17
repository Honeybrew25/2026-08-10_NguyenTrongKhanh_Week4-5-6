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

## Chọn đúng branch

```bash
git switch week-5
```

Branch này không có lệnh `project_sentinel` hoặc bộ đánh giá Week 6. Các phần
đó nằm trong branch `week-6`.

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

Demo khô chỉ kiểm tra policy, không gửi yêu cầu mạng:

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

Kết quả được ghi trong `security-results/runs/week-5/`. File log chỉ giữ dữ
liệu đã che và không lưu API key.

## Kiểm thử

Kiểm thử nhanh của riêng snapshot branch này:

```bash
python -m pytest -q -m "not integration"
```

Kết quả kiểm tra khi tách branch: `177 passed, 28 deselected`.

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

- [Tóm tắt Week 5](docs/week5-summary.md)
- [Thiết kế bảo vệ Week 5](docs/week5.md)
- [Kết quả kiểm tra nền](docs/security-baseline-triage.md)
- [Công cụ kiểm thử API](docs/safe-api-testing-tool.md)
- [Báo cáo Week 5](reports/week-5.md)
- [Bằng chứng kiểm thử](evidence/week-5/verification.log)

Muốn chạy sản phẩm hoàn chỉnh, chuyển sang branch `week-6`:

```bash
git switch week-6
```
