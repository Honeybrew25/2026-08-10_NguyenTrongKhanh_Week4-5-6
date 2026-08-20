# Project Sentinel — Week 6

Hệ thống có thể:

- nhận kết quả từ Bandit và ZAP;
- gộp các cảnh báo giống nhau;
- dùng AI để giải thích và đề xuất cách kiểm tra;
- hỏi người dùng trước khi gửi yêu cầu có rủi ro;
- chặn đường dẫn ngoài phạm vi và che thông tin nhạy cảm;
- lưu báo cáo để kiểm tra lại sau này.

Giao diện web chỉ dùng để trình bày. Việc phê duyệt và gửi yêu cầu kiểm thử
được thực hiện bằng dòng lệnh.

## Kết quả hiện tại

- 41 cảnh báo được gộp thành 6 nhóm.
- Bộ đánh giá đạt 10/10 trường hợp.
- 200 bài kiểm thử thông thường và 228 bài kiểm thử đầy đủ đã đạt.

Xem số liệu chi tiết tại
[`evidence/week-6/verification.log`](evidence/week-6/verification.log).

## Cài đặt lần đầu

Cần có Python 3.11+, Git và Docker Compose. Trên Windows có thể dùng Docker
Desktop; trên Linux dùng Docker Engine cùng Compose plugin.

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

Xác nhận Docker đã sẵn sàng:

```bash
docker version
docker compose version
docker compose config --quiet
```

Docker daemon phải đang chạy và tài khoản hiện tại phải gọi được `docker`.
Nếu dùng WSL2 với Docker Desktop, cần bật WSL integration cho bản Linux đang
dùng.

Mở `.env` và thay các giá trị bắt đầu bằng `replace-with-`. Giá trị
`SAFE_API_TOOL_API_KEY` cần dài ít nhất 32 ký tự. Không đưa `.env` lên Git.

Kiểm tra môi trường:

```bash
python -m project_sentinel preflight
```

## Chạy demo

### Demo nhanh, không gửi yêu cầu mạng

```bash
python -m project_sentinel demo --provider deterministic
```

Lệnh này quét, phân tích và tạo báo cáo trong
`security-results/runs/week-6/`. Chế độ `deterministic` cho kết quả ổn định và
không cần dịch vụ AI bên ngoài.

### Demo đầy đủ có phê duyệt

```bash
docker compose down --remove-orphans
docker compose up --build --detach --wait --wait-timeout 180
python -m project_sentinel preflight --execute
python -m project_sentinel demo --provider deterministic --execute
```

Khi được hỏi:

1. Nhập `Reject` ở lần đầu để chứng minh không có yêu cầu nào được gửi.
2. Nhập `Approve` ở lần sau để gửi đúng một yêu cầu kiểm thử an toàn.

### Chạy bộ đánh giá

```bash
python -m project_sentinel evaluate --provider deterministic
```

Kết quả đúng sẽ có `passed: 10`, `failed: 0` và `thresholds_met: true`.

### Mở giao diện

Khi Docker đang chạy, mở <http://localhost:8080/ui/>.

Giao diện không lưu API key và không tự gửi yêu cầu kiểm thử.

## Kiểm thử và dọn hệ thống

Kiểm thử nhanh:

```bash
python -m pytest -q -m "not integration"
```

Kiểm thử đầy đủ:

```bash
python scripts/run_all_tests.py
```

Dừng và dọn Docker:

```bash
docker compose down --remove-orphans
docker compose ps --all
```

## Lỗi thường gặp

- `gateway_preflight_timeout`: chạy `docker compose ps`, sau đó xem log bằng
  `docker compose logs --no-color --tail 200`.
- Báo lỗi API key: kiểm tra lại `SAFE_API_TOOL_API_KEY` trong `.env`.
- `FileExistsError`: lần chạy đó đã tồn tại; hãy dùng tên mới hoặc bỏ
  `--run-id`.
- Bandit trả mã `1`: thường là đã tìm thấy cảnh báo nhưng file kết quả vẫn được
  tạo bình thường.

## Tài liệu thêm

- [Kiến trúc](docs/project-sentinel-architecture.md)
- [Bộ đánh giá 10 trường hợp](docs/evaluation.md)
- [Báo cáo Week 6](reports/week-6.md)
- [Kịch bản demo 10–15 phút](docs/demo-script.md)
- [Bằng chứng kiểm thử](evidence/week-6/verification.log)
- [Các bước còn cần xác nhận](docs/release-acceptance.md)

Dashboard công khai:
<https://honeybrew25.github.io/2026-08-10_NguyenTrongKhanh_Week4-5-6/>.
