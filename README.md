# Project Sentinel — Week 6

Hệ thống có thể:

- nhận kết quả từ Bandit và ZAP;
- gộp các cảnh báo giống nhau;
- dùng AI để giải thích và đề xuất cách kiểm tra;
- hỏi người dùng trước khi gửi yêu cầu có rủi ro;
- chặn đường dẫn ngoài phạm vi và che thông tin nhạy cảm;
- lưu báo cáo để kiểm tra lại sau này.

Giao diện web cho phép xem lại bốn tình huống mẫu của quy trình Week 6 theo
từng bước. Việc phê duyệt và gửi yêu cầu thật vẫn được thực hiện bằng dòng lệnh.

## Kết quả hiện tại

- 41 cảnh báo được gộp thành 6 nhóm.
- Bộ đánh giá đạt 10/10 trường hợp, gồm 5 case Agent và 5 case hành vi.
- 216 bài kiểm thử thông thường và 244 bài kiểm thử đầy đủ đã đạt.

Xem số liệu chi tiết tại
[`evidence/week-6/pre-release-verification-2026-08-20.log`](evidence/week-6/pre-release-verification-2026-08-20.log).
Đây là kết quả trên working tree hiện tại; phiếu nghiệm thu cuối vẫn chờ commit
sạch, hosted CI và một người khác chạy lại từ README.
`reports/week-6.md` được giữ như snapshot của lúc kết thúc tuần, nên số test cũ
trong đó không thay thế kết quả pre-release ở trên.

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
python -m project_sentinel demo --provider deterministic --format human
```

Lệnh này quét, phân tích và tạo báo cáo trong
`security-results/runs/week-6/`. Chế độ `deterministic` cho kết quả ổn định và
không cần dịch vụ AI bên ngoài.

### Demo đầy đủ có phê duyệt

```bash
docker compose down --remove-orphans
docker compose up --build --detach --wait --wait-timeout 180
python -m project_sentinel preflight --execute
python -m project_sentinel demo --provider deterministic --execute --format human
```

Khi được hỏi:

1. Nhập `Reject` ở lần đầu để chứng minh không có yêu cầu nào được gửi.
2. Nhập `Approve` ở lần sau để gửi đúng một yêu cầu kiểm thử an toàn.

Terminal hiển thị đủ tám bước, kết quả ngay sau từng tình huống và bảng tổng
kết cuối. Xem [hướng dẫn terminal](docs/terminal-demo.md) để biết cách
đọc từng trạng thái.

### Chạy bộ đánh giá

```bash
python -m project_sentinel evaluate --provider deterministic
```

Kết quả đúng sẽ có `passed: 10`, `failed: 0` và `thresholds_met: true`.

### Mở giao diện

Khi Docker đang chạy, mở <http://localhost:8080/ui/>.

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

- `gateway_preflight_timeout`: demo đã dừng trước khi gửi request kiểm thử. Chạy
  `docker compose ps`, kiểm tra `curl http://127.0.0.1:8080/health`, rồi xem log
  bằng `docker compose logs --no-color --tail 200 envoy authz-service api`.
- Nếu cần dừng lúc chương trình đang chờ, nhấn `Ctrl+C`. Terminal sẽ báo
  `interrupted` thay vì in traceback; hãy chạy lại lệnh `preflight` trước khi
  thử lại.
- Báo lỗi API key: kiểm tra lại `SAFE_API_TOOL_API_KEY` trong `.env`.
- `FileExistsError`: lần chạy đó đã tồn tại; hãy dùng tên mới hoặc bỏ
  `--run-id`.
- Bandit trả mã `1`: thường là đã tìm thấy cảnh báo nhưng file kết quả vẫn được
  tạo bình thường.

## Tài liệu thêm

- [Kiến trúc](docs/architecture.md)
- [Kết quả đánh giá](docs/evaluation.md)
- [Báo cáo Week 6 (snapshot lịch sử)](reports/week-6.md)
- [Demo terminal](docs/terminal-demo.md)
- [Bằng chứng kiểm thử hiện tại](evidence/week-6/pre-release-verification-2026-08-20.log)

Dashboard công khai:
<https://honeybrew25.github.io/2026-08-10_NguyenTrongKhanh_Week4-5-6/>.
