# Project Sentinel — Week 6

Hệ thống có thể:

- nhận kết quả từ Bandit và ZAP;
- gộp các cảnh báo giống nhau;
- dùng AI để giải thích và đề xuất cách kiểm tra;
- hỏi người dùng trước khi gửi yêu cầu có rủi ro;
- chặn đường dẫn ngoài phạm vi và che thông tin nhạy cảm;
- lưu báo cáo để kiểm tra lại sau này.

Giao diện web hiện phát lại tám tình huống đã chạy trong demo E2E: bốn tình
huống Week 6 ban đầu và bốn kiểm soát mở rộng. Bốn nhánh hợp lệ đi qua Gateway;
bốn nhánh còn lại dừng an toàn trước khi gửi request. Việc phê duyệt vẫn được
thực hiện bằng dòng lệnh; giao diện chỉ hiển thị kết quả đã làm sạch.

## Kết quả hiện tại

- 41 cảnh báo được gộp thành 6 nhóm.
- Bộ đánh giá đạt 10/10 trường hợp, gồm 5 case Agent và 5 case hành vi.
- 235 bài kiểm thử thông thường đạt sau lần mở rộng dashboard; lượt demo thật
  đủ tám tình huống cũng đạt kỳ vọng.

Mốc kiểm tra đầy đủ trước thay đổi này nằm tại
[`evidence/week-6/pre-release-verification-2026-08-20.log`](evidence/week-6/pre-release-verification-2026-08-20.log).
Phiếu nghiệm thu cuối vẫn cần chạy lại Docker/CI trên commit mới và một người
khác làm lại theo README.
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

Lệnh trên dùng bộ mặc định gồm bốn tình huống: Reject, Approve, phản hồi đáng
ngờ và đường dẫn quản trị bị chặn.

### Chạy lại đủ tám tình huống kiểm soát

Bộ mở rộng chạy cả tám tình huống. Bốn tình huống mới kiểm tra endpoint trạng
thái, dữ liệu sai kiểu có chủ đích, test case sai phạm vi và header không được
phép:

```bash
python -m project_sentinel demo --provider deterministic --execute --scenario-set extended --format human
```

Khi được hỏi, lần lượt nhập:

1. `Reject` cho POST thông thường.
2. `Approve` cho POST thông thường.
3. `Approve` cho POST dùng test case `wrong-type`; HTTP 422 là kết quả mong
   đợi của tình huống này.

Sau khi terminal in đường dẫn file tổng kết, thay `<demo-summary>` bằng đường
dẫn đó để đưa kết quả đã làm sạch lên dashboard:

```bash
python scripts/build_dashboard_replay.py "<demo-summary>"
```

Lệnh tạo dashboard chỉ nhận bản tổng kết `extended` đủ tám tình huống, nên
một lượt chạy thiếu không thể làm giao diện quay lại bốn tab.

Nếu đang chạy Docker, build lại rồi tải lại trang bằng `Ctrl+F5`:

```bash
docker compose up --build --detach --wait --wait-timeout 180
```

Trang GitHub Pages chỉ đổi sau khi file dashboard đã được commit, đưa vào
`main` và workflow deploy hoàn tất. Chỉ refresh trình duyệt không thể cập nhật
trang công khai từ thay đổi local hoặc từ nhánh `week-6`.

### Chạy bộ đánh giá

```bash
python -m project_sentinel evaluate --provider deterministic
```

Kết quả đúng sẽ có `passed: 10`, `failed: 0` và `thresholds_met: true`.

### Mở giao diện

Khi Docker đang chạy, mở <http://localhost:8080/ui/>. Bốn tab đầu là kiểm soát
Week 6 ban đầu; bốn tab sau là kiểm soát mở rộng. Thẻ **RUN** cho biết kết quả
đang lấy từ lượt demo nào và sẽ đổi sau khi tạo lại dashboard.

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
