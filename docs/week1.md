# Tuần 1 — Chạy ứng dụng và quét bảo mật

## Mục tiêu

Tuần 1 chạy ứng dụng bằng Docker Compose với hai công cụ:

- Bandit `1.9.4` kiểm tra mã Python.
- OWASP ZAP `2.17.0` kiểm tra phản hồi web qua Envoy.

Kết quả gốc:
[`bandit-baseline.json`](../security-results/bandit-baseline.json) và
[`zap-baseline-local.json`](../security-results/zap-baseline-local.json).

## Cách ứng dụng hoạt động

```text
Agent/client --> Envoy :8080 --> FastAPI :8000
                    |
                    +--> authz-service --> Keycloak :8081
```

Envoy là cổng vào duy nhất. FastAPI và dịch vụ kiểm tra quyền ở trong mạng
Docker; Keycloak cấp token. Bandit đọc mã, còn ZAP kiểm tra ứng dụng đang chạy.

| Đường dẫn | Mục đích | Quyền truy cập |
|---|---|---|
| `GET /health` | Kiểm tra API | Công khai |
| `GET /.well-known/oauth-protected-resource` | Thông tin OAuth | Công khai |
| `GET /api/users` | Dữ liệu user mẫu | Token có quyền `users:read` |
| `GET /api/admin` | Dữ liệu admin mẫu | Token có quyền `admin:read` |
| Đường dẫn khác | Ngoài danh sách cho phép | Bị chặn |

Token phải hợp lệ, còn hạn, thuộc Agent được phép và có đúng quyền.

## Kết quả quét

### Bandit

| Mức độ | Số lượng |
|---|---:|
| High | 0 |
| Medium | 2 |
| Low | 19 |

21 cảnh báo đều nằm trong script kiểm tra, không nằm trong `src/app/` hoặc
`src/authz_service/`:

| Mã | Số lượng | Nhận xét ngắn |
|---|---:|---|
| B310 | 2 | `urlopen` cần giới hạn loại URL; hiện chỉ dùng HTTP localhost |
| B101 | 14 | `assert` chỉ nằm trong script xác minh |
| B105 | 1 | Nhận nhầm URL cấp token là mật khẩu |
| B404/B603 | 4 | Lệnh dùng tham số cố định và `shell=False` |

### OWASP ZAP

ZAP quét thụ động từ `/health`, không thấy cảnh báo High hoặc Medium. Hai
header nên bổ sung ở mức Low là
`Cross-Origin-Resource-Policy: same-origin` và
`X-Content-Type-Options: nosniff`. Phần còn lại liên quan đến bộ nhớ đệm và
phản hồi `403` của `/`, `/robots.txt`, `/sitemap.xml`.

ZAP không dùng token, không tấn công chủ động và chưa quét đủ hai API bảo vệ.

## Kết quả tuần 1

Ứng dụng chạy được bằng Docker và tạo JSON thật. GitHub Actions đã cấu hình,
nhưng cần một lần chạy thành công để làm bằng chứng CI.

Lần xác minh local ngày 29/07/2026 đạt `29 passed`; xem
[`evidence/integration-tests.log`](../evidence/integration-tests.log).

Không có cảnh báo nghiêm trọng chưa có nghĩa là hệ thống hoàn toàn an toàn.
Bandit không kiểm tra thư viện, image hoặc quyền khi chạy; ZAP không thay thế
quét chủ động và kiểm thử thủ công.

## Chạy lại trên PowerShell

Bandit:

```powershell
python -m pip install --requirement security/requirements.txt

python scripts/run_security_scan.py `
    --output security-results/bandit-local.json `
    --severity-level low

Get-Content security-results/bandit-local.json -Raw |
    ConvertFrom-Json |
    Select-Object -ExpandProperty results
```

Ở mức `low`, mã trả về `1` nghĩa là có cảnh báo; file JSON vẫn được tạo.

ZAP:

```powershell
docker compose up --build --detach --wait

$envoyId = docker compose ps --quiet envoy
$network = docker inspect `
    --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}' `
    $envoyId
$resultPath = (Resolve-Path security-results).Path

docker run --rm `
    --network $network `
    --volume "${resultPath}:/zap/wrk:rw" `
    zaproxy/zap-stable:2.17.0 `
    zap-baseline.py `
    -t "http://envoy:8080/health" `
    -J "zap-baseline-local.json" `
    -r "zap-baseline-local.html" `
    -m 1 `
    -I

Get-Content security-results/zap-baseline-local.json -Raw |
    ConvertFrom-Json |
    Out-Null

docker compose down --remove-orphans
```
