# Week 1 — Docker application và security scanning

## Phạm vi

Week 1 chứng minh staging application chạy bằng Docker Compose, xác định các
endpoint chính và tích hợp hai công cụ mã nguồn mở:

- Bandit `1.9.4` để SAST source Python.
- OWASP ZAP `2.17.0` Baseline để DAST thụ động qua Envoy.

Kết quả gốc được lưu tại
[`bandit-baseline.json`](../security-results/bandit-baseline.json) và
[`zap-baseline-local.json`](../security-results/zap-baseline-local.json).

## 1. Kiến trúc ứng dụng

```text
Agent/client ---- HTTP :8080 ----> Envoy API Gateway ---- allow ----> FastAPI :8000
                                      |
                                      | ext_authz check
                                      v
                                authz-service ---- JWKS ----> Keycloak :8081
```

Envoy là cổng duy nhất cho application traffic. FastAPI và `authz-service` chỉ
nằm trong Docker network; Keycloak publish cổng riêng để cấp OAuth token.
`authz-service` chỉ trả quyết định allow/deny cho Envoy, không chuyển tiếp
request đến FastAPI. Khi request được allow, chính Envoy forward request đến
FastAPI.
Bandit đọc source trước khi chạy ứng dụng, còn ZAP gửi request tới Envoy khi
stack đang chạy.

## 2. Các endpoint chính

| Endpoint | Mục đích | Quyền |
|---|---|---|
| `GET /health` | Kiểm tra staging API | Public |
| `GET /.well-known/oauth-protected-resource` | MCP/OAuth protected-resource metadata | Public |
| `GET /api/users` | Dữ liệu user minh họa | Bearer token hợp lệ của Agent được phép, có `users:read` |
| `GET /api/admin` | Dữ liệu admin minh họa | Bearer token hợp lệ của Agent được phép, có `admin:read` |
| Route khác | Không thuộc allowlist | Deny mặc định |

Token hợp lệ phải có chữ ký RS256 xác minh được qua JWKS, đúng `issuer`,
`audience`, còn hạn, thuộc một Agent client được phép và chứa scope tương ứng.

## 3. Lỗ hổng và cảnh báo phát hiện

### Bandit SAST

| Severity | Số lượng |
|---|---:|
| High | 0 |
| Medium | 2 |
| Low | 19 |

| Rule | Số lượng | Kết quả review |
|---|---:|---|
| B310 | 2 | `urlopen` cần giới hạn scheme; URL hiện là hằng số HTTP localhost |
| B101 | 14 | `assert` nằm trong verification script, không thuộc production request path |
| B105 | 1 | False positive: chuỗi bị báo là password thực tế là token endpoint URL |
| B404/B603 | 4 | Runner dùng argv cố định và `shell=False`; vẫn cần giữ input không tin cậy khỏi command |

Không có finding trong `app/` hoặc `authz_service/`; toàn bộ 21 cảnh báo thuộc
script chạy scan/test. Đây là cảnh báo cần review, không đồng nghĩa có 21 lỗ
hổng khai thác được.

### ZAP Baseline DAST

ZAP quét public endpoint `/health` qua Envoy và ghi nhận:

| Risk | Alert | Nhận định |
|---|---|---|
| Low | Cross-Origin-Resource-Policy header missing/invalid | Nên cân nhắc `Cross-Origin-Resource-Policy: same-origin` |
| Low | `X-Content-Type-Options` header missing | Nên thêm `X-Content-Type-Options: nosniff` tại gateway |
| Informational | Storable and cacheable content | Cần quyết định chính sách cache cho `/health` |
| Informational | Non-storable content | Xuất hiện trên `/`, `/robots.txt` và `/sitemap.xml`; cả ba không thuộc allowlist và bị deny `403` |

Không có cảnh báo High hoặc Medium. ZAP Baseline bắt đầu từ public endpoint
`/health`, spider và passive-scan các response thu được. Scan không dùng Agent
token, không thực hiện active attack và không bao phủ đầy đủ hai API được bảo
vệ.

## Kết luận

Week 1 đã có application chạy bằng Docker, danh sách endpoint, SAST và DAST
tạo JSON thật ở local. GitHub Actions đã được cấu hình để chạy lại các kiểm tra
và upload Bandit/ZAP artifact trong CI; cần dẫn link tới một workflow run thành
công nếu muốn dùng nó làm bằng chứng CI. Hai header hardening mức Low là hạng
mục nên xử lý tiếp; các cảnh báo Bandit còn lại có ngữ cảnh chủ yếu ở test
runner.

Lần xác minh local ngày 29/07/2026 bằng `python scripts/run_all_tests.py` đạt
`29 passed`; bản ghi kết quả nằm tại
[`evidence/integration-tests.log`](../evidence/integration-tests.log).

Không có finding không phải bằng chứng hệ thống an toàn. Bandit không kiểm tra
dependency/image/runtime authorization; ZAP Baseline không thay thế active API
scan hoặc kiểm thử thủ công.

## Lệnh tái lập trên PowerShell

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

Ở ngưỡng `low`, Bandit dự kiến trả exit code `1` khi có finding dù file JSON
vẫn được tạo thành công. Đây là trạng thái có finding cần review, không phải lỗi
khởi chạy scanner.

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
