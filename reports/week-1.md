# Báo cáo Week 1 — Nguyễn Trọng Khánh

## 1. Mục tiêu và kết quả

Project đã thực hiện cả hai hình thức kiểm tra:

- **SAST:** Bandit `1.9.4` quét mã nguồn Python.
- **DAST:** OWASP ZAP `2.17.0` Baseline quét ứng dụng qua API gateway.

| Yêu cầu | Cách thực hiện | Bằng chứng |
|---|---|---|
| Ứng dụng chạy bằng Docker | Docker Compose chạy FastAPI, Envoy, `authz-service` và Keycloak | [`docker-compose.yml`](../docker-compose.yml), [`29 passed`](../evidence/integration-tests.log) |
| Có quy trình CI | GitHub Actions chạy unit test, Bandit, Docker integration và ZAP khi push/PR | [`security-scan.yml`](../.github/workflows/security-scan.yml) |
| Công cụ quét tự động | Bandit chạy bằng một lệnh; Bandit và ZAP được chạy trong CI | [`run_security_scan.py`](../scripts/run_security_scan.py) |
| Lưu kết quả JSON | Lưu baseline của Bandit và ZAP trong repository | [`bandit-baseline.json`](../security-results/bandit-baseline.json), [`zap-baseline-local.json`](../security-results/zap-baseline-local.json) |
| Có hướng dẫn tái lập | README hướng dẫn cài dependency, chạy ứng dụng, test và scan | [`README.md`](../README.md) |

## 2. Kiến trúc

```text
Client/Agent ---> Envoy :8080 --------------------> FastAPI :8000
                     |
                     +--- ext_authz ---> authz-service
                                             |
                                             +--- JWKS ---> Keycloak :8081

Bandit ---> app/ + authz_service/ + scripts/
ZAP    ---> Envoy :8080
```

Envoy là cổng vào của application. Mỗi request được Envoy gửi sang
`authz-service` để quyết định allow/deny; nếu được phép, Envoy mới chuyển
request đến FastAPI. Keycloak cấp OAuth token và JWKS để xác minh chữ ký.

## 3. Endpoint chính

| Endpoint | Mục đích | Truy cập |
|---|---|---|
| `GET /health` | Health check | Public |
| `GET /.well-known/oauth-protected-resource` | OAuth protected-resource metadata | Public |
| `GET /api/users` | Dữ liệu user minh họa | Token hợp lệ có `users:read` |
| `GET /api/admin` | Dữ liệu admin minh họa | Token hợp lệ có `admin:read` |
| Route khác | Không thuộc allowlist | Deny mặc định |

## 4. Kết quả quét

### Bandit SAST

| Severity | Số lượng |
|---|---:|
| High | 0 |
| Medium | 2 |
| Low | 19 |

Hai cảnh báo Medium là B310 liên quan đến `urlopen`. Toàn bộ 21 finding nằm
trong các script chạy test/scan; không có finding trong `app/` hoặc
`authz_service/`. Các finding vẫn cần được review, nhưng không đồng nghĩa có 21
lỗ hổng khai thác được.

### OWASP ZAP Baseline

- Không có cảnh báo High hoặc Medium.
- Hai cảnh báo Low: thiếu `Cross-Origin-Resource-Policy` và
  `X-Content-Type-Options`.
- Có cảnh báo Informational về cache/non-storable response.

ZAP bắt đầu từ `/health`, spider và passive-scan các response qua Envoy. Scan
chưa dùng Agent token và chưa bao phủ đầy đủ các API được bảo vệ.

## 5. Cách tái lập

Từ thư mục project trong PowerShell:

```powershell
python -m pip install --requirement requirements-dev.txt
python -m pip install --requirement security/requirements.txt

python scripts/run_all_tests.py
python scripts/run_security_scan.py `
    --output security-results/bandit-local.json `
    --severity-level low
```

Lần xác minh local ngày 29/07/2026 đạt **29 test passed**. Lệnh Bandit ở ngưỡng
`low` trả exit code `1` khi có finding nhưng vẫn tạo JSON thành công. Hướng dẫn
chạy ZAP và cách đọc kết quả nằm trong [`docs/week1.md`](../docs/week1.md).

## 6. Kết luận

Ứng dụng Docker chạy được, có CI
quét tự động, có kết quả JSON, có danh sách endpoint và có tài liệu để thành
viên khác tái lập. Bandit và ZAP Baseline chỉ cung cấp kiểm tra bảo mật cơ bản;
kết quả không có High finding không có nghĩa hệ thống đã an toàn hoàn toàn.
