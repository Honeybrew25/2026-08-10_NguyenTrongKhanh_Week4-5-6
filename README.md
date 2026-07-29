# 2026-07-30_NguyenTrongKhanh_Week2

- Staging API bằng FastAPI.
- Docker Compose cho FastAPI, Envoy, `authz-service` và Keycloak.
- Agent IAM với JWT validation và scope authorization.
- Unit test và integration test.
- Bandit SAST và OWASP ZAP Baseline DAST.
- GitHub Actions cho test, security scan và build container image.
- Báo cáo, runbook và kết quả quét Week 1.
- Chuẩn hóa JSON Bandit/ZAP thành schema chung cho AI Agent.
- Kho tri thức OWASP và tìm kiếm lỗ hổng cho Week 2.

## Cấu trúc

```text
.
├── .github/workflows/      # CI, SAST, DAST và container delivery
├── app/                    # FastAPI staging API
├── authz_service/          # JWT validation và scope authorization
├── docs/                   # Runbook và hướng dẫn Week 1/Week 2
├── envoy/                  # API gateway và ext_authz
├── evidence/               # Bằng chứng integration test
├── keycloak/               # Realm import cho machine clients
├── knowledge-base/         # Kho tri thức lỗ hổng web Week 2
├── reports/                # Báo cáo bàn giao
├── scripts/                # Test, verification và Bandit runner
├── schemas/                # JSON Schema cho dữ liệu chuẩn hóa
├── security/               # Dependency cho security scan
├── security-results/       # Scanner baseline và dữ liệu đã chuẩn hóa
├── security_pipeline/      # Adapter, schema, aggregate và search Week 2
└── tests/                  # Unit và Docker integration tests
```

## Yêu cầu

- Python 3.11 trở lên.
- Docker Desktop và Docker Compose v2.
- Git.

## Bắt đầu nhanh

cp .env.example .env
Thay mọi giá trị `replace-with-...` trong `.env` bằng các secret khác nhau.

Khởi động và kiểm tra staging stack:

```powershell
docker compose up --build --detach --wait
docker compose ps
Invoke-RestMethod "http://localhost:8080/health"
python scripts/verify_gateway.py
```

Dừng stack:

```powershell
docker compose down --remove-orphans
```

## Test và security scan

```powershell
python -m pip install --requirement requirements-dev.txt
python -m pip install --requirement security/requirements.txt
python -m pytest -q -m "not integration"


python scripts/run_all_tests.py
python scripts/run_security_scan.py `
    --output security-results/bandit-local.json `
    --severity-level low
```

Lệnh ZAP Baseline và cách đọc kết quả nằm trong
[`docs/week1.md`](docs/week1.md). CI/CD được mô tả tại
[`docs/ci-cd.md`](docs/ci-cd.md).

## Deliverables Week 1

- [Week 1 runbook](docs/week1.md)
- [Báo cáo kiến trúc, endpoint và security findings](reports/2026-07-28_NguyenTrongKhanh_Week1.md)
- [Bandit baseline JSON](security-results/bandit-baseline.json)
- [ZAP baseline JSON](security-results/zap-baseline-local.json)
- [ZAP baseline HTML](security-results/zap-baseline-local.html)

## Week 2 — Chuẩn hóa và tìm kiếm

Chuẩn hóa hai kết quả Week 1 thành một file JSON chung:

```powershell
python -m security_pipeline normalize `
    security-results/bandit-baseline.json `
    security-results/zap-baseline-local.json `
    --output security-results/normalized-findings.json
```

Tìm kiếm kho tri thức:

```powershell
python -m security_pipeline search "SQL Injection"
python -m security_pipeline search "XSS"
python -m security_pipeline search "security headers"
```

## Deliverables Week 2

- [Báo cáo Week 2](reports/2026-07-30_NguyenTrongKhanh_Week2.md)
- [Thiết kế và hướng dẫn Week 2](docs/week2.md)
- [Chương trình chuẩn hóa và tìm kiếm](security_pipeline/)
- [Dữ liệu cảnh báo đã chuẩn hóa](security-results/normalized-findings.json)
- [Kho tri thức 17 lỗ hổng/rủi ro web](knowledge-base/vulnerabilities.json)
