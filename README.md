# Agent IAM Security Lab

Project Sentinel là repository xuyên suốt nhiều tuần: chuẩn hóa kết quả
Bandit/ZAP, phân tích finding có grounding và thực thi request kiểm thử hữu hạn
qua API Gateway.

## Luồng dự án

```text
Bandit/ZAP
  -> normalized findings + knowledge base
  -> Security Analysis Agent
  -> grounded JSONL
  -> Safe API Testing Tool
  -> Envoy / ext_authz
  -> stateless FastAPI test surface
  -> sanitized receipt
```

Code giữ quyền sở hữu dữ kiện scanner, URL, payload và credential. Model chỉ
diễn giải finding hoặc chọn capability đã được giới hạn.

## Bắt đầu nhanh

Yêu cầu: Python 3.11+, Docker Desktop với Compose v2 và Git.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --requirement requirements-dev.txt
Copy-Item .env.example .env
```

Thay các placeholder Keycloak/Agent IAM và `SAFE_API_TOOL_API_KEY` trong
`.env`. Cấu hình Gemini là tùy chọn và không cần cho chế độ deterministic.

```powershell
docker compose up --build --detach --wait
Invoke-RestMethod "http://localhost:8080/health"
Start-Process "http://localhost:8080/ui/"
```

Kết thúc bằng `docker compose down --remove-orphans`.

## Demo và kiểm thử

Tạo lại báo cáo deterministic của Week 3:

```powershell
python -m security_pipeline analyze `
    security-results/normalized-findings.json `
    --knowledge-base data/vulnerabilities.json `
    --provider deterministic `
    --output "$env:TEMP\security-analysis-check.jsonl"
```

Chạy demo policy của Week 4; mặc định là dry-run, không mở network:

```powershell
python -m safe_api_tool demo
```

Chạy toàn bộ unit và Docker integration tests:

```powershell
python scripts/run_all_tests.py
```

Các lệnh scan, Gemini, proposal/execute và cách đọc evidence được trình bày
trong tài liệu chuyên đề bên dưới.

## Dashboard

- Local qua Gateway: `http://localhost:8080/ui/`
- GitHub Pages: <https://honeybrew25.github.io/2026-08-10_NguyenTrongKhanh_Week4-5-6/>
- Preview static: `python -m http.server 4173 --bind 127.0.0.1 --directory src/app/static`

Dashboard public chỉ trình bày kiến trúc, evidence và dry-run simulator; API
key không được đưa vào trình duyệt.

## Tài liệu

- [Security Analysis Agent — Week 3](docs/security-analysis-agent.md)
- [Safe API Testing Tool — Week 4](docs/safe-api-testing-tool.md)
- [Dashboard UI](docs/ui-dashboard.md)
- [CI/CD](docs/ci-cd.md)