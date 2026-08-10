# Agent IAM Security Lab

Repository chung cho các tuần, gồm một staging API, Agent IAM qua
Envoy/Keycloak, pipeline chuẩn hóa kết quả Bandit/ZAP và Security Analysis
Agent tạo báo cáo JSONL có grounding. Week 4 bổ sung Safe API Testing Tool để
Agent đề xuất và gửi request GET/POST bị giới hạn qua Gateway.

## Bắt đầu nhanh

Yêu cầu: Python 3.11+, Docker Desktop với Compose v2 và Git.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --requirement requirements-dev.txt
Copy-Item .env.example .env
```

Thay các placeholder Keycloak/Agent IAM và `SAFE_API_TOOL_API_KEY` trong
`.env`, sau đó chạy stack. Các
biến Gemini là tùy chọn và không cần thiết cho chế độ deterministic:

```powershell
docker compose up --build --detach --wait
docker compose ps
Invoke-RestMethod "http://localhost:8080/health"
python scripts/verify_gateway.py
```

Mở dashboard tại `http://localhost:8080/ui/`. `/` tự chuyển hướng sang trang
này; UI public chỉ cho phép GET/HEAD và không nhận API key từ trình duyệt.

Dừng stack bằng `docker compose down --remove-orphans`.

## Safe API Testing Tool — Week 4

Dry-run là mặc định, không dùng credential và không mở network:

```powershell
python -m safe_api_tool demo
python -m safe_api_tool propose `
    --output "$env:TEMP\safe-api-proposal.json"
python -m safe_api_tool run "$env:TEMP\safe-api-proposal.json"
```

Sau khi stack đã chạy, thực thi demo có kiểm soát bằng:

```powershell
python -m safe_api_tool demo --execute `
    --audit "$env:TEMP\safe-api-demo.jsonl"
```

Tool không nhận URL hay raw payload từ Agent. Code chọn exact route từ
`config/safe-api-tool/policy.json`, dựng một trong bốn test case an toàn rồi
ghi receipt JSONL đã khử secret. Chi tiết tại
[thiết kế Safe API Testing Tool](docs/safe-api-testing-tool.md).

## Dashboard trực quan

Dashboard dùng HTML/CSS/JavaScript thuần, không CDN và hoạt động theo hai chế
độ từ cùng bộ asset trong `src/app/static/`:

- `docker compose`: FastAPI phục vụ `/ui/` qua Envoy; nút health chỉ gọi public
  `/health` cùng origin.
- static showcase: architecture, evidence và dry-run simulator vẫn hoạt động,
  nhưng không gọi protected API hoặc cần credential.

Preview riêng phần static mà không chạy Docker:

```powershell
python -m http.server 4173 --bind 127.0.0.1 --directory src/app/static
```

Sau đó mở `http://127.0.0.1:4173/`. Thiết kế và deployment guardrails nằm tại
[tài liệu UI](docs/ui-dashboard.md) và

## Test, security scan và Agent

```powershell
python -m pytest -q -m "not integration"
python scripts/run_all_tests.py

python -m pip install --requirement security/requirements.txt
python scripts/run_security_scan.py `
    --output security-results/bandit-local.json `
    --severity-level low
```

Chuẩn hóa hai baseline Week 1 và tìm kiếm dataset:

```powershell
python -m security_pipeline normalize `
    security-results/bandit-baseline.json `
    security-results/zap-baseline-local.json `
    --output security-results/normalized-findings.json

python -m security_pipeline search "SQL Injection"
python -m security_pipeline search "XSS"
```

Tạo lại báo cáo mẫu Week 3 không cần API key:

```powershell
python -m security_pipeline analyze `
    security-results/normalized-findings.json `
    --knowledge-base data/vulnerabilities.json `
    --provider deterministic `
    --output security-results/security-analysis.jsonl
```

Provider Gemini là tùy chọn. Điền `GEMINI_API_KEY` và các cấu hình `GEMINI_*`
trong file `.env` đã được ignore, sau đó ghi kết quả thử nghiệm ngoài
repository để không ghi đè baseline deterministic:

```powershell
python -m pip install --editable ".[agent]"
python -m security_pipeline analyze `
    security-results/normalized-findings.json `
    --knowledge-base data/vulnerabilities.json `
    --provider gemini `
    --output "$env:TEMP\security-analysis-gemini.jsonl"
```

Mặc định, Agent dùng `gemini-3.5-flash-lite` với thinking `minimal` để giảm
chi phí. Nếu output trống, sai schema hoặc không vượt qua kiểm tra grounding,
Agent thử lại đúng một lần bằng `gemini-3.6-flash` với thinking `low`. Lỗi xác
thực, quota hoặc mạng không kích hoạt fallback. Provider deterministic vẫn là
mặc định và là provider duy nhất được gọi trong CI.

## Báo cáo và tài liệu

- [Báo cáo Week 1](reports/week-1.md)
- [Báo cáo Week 2](reports/week-2.md)
- [Báo cáo Week 3](reports/week-3.md)
- [Báo cáo Week 4](reports/week-4.md)
- [Báo cáo chạy thật Gemini — Week 3](reports/week-3/gemini-live-run-2026-08-03.md)
- [Runbook Week 1](docs/week1.md)
- [Thiết kế pipeline Week 2](docs/week2.md)
- [Thiết kế Security Analysis Agent](docs/security-analysis-agent.md)
- [Thiết kế Safe API Testing Tool](docs/safe-api-testing-tool.md)
- [Dashboard UI](docs/ui-dashboard.md)
- [Project handoff và workflow tiếp tục](docs/project-handoff.md)
- [System Prompt của Agent](src/security_pipeline/analysis/prompts/security_analysis_system.md)
- [JSON Schema của một finding](schemas/security-analysis-finding.schema.json)
- [Báo cáo JSONL mẫu](security-results/security-analysis.jsonl)
- [Receipt demo Week 4](security-results/runs/week-4/safe-api-demo.jsonl)
- [CI/CD](docs/ci-cd.md)
