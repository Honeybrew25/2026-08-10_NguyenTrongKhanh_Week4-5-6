# Agent IAM Security Lab

Repository chung cho các tuần, gồm một staging API, Agent IAM qua
Envoy/Keycloak, pipeline chuẩn hóa kết quả Bandit/ZAP và Security Analysis
Agent tạo báo cáo JSONL có grounding.

## Bắt đầu nhanh

Yêu cầu: Python 3.11+, Docker Desktop với Compose v2 và Git.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --requirement requirements-dev.txt
Copy-Item .env.example .env
```

Thay các placeholder Keycloak/Agent IAM trong `.env`, sau đó chạy stack. Hai
biến OpenAI là tùy chọn và không cần thiết cho chế độ deterministic:

```powershell
docker compose up --build --detach --wait
docker compose ps
Invoke-RestMethod "http://localhost:8080/health"
python scripts/verify_gateway.py
```

Dừng stack bằng `docker compose down --remove-orphans`.

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

Provider OpenAI là tùy chọn. Điền `OPENAI_API_KEY` và `OPENAI_MODEL` trong
file `.env` đã được ignore, sau đó ghi kết quả thử nghiệm ngoài repository để
không ghi đè baseline deterministic:

```powershell
python -m pip install --editable ".[agent]"
python -m security_pipeline analyze `
    security-results/normalized-findings.json `
    --knowledge-base data/vulnerabilities.json `
    --provider openai `
    --output "$env:TEMP\security-analysis-openai.jsonl"
```

## Báo cáo và tài liệu

- [Báo cáo Week 1](reports/week-1.md)
- [Báo cáo Week 2](reports/week-2.md)
- [Báo cáo Week 3](reports/week-3.md)
- [Runbook Week 1](docs/week1.md)
- [Thiết kế pipeline Week 2](docs/week2.md)
- [Thiết kế Security Analysis Agent](docs/security-analysis-agent.md)
- [System Prompt của Agent](src/security_pipeline/analysis/prompts/security_analysis_system.md)
- [JSON Schema của một finding](schemas/security-analysis-finding.schema.json)
- [Báo cáo JSONL mẫu](security-results/security-analysis.jsonl)
- [CI/CD](docs/ci-cd.md)
