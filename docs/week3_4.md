## Đọc nhanh

| Tuần | Câu hỏi chính | Đầu vào | Đầu ra | Tài liệu |
|---|---|---|---|---|
| Week 3 | Agent giải thích finding mà không bịa dữ kiện như thế nào? | 27 normalized findings + 17 knowledge records | 9 grounded JSONL records | [Security Analysis Agent](security-analysis-agent.md) |
| Week 4 | Agent kiểm tra API mà không sở hữu URL, payload hoặc credential như thế nào? | Grounded finding + capability policy + safe test catalog | Bounded request + sanitized receipt | [Safe API Testing Tool](safe-api-testing-tool.md) |

## Luồng nối tiếp Week 3 → Week 4

```text
Bandit/ZAP
  -> normalized-findings.json
  -> Security Analysis Agent
  -> security-analysis.jsonl
  -> deterministic safe-request planner
  -> RequestProposal chỉ chứa bounded ID, provenance và metadata
  -> policy + Envoy/ext_authz
  -> stateless test API
  -> sanitized JSONL receipt
```

Ranh giới sở hữu dữ liệu được giữ xuyên suốt:

- Scanner và code sở hữu finding, severity, location, evidence và provenance.
- Narrative provider chỉ viết giải thích, bước xác minh và bước khắc phục.
- Planner chỉ chọn bounded identifier cùng rationale/provenance/header đã
  allowlist; proposal không có URL, raw body hoặc credential. Code sở hữu
  origin, method, path, payload và credential.
- Gateway kiểm tra lại identity, exact route, canonical path, body cap và rate
  limit trước khi request tới ứng dụng.

## Tái hiện Week 3

Chạy ở repository root, không cần API key:

```powershell
python -m security_pipeline search "SQL Injection" --limit 1

python -m security_pipeline analyze `
  security-results/normalized-findings.json `
  --knowledge-base data/vulnerabilities.json `
  --provider deterministic `
  --output "$env:TEMP\week3-analysis-check.jsonl"

python -m pytest -q tests/test_security_pipeline.py `
  tests/test_security_analysis_agent.py
```

Kết quả mong đợi: 27 finding được phủ đúng một lần trong 9 record; output hợp
schema, có provenance và không cần gọi model bên ngoài.

## Tái hiện Week 4

Dry-run mặc định không cần secret hoặc network:

```powershell
python -m safe_api_tool demo
```

Kiểm chứng full stack bằng Keycloak, Envoy, authz-service và FastAPI:

```powershell
python scripts/run_all_tests.py
```

Runner sinh credential kiểm thử tạm trong process, thực thi GET/POST qua
Gateway, kiểm tra negative control, ghi receipt CI đã sanitize và luôn dọn
Docker stack khi kết thúc.

## Bản đồ bằng chứng

| Lớp | Week 3 | Week 4 |
|---|---|---|
| Input được curate | `security-results/normalized-findings.json`, `data/vulnerabilities.json` | `security-results/security-analysis.jsonl`, `data/safe-api-test-cases.json` |
| Policy/contract | `schemas/security-analysis-finding.schema.json`, System Prompt | `config/safe-api-tool/policy.json`, `schemas/safe-api-*.schema.json` |
| Machine-readable output | `security-results/security-analysis.jsonl` | `security-results/runs/week-4/safe-api-demo.jsonl` |
| Verification | Unit/grounding/coverage tests | Unit + Docker integration + secret sentinel |
| Human snapshot | [`reports/week-3.md`](../reports/week-3.md) | [`reports/week-4.md`](../reports/week-4.md) |

## Kịch bản demo 7 phút

1. Mở 27 normalized findings và 9 grounded records để giải thích việc giảm
   nhiễu nhưng vẫn giữ provenance.
2. Chạy một deterministic analysis, chỉ ra field do code sở hữu và phần
   narrative do provider sở hữu.
3. Chạy `python -m safe_api_tool demo` để cho thấy proposal không có URL, raw
   body hoặc API key.
4. Trình bày policy exact-route và ba receipt mẫu: GET thành công, POST thành
   công, capability `admin` bị chặn trước transport.
5. Kết thúc bằng dashboard `/ui/` hoặc static showcase để nối kiến trúc,
   controls và evidence trên một màn hình.

## Checklist nghiệm thu

- [ ] Week 3 deterministic chạy offline và tạo đúng 9 record từ 27 finding.
- [ ] Mỗi finding nguồn xuất hiện đúng một lần; output qua schema và grounding.
- [ ] Week 4 dry-run không mở network và proposal không chứa URL/credential.
- [ ] Full integration chỉ đi qua Envoy; backend không có host port.
- [ ] Route/method/body vượt policy bị chặn với outcome có kiểu rõ ràng.
- [ ] API key không xuất hiện trong receipt, authz audit hoặc response.
- [ ] Generated artifacts nằm đúng `security-results/` hoặc `evidence/`, không
      được chép vào `docs/` hay `reports/`.

CI, artifact retention và GHCR được mô tả tại [CI/CD](ci-cd.md). Giao diện
trình bày được mô tả tại [Project Sentinel dashboard](ui-dashboard.md).
