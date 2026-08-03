# Báo cáo Week 3 — Security Analysis Agent

## Mục tiêu

Xây dựng Agent đọc kết quả Bandit/ZAP của Week 1 đã được chuẩn hóa ở Week 2,
kết hợp kho tri thức để tạo báo cáo JSONL dễ hiểu, có bằng chứng và không tự
thêm endpoint hoặc lỗ hổng.

## Quá trình

Luồng xử lý được đặt trong
[`security_pipeline.analysis`](../src/security_pipeline/analysis/):

```text
normalized findings + knowledge base
        -> validate -> group -> retrieve -> explain -> ground -> JSONL
```

Agent kiểm tra schema đầu vào rồi nhóm các finding cùng công cụ và scanner
rule. Mỗi nhóm giữ toàn bộ finding ID, vị trí và bằng chứng gốc; severity lấy
mức cao nhất và confidence lấy mức thấp nhất trong nhóm. Kho tri thức được
ghép bằng đúng cặp `(tool, rule_id)`. Nếu không có tài liệu phù hợp, Agent giữ
ngữ cảnh scanner thay vì suy đoán một loại lỗ hổng.

[`System Prompt`](../src/security_pipeline/analysis/prompts/security_analysis_system.md)
coi scanner evidence và kho tri thức là dữ liệu không tin cậy. Các trường tên,
severity, vị trí, bằng chứng và provenance do code tạo; provider chỉ viết giải
thích, cách kiểm tra và cách khắc phục. Output tiếp tục được kiểm tra grounding
và model dữ liệu theo hợp đồng
[`JSON Schema`](../schemas/security-analysis-finding.schema.json) trước khi ghi
nguyên tử.

Project có provider deterministic để demo/CI không cần API key và provider
OpenAI tùy chọn dùng Structured Output. Dữ liệu rỗng hợp lệ tạo báo cáo 0 dòng;
input sai trả lỗi rõ ràng và không thay thế output tốt trước đó.

## Kết quả

- 27 finding chuẩn hóa được tổng hợp thành **9 nhóm cảnh báo**, không mất hoặc
  lặp finding nguồn.
- Mỗi dòng trong
  [`security-analysis.jsonl`](../security-results/security-analysis.jsonl) là
  một finding độc lập gồm tên, severity, vị trí, bằng chứng, giải thích, đề
  xuất kiểm tra/khắc phục, confidence và provenance.
- ID, thứ tự và định dạng ổn định khi chạy lại bằng provider deterministic.
- **15 test case** bao phủ dữ liệu Week 1/2, nhóm trùng, mapping tri thức,
  JSONL, dữ liệu rỗng/lỗi, prompt injection, secret redaction và provider bịa
  endpoint hoặc loại lỗ hổng không có căn cứ.
- Toàn bộ **53 test** của project pass trên stack Docker thật gồm Keycloak,
  Envoy và hai service; Bandit không có finding mức High.

Lệnh tái lập không cần khóa API:

```powershell
python -m security_pipeline analyze `
    security-results/normalized-findings.json `
    --knowledge-base data/vulnerabilities.json `
    --provider deterministic `
    --output security-results/security-analysis.jsonl

python -m pytest -q tests/test_security_analysis_agent.py
```

## Kết luận

Phần quan trọng không chỉ là gọi model mà là giữ ranh giới giữa dữ kiện và
diễn giải. Grouping, exact-rule retrieval, provenance, schema validation và
grounding giúp báo cáo ngắn hơn nhưng vẫn truy ngược được scanner. Kết quả hỗ
trợ triage, không thay thế xác minh thủ công hoặc bằng chứng khai thác.
