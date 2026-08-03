# Báo cáo bổ sung Week 3 — Chạy thật Gemini

## Mục tiêu

Xác minh Security Analysis Agent hoạt động end-to-end với Gemini trên dữ liệu
Bandit/ZAP của Week 1–2, đồng thời giữ nguyên schema, provenance và kiểm tra
chống bịa dữ kiện đã xây dựng ở Week 3.

## Quá trình

| Thành phần | Cấu hình |
|---|---|
| Thời điểm xác minh | 03/08/2026 11:19 (UTC+7) |
| Input | `security-results/normalized-findings.json` |
| Kho tri thức | `data/vulnerabilities.json` |
| Primary | `gemini-3.5-flash-lite`, thinking `minimal` |
| Fallback | `gemini-3.6-flash`, thinking `low`, tối đa một lần |
| Raw output | [`gemini-live-2026-08-03.jsonl`](../../security-results/runs/week-3/gemini-live-2026-08-03.jsonl) |

Lệnh chạy cuối:

```powershell
python -m security_pipeline analyze `
    security-results/normalized-findings.json `
    --knowledge-base data/vulnerabilities.json `
    --provider gemini `
    --output security-results/runs/week-3/gemini-live-2026-08-03.jsonl
```

Lần thử đầu phát hiện `response_schema` của SDK chuyển
`additionalProperties` sang trường OpenAPI mà Gemini Developer API không nhận.
Provider được chuyển sang `response_json_schema`; các ràng buộc chuỗi không
được API hỗ trợ vẫn được Pydantic kiểm tra nghiêm ngặt sau khi nhận output.
Một lần chạy trung gian gặp lỗi server ở fallback và đã dừng mà không ghi file
dở nhờ cơ chế ghi nguyên tử.

## Kết quả

- Lệnh cuối thành công trong **8,01 giây** bằng primary, không dùng fallback.
- **27/27 finding nguồn** được phủ đúng một lần và gom thành **9 nhóm**:
  1 Medium, 6 Low và 2 Informational.
- Cả 9 dòng đều hợp lệ với Pydantic và
  `schemas/security-analysis-finding.schema.json`.
- Kiểm tra grounding đã pass: không thêm endpoint, đường dẫn, CWE/CVE hoặc loại
  lỗ hổng ngoài dữ liệu scanner và kho tri thức được ghép cho nhóm.
- `analysis_method` của mọi record là
  `gemini:gemini-3.5-flash-lite`.
- File raw có 17.466 byte; SHA-256:
  `ad027dda8264eb39c2f2ad034b13cda5fd4bcc72b7ff9332aa755abf19822e2b`.
- SDK hiện chưa lưu usage metadata, vì vậy báo cáo không ước lượng token hoặc
  chi phí. API key không được ghi vào output, log hay báo cáo.

## Kết luận

Gemini provider đã hoạt động thật với dữ liệu Week 1–2 và tạo báo cáo JSONL ổn
định, có thể truy ngược toàn bộ bằng chứng. Kết quả phù hợp để hỗ trợ triage;
vẫn cần người phụ trách xác minh thủ công trước khi kết luận khả năng khai thác
hoặc triển khai bản vá.
