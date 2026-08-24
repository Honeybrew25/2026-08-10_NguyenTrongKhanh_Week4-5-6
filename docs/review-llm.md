# Báo cáo ngắn: LLM, deterministic và mức độ bám đề bài

## Tại sao sử dụng Deterministic?

`DeterministicNarrativeProvider` là bộ tạo nội dung bằng quy tắc cố định trong
`providers.py`. Nó **không gọi mô hình AI**.

Project sử dụng deterministic cho demo mặc định, test và CI vì:

- kết quả lặp lại được;
- không phụ thuộc Internet, quota hoặc API key;
- test có thể so sánh chính xác;
- demo không thất bại vì dịch vụ LLM bên ngoài;
- dễ kiểm tra guardrails, policy và Gateway độc lập với chất lượng LLM.

> Pipeline đang chạy bằng provider cố định để chứng minh luồng và kiểm soát an
> toàn. Project có provider Gemini riêng để chứng minh phần LLM.

## Nhận xét

Thiết kế này phù hợp mục tiêu an toàn của đề bài: AI đề xuất hướng kiểm tra,
nhưng code giới hạn capability.

Ứng dụng staging hiện thiên về kiểm chứng control an toàn; ZAP chưa quét sâu protected API và không thực hiện khai thác. Điều này vẫn nằm trong phạm vi vì đề bài không yêu cầu khai thác thật, nhưng phần minh họa lỗ hổng web chưa mạnh.

## Đề xuất sửa

1. Giữ deterministic cho CI, evaluation và demo dự phòng.
2. Trong demo chạy thêm một lượt Gemini riêng:

   ```powershell
   python -m security_pipeline analyze `
     security-results/normalized-findings.json `
     --knowledge-base data/vulnerabilities.json `
     --provider gemini `
     --output "$env:TEMP\security-analysis-gemini.jsonl"
   ```
Bản tóm tắt lần chạy : 
security-results\runs\week-6\golden\gemini-mentor-demo-2026-08-24