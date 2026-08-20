# Tuần 3–4 — Giải thích cảnh báo và kiểm thử API an toàn

## Đọc nhanh

| Tuần | Việc chính | Kết quả | Chi tiết |
|---|---|---|---|
| 3 | Giải thích 27 cảnh báo bằng 17 mục tra cứu | 9 bản ghi có nguồn | [Security Analysis Agent](security-analysis-agent.md) |
| 4 | Kiểm tra API trong phạm vi cho phép | Yêu cầu giới hạn, kết quả đã làm sạch | [Safe API Testing Tool](safe-api-testing-tool.md) |

## Luồng xử lý

```text
Bandit/ZAP
  -> 27 cảnh báo đã chuẩn hóa
  -> Agent giải thích thành 9 bản ghi
  -> chọn ca kiểm thử có sẵn
  -> kiểm tra quyền tại Envoy
  -> gọi API thử nghiệm
  -> lưu kết quả đã làm sạch
```

AI chỉ giải thích và đề xuất cách sửa. Mã nguồn giữ dữ liệu gốc, chỉ cho chọn
ca kiểm thử có sẵn; AI không tự tạo URL, nội dung gửi hoặc thông tin đăng nhập.
Envoy kiểm tra quyền, đường dẫn, phương thức, kích thước và số lần gọi.

## Chạy lại tuần 3

Không cần API key:

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

Kết quả: 27 cảnh báo xuất hiện đúng một lần trong 9 bản ghi, có nguồn và không
gọi dịch vụ AI bên ngoài.

## Chạy lại tuần 4

Chạy thử không gửi yêu cầu ra mạng:

```powershell
python -m safe_api_tool demo
```

Kiểm tra đầy đủ bằng Docker, Keycloak, Envoy và FastAPI:

```powershell
python scripts/run_all_tests.py
```

Script tạo đăng nhập tạm, gọi GET/POST qua Envoy, lưu kết quả sạch và dọn
Docker.

## Bằng chứng chính

| Tuần | Dữ liệu vào | Kết quả | Báo cáo |
|---|---|---|---|
| 3 | `normalized-findings.json`, `vulnerabilities.json` | `security-analysis.jsonl` | [`week-3.md`](../reports/week-3.md) |
| 4 | `security-analysis.jsonl`, `safe-api-test-cases.json` | `safe-api-demo.jsonl` | [`week-4.md`](../reports/week-4.md) |

## Demo ngắn

1. Mở 27 cảnh báo và 9 bản ghi để cho thấy vẫn giữ nguồn.
2. Chạy tuần 3, phân biệt dữ liệu gốc với phần AI viết.
3. Chạy `python -m safe_api_tool demo`; xác nhận không lộ URL, nội dung gửi
   đi hoặc API key.
4. Cho xem GET, POST và trường hợp `admin` bị chặn; kết thúc tại `/ui/`.

## Kết quả nghiệm thu

- Tuần 3 chạy offline: 27 cảnh báo thành 9 bản ghi có nguồn.
- Tuần 4 chạy thử không mở mạng; bản chạy thật chỉ đi qua Envoy.
- Đường dẫn hoặc dữ liệu sai bị chặn; kết quả không có API key.
- File sinh ra chỉ nằm trong `security-results/` hoặc `evidence/`.

Kết quả được kiểm tra lại ở tuần 5–6. Xem bằng chứng mới trong
[README](../README.md), [CI/CD](ci-cd.md) và [giao diện demo](ui-dashboard.md).
