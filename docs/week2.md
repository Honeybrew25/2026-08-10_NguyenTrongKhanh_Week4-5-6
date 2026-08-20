# Tuần 2 — Gộp kết quả quét và tạo kho tra cứu

## Mục tiêu

Tuần 2 đưa JSON của Bandit và ZAP về cùng một mẫu để chương trình hoặc AI đọc
thống nhất. Dự án cũng có kho tra cứu lỗi.

```text
Bandit JSON --\
               +--> bộ chuyển đổi --> một mẫu chung --> normalized-findings.json
ZAP JSON ------/

Từ khóa --> tìm kiếm --> data/vulnerabilities.json
```

Mỗi công cụ có bộ chuyển đổi riêng, nên có thể thêm nguồn mới mà không đổi đầu
ra.

## Mẫu dữ liệu chung

Mỗi cảnh báo có ID, công cụ, mức độ, vị trí, mô tả, cách sửa, nguồn và bằng
chứng. Mức độ gồm `informational`, `low`, `medium`, `high`, `critical` và
`unknown`. ID giữ ổn định giữa các lần chạy. Mẫu đầy đủ nằm tại
[`normalized-findings.schema.json`](../schemas/normalized-findings.schema.json).

## Chuyển dữ liệu tuần 1

```powershell
python -m security_pipeline normalize `
    security-results/bandit-baseline.json `
    security-results/zap-baseline-local.json `
    --output security-results/normalized-findings.json
```

| Kết quả | Số lượng |
|---|---:|
| Tổng | 27 |
| Bandit | 21 |
| ZAP | 6 |
| Medium | 2 |
| Low | 21 |
| Informational | 4 |

File đầu ra:
[`security-results/normalized-findings.json`](../security-results/normalized-findings.json).

## Kho tra cứu

[`data/vulnerabilities.json`](../data/vulnerabilities.json) có 17 mục từ OWASP,
Bandit và ZAP, gồm dấu hiệu, ví dụ, cách xử lý và nguồn.

```powershell
python -m security_pipeline search "SQL Injection"
python -m security_pipeline search "XSS"
python -m security_pipeline search "SQL Injection" --json
```

Tìm kiếm không phân biệt hoa/thường hoặc dấu tiếng Việt. Hai truy vấn đầu phải
trả `SQL Injection` và `Cross-Site Scripting (XSS)` ở vị trí đầu.

## Thêm công cụ quét

1. Tạo bộ chuyển đổi trong `src/security_pipeline/normalizers/`.
2. Thêm cách nhận diện file và chuyển cảnh báo sang mẫu chung.
3. Đăng ký vào `DEFAULT_NORMALIZERS`.
4. Thêm dữ liệu mẫu và bài kiểm thử.

## Kiểm tra

```powershell
python -m pytest -q -m "not integration"
python -m security_pipeline search "SQL Injection" --limit 1
python -m security_pipeline search "XSS" --limit 1
```

Nguồn chính: [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/),
[OWASP Web Security Community](https://owasp.org/www-community/attacks/),
[Bandit 1.9.4](https://bandit.readthedocs.io/en/1.9.4/) và
[ZAP](https://www.zaproxy.org/docs/alerts/).
