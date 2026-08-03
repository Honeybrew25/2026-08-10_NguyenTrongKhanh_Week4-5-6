# Week 2 — Chuẩn hóa kết quả quét và kho tri thức

## Mục tiêu

Week 2 chuyển JSON của Bandit và OWASP ZAP từ Week 1 thành một schema chung để
AI Agent hoặc chương trình khác có thể đọc thống nhất. Project đồng thời cung
cấp kho tri thức nhỏ và tìm kiếm theo tên lỗ hổng/từ khóa.

## Kiến trúc

```text
Bandit JSON ---\
                +--> scanner adapter --> common schema --> normalized-findings.json
ZAP JSON ------/

Query --> weighted keyword search --> data/vulnerabilities.json
```

Mỗi scanner có một adapter riêng. Orchestrator tự nhận diện định dạng, gọi
adapter và tổng hợp record. Cách tách này giữ schema/output ổn định khi bổ sung
scanner mới.

## Schema finding chung

Một record có cấu trúc:

```json
{
  "id": "bandit-c38035a2a6e76870",
  "tool": "bandit",
  "tool_version": null,
  "severity": "medium",
  "confidence": "high",
  "file_or_url": "scripts/run_all_tests.py",
  "line": 43,
  "method": null,
  "title": "B310: Audit url open for permitted schemes...",
  "description": "Audit url open for permitted schemes...",
  "rule_id": "B310",
  "cwe": "CWE-22",
  "remediation": "Review the flagged code...",
  "references": ["https://bandit.readthedocs.io/..."],
  "evidence": "with urlopen(...)",
  "source_file": "security-results/bandit-baseline.json",
  "metadata": {}
}
```

Severity chung gồm `informational`, `low`, `medium`, `high`, `critical` và
`unknown`. ID được tạo ổn định từ thuộc tính finding, giúp Agent so sánh giữa
các lần chạy. Với ZAP, mỗi URL instance trở thành một record cụ thể.
Schema đầy đủ nằm tại
[`schemas/normalized-findings.schema.json`](../schemas/normalized-findings.schema.json).

## Chuẩn hóa dữ liệu Week 1

```powershell
python -m security_pipeline normalize `
    security-results/bandit-baseline.json `
    security-results/zap-baseline-local.json `
    --output security-results/normalized-findings.json
```

Kết quả hiện tại:

| Chỉ số | Số lượng |
|---|---:|
| Tổng record | 27 |
| Bandit | 21 |
| ZAP | 6 |
| Medium | 2 |
| Low | 21 |
| Informational | 4 |

File bàn giao:
[`security-results/normalized-findings.json`](../security-results/normalized-findings.json).

## Kho tri thức và tìm kiếm

[`data/vulnerabilities.json`](../data/vulnerabilities.json)
gồm 17 tài liệu ngắn dựa trên OWASP Top 10:2025, OWASP Web Security Community,
Bandit và ZAP. Mỗi tài liệu có tên, alias, nhóm OWASP, mô tả, ví dụ, dấu hiệu,
khuyến nghị, scanner rule liên quan, tag và nguồn tham khảo.

Tìm kiếm dạng đọc nhanh:

```powershell
python -m security_pipeline search "SQL Injection"
python -m security_pipeline search "XSS"
```

Kết quả dành cho chương trình/AI Agent:

```powershell
python -m security_pipeline search "SQL Injection" --json
```

Search chuẩn hóa chữ hoa/thường và dấu tiếng Việt, sau đó xếp hạng có trọng số
cho title, alias, OWASP category, tag và nội dung. Module
`security_pipeline.knowledge` là ranh giới riêng nên có thể thay bộ xếp hạng
bằng embedding/vector database mà không thay normalizer.

## Mở rộng scanner mới

1. Tạo adapter kế thừa `ReportNormalizer` trong
   `src/security_pipeline/normalizers/`.
2. Cài đặt `supports()` để nhận diện JSON và `normalize()` để trả
   `NormalizedFinding`.
3. Đăng ký adapter trong `DEFAULT_NORMALIZERS`.
4. Thêm fixture/test cho scanner mới.

Không đưa logic riêng của scanner vào `pipeline.py`; file này chỉ điều phối,
deduplicate, sort và tổng hợp thống kê.

## Kiểm tra tiêu chí hoàn thành

```powershell
python -m pytest -q -m "not integration"
python -m security_pipeline search "SQL Injection" --limit 1
python -m security_pipeline search "XSS" --limit 1
```

Hai truy vấn bắt buộc trả lần lượt `SQL Injection` và
`Cross-Site Scripting (XSS)` ở vị trí đầu.

## Nguồn chính

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
- [OWASP Web Security Community](https://owasp.org/www-community/attacks/)
- [Bandit 1.9.4 documentation](https://bandit.readthedocs.io/en/1.9.4/)
- [ZAP alert documentation](https://www.zaproxy.org/docs/alerts/)
