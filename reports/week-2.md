# Báo cáo Week 2 — Chuẩn hóa kết quả quét và xây dựng kho tri thức

**Project:** `2026-07-30_NguyenTrongKhanh_Week2`

## Mục tiêu

Trong tuần 2, em tiếp tục sử dụng kết quả quét bảo mật của Week 1. Mục tiêu là chuyển dữ liệu từ Bandit và OWASP ZAP về cùng một cấu trúc để chương trình hoặc AI Agent có thể đọc dễ dàng. Bên cạnh đó, em xây dựng một kho kiến thức nhỏ về các lỗ hổng web và chức năng tìm kiếm theo từ khóa.

## Công việc đã thực hiện

Đầu tiên, em viết chương trình Python để đọc hai định dạng JSON khác nhau.
Bandit trả kết quả theo file và dòng code, còn ZAP trả cảnh báo theo URL. Em
chuẩn hóa cả hai về các trường chung như:

```json
{
  "tool": "bandit",
  "severity": "medium",
  "file_or_url": "scripts/run_all_tests.py",
  "title": "B310: Audit url open for permitted schemes",
  "rule_id": "B310"
}
```

Chương trình tự nhận diện loại báo cáo, chuyển đổi dữ liệu, loại bỏ bản ghi
trùng và tạo ID ổn định cho từng cảnh báo. Kết quả tổng hợp được lưu tại
[`normalized-findings.json`](../security-results/normalized-findings.json).

Tiếp theo, em xây dựng kho tri thức gồm 17 nội dung bảo mật dựa trên OWASP Top
10:2025 và tài liệu của Bandit/ZAP.

Cuối cùng, em bổ sung chức năng tìm kiếm theo tên lỗ hổng hoặc từ khóa. Hệ
thống ưu tiên kết quả dựa trên tên, tên viết tắt, nhóm OWASP, tag và nội dung
tài liệu. Kết quả cũng có thể xuất dưới dạng JSON để AI Agent sử dụng.

## Kết quả

- Chuẩn hóa thành công **27 cảnh báo** từ dữ liệu Week 1:
  - 21 cảnh báo từ Bandit.
  - 6 cảnh báo theo URL từ ZAP.
- Xây dựng kho tri thức gồm **17 chủ đề bảo mật web**.
- Tìm kiếm `"SQL Injection"` trả đúng tài liệu SQL Injection.
- Tìm kiếm `"XSS"` trả đúng tài liệu Cross-Site Scripting.

Các lệnh chính:

```powershell
python -m security_pipeline normalize `
    security-results/bandit-baseline.json `
    security-results/zap-baseline-local.json

python -m security_pipeline search "SQL Injection"
python -m security_pipeline search "XSS"
python -m security_pipeline search "security headers"

```

## Điều em học được

Qua công việc tuần này, em hiểu rằng mỗi công cụ bảo mật có định dạng kết quả
khác nhau nên cần một lớp chuẩn hóa trước khi đưa dữ liệu cho AI Agent. Em cũng
hiểu rõ hơn sự khác nhau giữa cảnh báo của công cụ và lỗ hổng thực tế: kết quả
quét cần được kết hợp với kiến thức bảo mật và ngữ cảnh của source code trước
khi đưa ra kết luận.

Em thiết kế chương trình theo từng adapter riêng cho Bandit và ZAP. Nhờ đó, khi
cần hỗ trợ thêm công cụ như Semgrep, phần tổng hợp và tìm kiếm hiện tại có thể
được giữ nguyên, chỉ cần bổ sung adapter mới.
