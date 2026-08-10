# Báo cáo Week 3 — Security Analysis Agent

## Mục tiêu

Xây dựng Agent đọc kết quả Bandit/ZAP của Week 1 đã được chuẩn hóa ở Week 2,
kết hợp kho tri thức để tạo báo cáo JSONL, có bằng chứng.

## Quá trình

Luồng xử lý :

```text
normalized findings + knowledge base
        -> validate -> group -> retrieve -> explain -> ground -> JSONL
```

Agent kiểm tra schema đầu vào rồi nhóm các finding cùng công cụ và scanner
rule. Mỗi nhóm giữ toàn bộ finding ID, vị trí và bằng chứng gốc; severity lấy
mức cao nhất và confidence lấy mức thấp nhất trong nhóm. Kho tri thức được
ghép bằng đúng cặp `(tool, rule_id)`. Nếu không có tài liệu phù hợp, Agent giữ
ngữ cảnh scanner thay vì suy đoán một loại lỗ hổng.

System Prompt coi scanner evidence và kho tri thức là dữ liệu không tin cậy. Các trường tên,
severity, vị trí, bằng chứng và provenance do code tạo; provider chỉ viết giải
thích, cách kiểm tra và cách khắc phục. Output tiếp tục được kiểm tra grounding
và model dữ liệu theo hợp đồng trước khi ghi.

## Kết quả

- 27 finding chuẩn hóa được tổng hợp thành **9 nhóm cảnh báo**, không mất hoặc
  lặp finding nguồn.

## Kết luận

Điểm quan trọng của hệ thống không nằm ở việc sử dụng AI, mà ở việc kiểm soát AI sử dụng dữ liệu như thế nào. Hệ thống cần phân biệt rõ thông tin scanner thực sự phát hiện với phần AI suy luận. Các kết quả giống nhau được gom nhóm, mỗi nhận định phải dựa trên đúng dữ liệu và có thể truy ngược về nguồn ban đầu, đồng thời dữ liệu phải được kiểm tra cấu trúc trước khi sử dụng. Kết quả hỗ trợ triage, không thay thế xác minh thủ công hoặc bằng chứng khai thác.
