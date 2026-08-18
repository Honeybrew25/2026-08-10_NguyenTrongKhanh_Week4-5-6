# Tuần 5 — Bản tóm tắt

## Tuần này làm gì?

Tuần 5 tập trung làm cho việc kiểm thử API an toàn hơn. 

- Tạo sanitizer dùng chung cho Agent, planner, CLI, approval, response và log;
  hỗ trợ email, số điện thoại lab, token, API key, password và PII có khóa/mẫu
  đã định nghĩa.
- Tạo state machine cùng contract riêng cho risk, approval, guarded response
  và run event, đồng thời giữ nguyên receipt schema v1 của Week 4.
- Đặt cổng approval ngay trong `SafeApiClient`. Approval được gắn với run,
  proposal, policy, trusted origin, request fingerprint, thời hạn và chỉ dùng
  một lần.
- Thêm exact GET fixture mô phỏng prompt injection, detector/quarantine và
  benign control. Response không thể sinh proposal, tự approve hoặc gọi thêm
  endpoint/tool.
- Đổi demo thật thành hai run tách biệt: Reject để chứng minh không gọi mạng,
  sau đó Approve để gửi đúng một bounded POST qua Envoy.

## Kết quả

- Non-integration suite đạt **183 passed, 28 deselected**, không warning.
- Full-stack suite với Keycloak, Envoy, authz-service và API đạt
  **211 passed**, không warning; bốn curated POST profile không đổi state.
- Live demo cho kết quả GET 200, Reject POST với 0 response/network fact,
  Approve POST 200 và admin bị policy chặn.
- Bốn JSONL artifact qua schema; secret/PII sentinel không tìm thấy giá trị raw.
- Bandit High release gate đạt 0 finding.

Chi tiết lệnh, hash và tiêu chí Pass/Fail nằm trong
[`evidence/week-5/verification.log`](../evidence/week-5/verification.log). Thiết
kế và cách chạy nằm trong
[`docs/week5-guardrails.md`](../docs/week5-guardrails.md).

## Ý nghĩa

Week 5 hoàn thành lớp guardrails, redaction và HITL có thể kiểm chứng bằng hành
vi. Phần còn lại của Week 6 là nối các contract này thành orchestrator đầu-cuối,
evaluation và báo cáo cuối.

[bằng chứng kiểm thử](../evidence/week-5/verification.log).
