# Báo cáo tuần 6 - Tích hợp và đánh giá Project Sentinel

## Mục tiêu

Trong tuần 6, em nối scanner, normalizer, Security Analysis Agent, approval,
Gateway và response guard thành một sản phẩm đầu-cuối có final report, metrics,
evaluation và lệnh demo tái hiện được.

## Quá trình

- Tạo `project_sentinel` runner theo state machine, một proposal/run, workspace
  immutable, scanner provenance/hash, event log, metrics, final report và
  manifest.
- Thêm dry-run, interactive demo và deterministic CI; đóng gói one-shot runner
  non-root trong Compose với trusted origin nội bộ và mount read-only.
- Tạo bộ evaluation 10 case có expected/actual, truth unit TP/FP/FN, các trap
  empty/invalid/hallucination/injection/redaction/approval và release threshold.
- Thêm CI Week 6 dùng Bandit/ZAP artefact cùng workflow, schema/hash/sentinel
  gate, product brief, kiến trúc, README và kịch bản demo 10–15 phút.

## Kết quả

- Fresh Bandit Low: **41 findings → 6 grounded groups**; Bandit High: **0**.
- Evaluation: **10/10 Pass**, **TP=5, FP=0, FN=0**, source coverage/schema-valid
  100%, hallucination/leak/policy bypass đều 0 trên dataset curate.
- Non-integration: **200 passed, 28 deselected**; full Docker: **228 passed**.
- Live controls: Reject gửi 0 request; Approve gửi đúng 1 bounded POST; prompt
  injection bị quarantine; admin bị deny trước transport; Compose cleanup sạch.
- Final report phân biệt scanner fact, AI narrative, human decision và request
  result; status 200 chỉ là verification signal, không phải exploit proof.

Chi tiết command, hash và giới hạn nằm trong
[`evidence/week-6/verification.log`](../evidence/week-6/verification.log), kiến
trúc tại [`docs/project-sentinel-architecture.md`](../docs/project-sentinel-architecture.md)
và evaluation tại [`docs/evaluation.md`](../docs/evaluation.md). Ánh xạ từng
nhóm rubric sang evidence/lệnh cùng release review nằm tại
[`docs/rubric-evidence.md`](../docs/rubric-evidence.md); tài liệu này không tự
chấm điểm.

## Kết luận

Các P0 chức năng Week 6 đã có code và evidence thực thi. Sản phẩm vẫn là lab:
ZAP passive `/health`, Keycloak dev/HTTP local, rate limiter process-local và
regex guard có phạm vi hữu hạn. Bước quản trị còn lại là owner review/stage/
commit toàn bộ file bàn giao rồi ghi lại clean release revision; báo cáo này
không giả rằng working tree hiện tại đã được version-control. Biểu mẫu peer
rerun, rehearsal và owner release nằm tại
[`docs/release-acceptance.md`](../docs/release-acceptance.md).
