# Product brief — Project Sentinel

## Vấn đề

Các công cụ SAST/DAST tạo báo cáo khó đọc, khác schema và dễ bị hiểu quá mức.
Khi thêm AI vào chuỗi bảo mật, hai rủi ro mới xuất hiện: model có thể bịa dữ
kiện hoặc bị HTTP response điều khiển; một đề xuất kiểm thử cũng có thể biến
thành request vượt phạm vi. Nhóm kỹ thuật cần một lab nhỏ để tổng hợp evidence,
giải thích finding và minh họa kiểm thử an toàn mà không thực hiện khai thác.

## Người dùng

- Sinh viên/nhóm AppSec cần demo chuỗi scan → phân tích → kiểm tra có kiểm soát.
- Developer cần báo cáo dễ hiểu nhưng vẫn truy ngược được scanner evidence.
- Reviewer/giảng viên cần expected/actual, audit trail và lệnh tái hiện thay vì
  chỉ xem ảnh chụp hoặc tuyên bố của model.

## Giá trị

Project Sentinel biến Bandit/ZAP JSON thành một final report có provenance và
đưa mọi hành động qua bốn ranh giới độc lập: exact policy, human approval,
Gateway authorization và response guard. Sản phẩm cho thấy AI có thể hỗ trợ
diễn giải mà không sở hữu quyền thực thi. Người review có thể kiểm hash input,
source finding IDs, human decision, request receipt, redaction/injection flags
và metrics trong cùng run ID.

## Phạm vi sản phẩm

Sản phẩm gồm:

- Bandit SAST và ZAP passive DAST artefact trong CI;
- schema chung và keyword knowledge base 17 tài liệu;
- Security Analysis Agent deterministic/Gemini tùy chọn, grounding và JSONL;
- deterministic bounded request planner, exact allowlist và bốn payload curate;
- Envoy, ext_authz, Keycloak lab IAM và API key riêng cho Safe API Tool;
- HITL Approve/Reject có fingerprint, expiry, single-use và policy re-check;
- response cap, prompt-injection quarantine và shared sensitive-data redaction;
- one-proposal-per-run orchestrator, final report, event/metrics và manifest;
- evaluation 10 case, CI release artefact, Compose runner và demo 10–15 phút.

Ngoài phạm vi: khai thác thật, production deployment, GraphRAG, multi-agent
phức tạp, MCP/A2A IAM hoàn chỉnh, self-host GPU/vLLM và LLM-as-a-Judge.

## Trải nghiệm chính

Người dùng chạy dry-run một lệnh để tạo fresh scanner JSON và final report mà
không mở network. Trong interactive mode, CLI hiển thị exact request view; POST
chỉ đi tiếp khi người dùng gõ `Approve`. `Reject`, timeout, EOF hoặc input lạ
đều tạo 0 call. Approval không mở allowlist. HTTP response bị coi là untrusted,
giới hạn byte, quarantine instruction và redact trước khi persist.

Dashboard trình bày kiến trúc, evidence và policy simulator cho audience không
kỹ thuật. Nó không nhận credential và không thay execution CLI.

## Tiêu chí thành công

- Fresh scanner artefact được normalize/analyze trong cùng run, có hash.
- Empty/invalid input và provider/Gateway lỗi fail closed.
- Reject = 0 request; Approve = đúng một bounded request qua Envoy.
- Endpoint ngoài allowlist = 0 request; redirect không theo.
- Raw HTTP instruction và fixture sensitive data không xuất hiện trong final
  artefact.
- Evaluation đạt schema/source coverage 100%, hallucination/leak/bypass 0 và
  báo TP/FP/FN theo truth unit công bố.
- Một người khác có thể chạy lại bằng README, xem evidence và cleanup sạch.

## Hạn chế và hướng phát triển

Phiên bản này là educational lab: Keycloak `start-dev`, HTTP loopback,
process-local rate limit, passive unauthenticated ZAP và regex guard. Dataset
evaluation nhỏ nên không đại diện toàn bộ security domain. Gemini phụ thuộc
dịch vụ ngoài và không nằm trên release path.

Hướng tiếp theo sau P0 là authenticated DAST an toàn, dependency/container
scanning, shared/distributed rate limiting, centralized telemetry, secret
manager, digest/SHA pinning và mở rộng dataset theo failure thực tế. Chỉ cân
nhắc semantic retrieval hoặc multi-agent khi các ranh giới policy, evaluation
và observability hiện tại vẫn được giữ nguyên.
