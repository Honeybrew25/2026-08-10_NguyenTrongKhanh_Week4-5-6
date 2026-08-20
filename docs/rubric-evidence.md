# Ánh xạ rubric với evidence Week 6

Tài liệu này chỉ liên kết claim với artefact/lệnh tái hiện; không tự chấm điểm.
Base revision và trạng thái working tree phải đọc từ verification log, không
suy ra rằng thay đổi đã commit.

| Rubric | Chức năng | Evidence cùng release review |
|---|---|---|
| Hệ thống hoạt động | Fresh scanner → normalize → Agent → proposal → final report; Docker live controls | `evidence/week-6/pre-release-verification-2026-08-20.log`; `project_sentinel run`; 244 full-stack tests |
| Chất lượng AI Agent | Grounding, source coverage, empty/invalid và hallucination trap | `data/evaluation-cases.json`; `docs/evaluation.md`; 5 Agent + 5 behavioral, 10/10, TP=6/FP=0/FN=0 |
| An toàn hệ thống | Exact allowlist, Reject=0, Approve=1, response quarantine/redaction | Week 6 demo summary trong verification log; Week 5 contract evidence; guardrail/integration tests |
| Chất lượng mã nguồn | Strict schema/state machine, CI same-run artefacts, non-root Compose runner | `schemas/project-sentinel-*.json`; `.github/workflows/security-scan.yml`; 216 non-integration tests |
| Tài liệu/trình bày | README rerun, kiến trúc, evaluation, demo script, report và product brief | `README.md`; `docs/architecture.md`; `docs/evaluation.md`; `docs/demo-script.md`; `reports/week-6.md`; `docs/product-brief.md` |

Machine-readable fallback được curate tại
`security-results/runs/week-6/golden/release-summary.json`; nó không thay fresh
run và ghi rõ working tree chưa phải clean release commit. Các gate cần owner
hoặc peer ký nhận nằm trong `docs/release-acceptance.md`.
