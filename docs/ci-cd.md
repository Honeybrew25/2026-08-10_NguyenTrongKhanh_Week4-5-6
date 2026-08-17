# CI/CD với GitHub Actions

Workflow `.github/workflows/security-scan.yml` thực hiện:

1. Chạy unit test, Bandit full-severity/Low làm dữ liệu và Bandit High làm
   release gate trên pull request và nhánh `main`.
2. Khởi động Keycloak, Envoy, authz-service và FastAPI bằng Docker Compose để
   chạy integration test thật cho JWT IAM và Safe API Tool.
3. Chạy OWASP ZAP passive baseline qua Envoy, seed từ public `/health`, rồi
   upload JSON/HTML report. Job không dùng Agent token và không phải
   authenticated DAST cho protected API. Quyết định từng alert nằm tại
   [fresh ZAP baseline triage](security-baseline-triage.md).
4. Job `fresh-analysis` tải chính Bandit/ZAP artifact của cùng workflow run,
   normalize chung rồi chạy Security Analysis Agent deterministic. Kết quả
   normalized, JSONL và SHA-256 manifest được upload trong artifact
   `fresh-security-analysis` với retention 14 ngày.
5. Chạy demo Week 5 qua Envoy bằng API key tạm, cấp hai quyết định HITL kiểm
   soát (`Reject`, rồi `Approve`), kiểm tra negative control và upload bốn JSONL
   đã sanitize dưới artifact `week5-safe-api-guardrail-artifacts`.
6. Job `week6-e2e` tải lại chính Bandit/ZAP của workflow, chạy
   `project_sentinel` deterministic dry-run và evaluation 10 case. Script gate
   kiểm final/event schema, manifest hash, run ID, network count, release
   threshold và secret/PII sentinel; artifact `week6-release-artifacts` giữ
   final report, evaluation summary và verification log trong 14 ngày.
7. Khi push hoặc merge thành công vào `main`, build và publish ba image lên
   GitHub Container Registry (GHCR), nhưng chỉ sau khi Week 6 E2E Pass:
   - `ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-staging-api`
   - `ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-authz-service`
   - `ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-sentinel-runner`

Workflow không cần secret do người dùng cung cấp: Keycloak secret và
`SAFE_API_TOOL_API_KEY` đều được sinh ngẫu nhiên và chỉ tồn tại trong job.
DAST đăng ký các giá trị với GitHub masking; integration runner giữ key trong
environment của subprocess và không in ra log. Workflow không gọi model bên
ngoài. Artefact CI nằm trên runner/GitHub artifact, không được dùng để ghi đè
baseline lịch sử đã commit.

Đây là continuous delivery: workflow tạo image có thể triển khai nhưng không
tự ý kết nối hoặc deploy lên máy chủ chưa được chỉ định.

## Dashboard Pages chạy thủ công

Workflow `.github/workflows/deploy-ui-pages.yml` publish đúng bốn static asset
trong `src/app/static/` lên GitHub Pages. Nó chỉ có trigger
`workflow_dispatch`, chỉ nhận revision `main` và không tự deploy khi push.

Trước khi đóng gói, job kiểm tra JSON, từ chối symlink/file ngoài allowlist và
quét các chuỗi giống credential. Dashboard chỉ chứa dữ liệu curate cùng dry-run
simulator; API key và protected API không thuộc static artifact.

Sau khi chủ repository đồng ý rõ ràng, có thể chạy từ giao diện Actions hoặc:

```powershell
gh workflow run deploy-ui-pages.yml --ref main
gh run list --workflow deploy-ui-pages.yml --limit 1
```

URL hiện tại:
`https://honeybrew25.github.io/2026-08-10_NguyenTrongKhanh_Week4-5-6/`.
Đẩy commit mới lên `main` không làm site đổi ngay; phải chạy lại workflow thủ
công để phát hành revision đã review.

## Thiết lập GitHub

Trong repository GitHub, mở **Settings → Actions → General → Workflow
permissions** và bảo đảm workflow được phép ghi package. Workflow chỉ dùng
`GITHUB_TOKEN` tạm do GitHub cấp; không cần đưa `.env` hoặc client secret lên
GitHub.

Nếu repository hoặc tổ chức giới hạn package, quản trị viên cần cho phép
`packages: write`.

## Đưa thay đổi lên GitHub bằng PowerShell

Nên tạo nhánh và pull request:

```powershell
Set-Location "D:\AI Vinsoc\2026-08-10_NguyenTrongKhanh_Week4-5-6"

git switch -c add-ci-cd
git status
git diff --check
git add .github/workflows/security-scan.yml docs/ci-cd.md README.md
git commit -m "Add CI and container delivery workflow"
git push --set-upstream origin add-ci-cd
```

Mở repository GitHub, tạo pull request từ `add-ci-cd` vào `main`, chờ unit/SAST,
Docker integration và ZAP DAST đều màu xanh rồi merge. Lần chạy trên `main` sẽ
publish image.

Không dùng pull request từ fork để publish image; job publish chỉ chạy cho sự
kiện `push` vào `main`.

## Theo dõi và tải kết quả

- Mở tab **Actions** để theo dõi từng job.
- Trong run summary, tải artifact `bandit-json` để xem bản full-severity, bản
  High gate và hash của hai JSON SAST.
- Tải artifact `zap-baseline-report` để xem JSON/HTML DAST.
- Tải artifact `fresh-security-analysis` để xem normalized JSON, báo cáo JSONL
  đã nhóm/giải thích từ chính scanner output của run đó và SHA-256 manifest.
- Tải artifact `week5-safe-api-guardrail-artifacts` để xem receipt v1,
  approval decision, guarded response và run event của demo Gateway. Không có
  raw HTTP response, credential hoặc PII trong artifact này.
- Tải `week6-release-artifacts` để xem final report/manifest/event, evaluation
  summary/manifest và verification log của cùng workflow run.
- Mở trang repository **Packages** để xem ba image và các tag.
- Tag `sha-<commit>` cố định theo commit; `latest` trỏ tới lần publish mới nhất.

Kéo image về máy:

```powershell
docker pull ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-staging-api:latest
docker pull ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-authz-service:latest
docker pull ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-sentinel-runner:latest
```

Nếu package đang để private, đăng nhập GHCR bằng personal access token có quyền
`read:packages`; không ghi token vào file hoặc câu lệnh được commit:

```powershell
$env:GHCR_TOKEN | docker login ghcr.io `
    --username Honeybrew25 `
    --password-stdin
```

Sau đó xóa token khỏi session:

```powershell
Remove-Item Env:GHCR_TOKEN
```

## Kiểm tra workflow trước khi push

```powershell
python -m pip install --requirement requirements-dev.txt
python -m pip install --requirement security/requirements.txt
python -m pytest -q -m "not integration"
python scripts/run_security_scan.py `
    --output "$env:TEMP\bandit-full.json" `
    --severity-level low
# Exit 1 ở lệnh trên là bình thường khi JSON có finding.
python scripts/run_security_scan.py `
    --output "$env:TEMP\bandit-high.json" `
    --severity-level high
python -m security_pipeline normalize `
    "$env:TEMP\bandit-full.json" `
    security-results/zap-baseline-local.json `
    --output "$env:TEMP\normalized-ci-check.json"
python -m security_pipeline analyze `
    "$env:TEMP\normalized-ci-check.json" `
    --knowledge-base data/vulnerabilities.json `
    --provider deterministic `
    --output "$env:TEMP\security-analysis-ci-check.jsonl"
python -m project_sentinel run `
    "$env:TEMP\bandit-full.json" `
    security-results/zap-baseline-local.json `
    --provider deterministic
python -m project_sentinel evaluate --provider deterministic
docker compose config --quiet
python scripts/run_all_tests.py
```

Lệnh cuối tự tạo secret kiểm thử tạm trong bộ nhớ, khởi động stack, lấy token
thật từ Keycloak, chạy toàn bộ test, thực thi demo Safe API Tool, ghi receipt,
approval, guarded response và event
đã sanitize và dọn container khi kết thúc.
