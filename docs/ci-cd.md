# CI/CD với GitHub Actions

Workflow `.github/workflows/security-scan.yml` thực hiện:

1. Chạy unit test và Bandit trên pull request và nhánh `main`.
2. Khởi động Keycloak, Envoy, authz-service và FastAPI bằng Docker Compose để
   chạy integration test thật cho JWT IAM và Safe API Tool.
3. Chạy OWASP ZAP Baseline qua Envoy và upload JSON/HTML report.
4. Chạy Security Analysis Agent deterministic từ normalized findings và kho
   tri thức, rồi upload artifact `week3-security-analysis-jsonl` trong 14 ngày.
5. Chạy demo Week 4 qua Envoy bằng API key tạm, kiểm tra negative control và
   upload receipt đã sanitize dưới artifact `week4-safe-api-demo-receipts`.
6. Khi push hoặc merge thành công vào `main`, build và publish hai image lên
   GitHub Container Registry (GHCR):
   - `ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-staging-api`
   - `ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-authz-service`

Workflow không cần secret do người dùng cung cấp: Keycloak secret và
`SAFE_API_TOOL_API_KEY` đều được sinh ngẫu nhiên và chỉ tồn tại trong job.
DAST đăng ký các giá trị với GitHub masking; integration runner giữ key trong
environment của subprocess và không in ra log. Workflow không gọi model bên
ngoài. File sinh tạm
`security-results/security-analysis-ci.jsonl` được `.gitignore` loại khỏi
source control.

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
- Trong run summary, tải artifact `bandit-json` để xem JSON SAST.
- Tải artifact `zap-baseline-report` để xem JSON/HTML DAST.
- Tải artifact `week3-security-analysis-jsonl` để xem báo cáo đã nhóm và giải
  thích tự động của Security Analysis Agent.
- Tải artifact `week4-safe-api-demo-receipts` để xem proposal, policy hash,
  request ID, status, latency và bounded response excerpt của demo Gateway.
- Mở trang repository **Packages** để xem hai image và các tag.
- Tag `sha-<commit>` cố định theo commit; `latest` trỏ tới lần publish mới nhất.

Kéo image về máy:

```powershell
docker pull ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-staging-api:latest
docker pull ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-authz-service:latest
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
    --output security-results/bandit-local.json `
    --severity-level high
python -m security_pipeline analyze `
    security-results/normalized-findings.json `
    --knowledge-base data/vulnerabilities.json `
    --provider deterministic `
    --output security-results/security-analysis-ci.jsonl
python scripts/run_all_tests.py
```

Lệnh cuối tự tạo secret kiểm thử tạm trong bộ nhớ, khởi động stack, lấy token
thật từ Keycloak, chạy toàn bộ test, thực thi demo Safe API Tool, ghi receipt
đã sanitize và dọn container khi kết thúc.
