# Tự động kiểm tra và đóng gói

File `.github/workflows/security-scan.yml` chạy khi có yêu cầu gộp mã
(pull request) hoặc thay đổi trên `main`:

1. Chạy kiểm thử code và Bandit. Cảnh báo High chặn phát hành; bản Low trở lên được
   giữ làm dữ liệu.
2. Dùng Docker Compose chạy Keycloak, Envoy, authz-service và FastAPI rồi kiểm
   tra JWT và Safe API Tool.
3. Dùng ZAP quét thụ động từ `/health` công khai. ZAP không có token của bộ phân tích nên
   không kiểm tra API cần đăng nhập. Xem [quyết định cho từng cảnh
   báo](security-baseline-triage.md).
4. `fresh-analysis` phân tích không gọi mạng, dùng chính kết quả Bandit/ZAP của lần chạy đó.
   `fresh-security-analysis` giữ JSON chuẩn hóa, JSONL và SHA-256 trong 14 ngày.
5. Demo Week 5 qua Envoy bằng API key tạm: `Reject`, `Approve` và một trường hợp
   phải bị chặn. Bốn JSONL đã che dữ liệu được lưu trong
   `week5-safe-api-guardrail-artifacts`.
6. `week6-e2e` chạy `project_sentinel` không gửi yêu cầu và đánh giá 10 trường hợp.
   Nó kiểm tra định dạng, mã SHA-256, mã lần chạy, số yêu cầu, điều kiện phát
   hành và dữ liệu nhạy cảm. `week6-release-artifacts` giữ kết quả và nhật ký
   trong 14 ngày.
7. Chỉ sau khi Week 6 đạt, mã được đẩy hoặc gộp vào `main` mới đăng ba image Docker lên GHCR:
   - `ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-staging-api`
   - `ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-authz-service`
   - `ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-sentinel-runner`

Quy trình tự tạo thông tin bí mật của Keycloak và `SAFE_API_TOOL_API_KEY`, che
chúng trong nhật ký rồi xóa khi hoàn tất. Nó không cần `.env`, không gọi AI bên
ngoài và không ghi đè dữ liệu mẫu trong kho mã. Quy trình chỉ tạo image Docker,
không tự triển khai lên máy chủ.

## Đăng giao diện lên GitHub Pages

`.github/workflows/deploy-ui-pages.yml` chỉ đăng bốn file trong
`src/app/static/`. Nó phải được chạy thủ công, chỉ nhận phiên bản từ `main` và
không tự chạy khi đẩy code. Trước khi đăng, quy trình kiểm tra JSON, từ chối
liên kết đến file khác hoặc file ngoài danh sách, rồi tìm chuỗi giống thông tin
đăng nhập. Trang chỉ có dữ liệu mẫu và mô phỏng không gửi yêu cầu; không chứa
API key hay API cần quyền.

Sau khi chủ repository đồng ý, chạy trên tab Actions hoặc:

```powershell
gh workflow run deploy-ui-pages.yml --ref main
gh run list --workflow deploy-ui-pages.yml --limit 1
```

Trang hiện tại:
`https://honeybrew25.github.io/2026-08-10_NguyenTrongKhanh_Week4-5-6/`.
Muốn cập nhật trang phải chạy lại quy trình sau khi phiên bản mới được duyệt.

## Thiết lập và đưa code lên GitHub

Trong **Settings → Actions → General → Workflow permissions**, cho quy trình
quyền ghi gói. Quy trình chỉ dùng `GITHUB_TOKEN` tạm. Nếu tổ chức đang chặn
gói, quản trị viên cần cho phép `packages: write`. Không tải `.env` hoặc khóa
bí mật của ứng dụng lên GitHub.

Nên tạo nhánh và yêu cầu gộp mã:

```powershell
Set-Location "D:\AI Vinsoc\2026-08-10_NguyenTrongKhanh_Week4-5-6"

git switch -c add-ci-cd
git status
git diff --check
git add .github/workflows/security-scan.yml docs/ci-cd.md README.md
git commit -m "Add CI and container delivery workflow"
git push --set-upstream origin add-ci-cd
```

Tạo yêu cầu gộp `add-ci-cd` vào `main`, chờ các bước kiểm tra đạt rồi mới gộp.
Image chỉ được đăng khi code vào `main`, không đăng từ bản sao kho mã bên ngoài.

## Xem và tải kết quả

Trong tab **Actions**, tải:

- `bandit-json`: hai kết quả Bandit và mã SHA-256;
- `zap-baseline-report`: JSON/HTML của ZAP;
- `fresh-security-analysis`: JSON chuẩn hóa, JSONL phân tích và SHA-256;
- `week5-safe-api-guardrail-artifacts`: biên nhận v1, quyết định, phản hồi đã lọc
  và sự kiện; không có phản hồi HTTP thô, thông tin đăng nhập hay dữ liệu cá nhân;
- `week6-release-artifacts`: báo cáo, đánh giá, danh sách mã file và nhật ký của
  cùng một lần chạy.

Trang **Packages** chứa ba image Docker. `sha-<commit>` gắn với một commit;
`latest` trỏ tới lần đăng mới nhất. Tải image bằng:

```powershell
docker pull ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-staging-api:latest
docker pull ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-authz-service:latest
docker pull ghcr.io/honeybrew25/2026-08-10_nguyentrongkhanh_week4-5-6-sentinel-runner:latest
```

Với gói riêng tư, dùng token cá nhân có quyền `read:packages`. Không ghi token
vào file hoặc lệnh được commit:

```powershell
$env:GHCR_TOKEN | docker login ghcr.io `
    --username Honeybrew25 `
    --password-stdin
```

Xóa token khỏi phiên làm việc:

```powershell
Remove-Item Env:GHCR_TOKEN
```

## Kiểm tra trước khi push

```powershell
python -m pip install --requirement requirements-dev.txt
python -m pip install --requirement security/requirements.txt
python -m pytest -q -m "not integration"
python scripts/run_security_scan.py `
    --output "$env:TEMP\bandit-full.json" `
    --severity-level low
# Mã trả về 1 ở lệnh trên là bình thường khi JSON có cảnh báo.
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

Lệnh cuối tự tạo thông tin bí mật tạm trong bộ nhớ, chạy Docker, lấy token thật
từ Keycloak, chạy toàn bộ kiểm thử và demo, lưu bốn JSONL đã che dữ liệu rồi
dọn container.
