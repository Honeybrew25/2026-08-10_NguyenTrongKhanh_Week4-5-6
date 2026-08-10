# Chiến lược deploy miễn phí dài hạn cho dashboard

> Đánh giá tại ngày 10/08/2026. Free tier và giới hạn nhà cung cấp có thể thay
> đổi; phải kiểm tra lại tài liệu chính thức trước mỗi lần tạo tài nguyên.

## Quyết định đề xuất

Chọn **GitHub Pages làm kênh public chính** và chỉ publish thư mục
`src/app/static/`.

Đây là phương án bền nhất cho sản phẩm nộp bài vì dashboard:

- không cần process chạy nền nên không có cold start hoặc sleep;
- không chứa API key, `.env`, token hoặc endpoint quản trị;
- vẫn trình bày được kiến trúc, policy, finding metrics, receipt đã sanitize và
  dry-run simulator;
- dùng ngay public repository hiện có, không cần mở thêm tài khoản cloud;
- có thể deploy bằng workflow **chỉ chạy thủ công**, phù hợp quy tắc phải được
  chủ repository đồng ý trước khi push/deploy.

GitHub Pages hỗ trợ public repository trên GitHub Free. Site có giới hạn 1 GB,
soft bandwidth 100 GB/tháng và deployment timeout 10 phút; dashboard hiện nhỏ
hơn rất nhiều các ngưỡng này. Xem
[GitHub Pages limits](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits)
và
[publishing source](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).

## Kiến trúc deploy

```text
Public, always-on, $0
GitHub Pages
  └── HTML/CSS/JS + dashboard-data.json đã curate
      ├── architecture explorer
      ├── safe proposal dry-run simulator
      ├── sanitized evidence
      └── không có credential/protected request

Local và CI, không public
Docker Compose
  └── Envoy -> ext_authz -> FastAPI + Keycloak
      ├── live GET/POST verification
      ├── API-key/JWT tests
      └── Bandit/ZAP/receipt artifacts
```

Khi chạy local, chính bộ static asset đó được FastAPI phục vụ tại `/ui/` qua
Envoy. Khi deploy Pages, nó chạy ở chế độ showcase tĩnh và không cố gọi các
route cần credential.

## Cơ chế phát hành có phê duyệt

File `.github/workflows/deploy-ui-pages.yml` được chuẩn bị với duy nhất trigger
`workflow_dispatch`; không deploy khi push. Workflow chỉ nhận `main`, validate
bốn static asset, từ chối nội dung giống credential rồi mới upload Pages
artifact.

Lần phát hành đầu chỉ thực hiện sau khi chủ repository đồng ý:

1. Review diff, chạy unit/full Docker tests và secret scan local.
2. Được chủ repository cho phép rõ ràng rồi mới commit/push.
3. Trong **Settings → Pages**, chọn **GitHub Actions** làm source.
4. Trong environment `github-pages`, nên đặt required reviewer là chủ repo.
5. Vào **Actions → Deploy dashboard to GitHub Pages (manual) → Run workflow**.
6. Kiểm tra URL `https://honeybrew25.github.io/2026-08-10_NguyenTrongKhanh_Week4-5-6/`
   trên desktop/mobile rồi mới chia sẻ hoặc tạo QR code.

Workflow dùng luồng artifact/deploy do GitHub khuyến nghị trong
[custom Pages workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

Rollback không sửa lịch sử: tạo một revert commit được review trên `main`, chỉ
push sau khi chủ repository đồng ý, rồi chạy lại workflow thủ công.

## So sánh các kênh miễn phí

| Kênh | Phù hợp | Giới hạn/rủi ro | Kết luận |
|---|---|---|---|
| GitHub Pages | Static showcase | Static only; soft bandwidth 100 GB/tháng | **Chọn làm kênh chính** |
| Cloudflare Pages Free | Static showcase/CDN | 500 build/tháng, 20.000 file, 25 MiB/file; cần thêm account/integration | Fallback tốt |
| OCI Always Free A1 | Full Docker Compose | 2 OCPU/12 GB, có thể hết capacity và reclaim VM idle | Chỉ dùng live backend khi thật sự cần |
| Google Cloud Free `e2-micro` | Service rất nhỏ | 1 VM ở ba US region, 30 GB disk, 1 GB egress; RAM không phù hợp Keycloak stack | Không đề xuất cho stack hiện tại |

Cloudflare cho static asset requests miễn phí/không giới hạn và Free plan có
500 builds mỗi tháng, nhưng Git integration mặc định deploy theo push. Có thể
tắt automatic production/preview deployments, song thêm một control plane là
không cần thiết cho project này. Xem
[Cloudflare Pages limits](https://developers.cloudflare.com/pages/platform/limits/),
[Pages pricing](https://developers.cloudflare.com/pages/functions/pricing/)
và
[Git integration controls](https://developers.cloudflare.com/pages/configuration/git-integration/).

Google Cloud Free Tier hiện chỉ cấp một `e2-micro` theo quota thời gian tại
`us-west1`, `us-central1` hoặc `us-east1`, cùng 30 GB standard disk và 1 GB
outbound/tháng. Xem
[Google Cloud Free Program](https://docs.cloud.google.com/free/docs/free-cloud-features).

## Nếu bắt buộc public toàn bộ backend

OCI Always Free A1 là phương án $0 thực tế hơn: entitlement hiện tương đương
2 OCPU và 12 GB RAM, đủ hợp lý hơn cho Keycloak + Envoy + hai Python service.
Tuy nhiên Always Free capacity có thể tạm hết; Oracle cũng nêu rõ VM idle có
thể bị reclaim khi CPU, network và memory đều dưới ngưỡng trong bảy ngày. Xem
[OCI Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
và
[OCI Free Tier](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier.htm).

Không deploy Compose hiện tại thẳng ra Internet. Trước một live backend cần:

1. Đổi Keycloak `start-dev` sang production mode, dùng PostgreSQL bền vững và
   production hostname.
2. Đặt TLS/reverse proxy, chỉ mở 443; SSH giới hạn theo IP hoặc Bastion.
3. Tách issuer/origin/policy theo environment; không giữ `localhost` trong
   public policy.
4. Lưu secret ngoài Git, rotate API key/client secret và không public Keycloak
   admin console.
5. Thay limiter process-local nếu scale nhiều replica; thiết lập backup,
   monitoring, update image và recovery runbook.
6. Giữ GitHub Pages hoạt động độc lập để sản phẩm vẫn xem được khi free VM bị
   reclaim hoặc hết capacity.

Các yêu cầu hardening Keycloak nêu trên bám theo tài liệu chính thức về
[production mode](https://www.keycloak.org/server/configuration-production),
[database](https://www.keycloak.org/server/db),
[hostname](https://www.keycloak.org/server/hostname) và
[reverse proxy](https://www.keycloak.org/server/reverseproxy).

Vì mục tiêu là một đường link nộp bài ổn định, public static dashboard +
on-demand verified backend cho buổi demo có tỷ lệ bền vững/rủi ro tốt hơn một
VM miễn phí phải hoạt động 24/7.
