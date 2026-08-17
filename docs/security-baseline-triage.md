# Fresh ZAP baseline triage

## Phạm vi và kết quả

Triage này dùng ZAP `2.17.0`, seed public `GET /health` qua Envoy ngày
15/08/2026. Scanner chạy standard spider và passive rules, không nhận Agent
token hoặc Safe API key. Vì vậy đây là unauthenticated passive baseline, không
phải bằng chứng bao phủ protected API.

| Snapshot | Alert refs | URL instances | Low | Informational | Console |
|---|---:|---:|---:|---:|---|
| Trước hardening | 7 | 20 | 2 | 5 | 0 FAIL, 5 WARN, 62 PASS |
| Sau hardening | 5 | 16 | 0 | 5 | 0 FAIL, 4 WARN, 63 PASS |

Artefact nguồn:

- Trước: `security-results/runs/week-5/zap-fresh.json`.
- Sau: `security-results/runs/week-5/zap-hardening.json` và
  `zap-hardening.html`.
- Evidence tổng hợp: `evidence/week-5/baseline.log`.

## Quyết định theo từng alert ref ban đầu

| Alert ref | Trước | Quyết định | Căn cứ và điều kiện mở lại |
|---|---:|---|---|
| `90004-2` COEP missing/invalid | Low · 3 | **Fixed** | UI response nay có `Cross-Origin-Embedder-Policy: require-corp`; ZAP hậu-hardening không còn alert này. Mở lại nếu UI cần cross-origin resource mới. |
| `90004-1` CORP missing/invalid | Low · 1 | **Fixed** | Middleware thêm `Cross-Origin-Resource-Policy: same-origin` cho mọi response, gồm `/health`; unit test và ZAP hậu-hardening đều Pass. |
| `10055-12` CSP header & meta | Info · 3 | **Accepted** | CSP meta bảo vệ static Pages; CSP header bảo vệ bản serve qua Envoy và bổ sung `frame-ancestors 'none'`, directive không dùng được trong meta. Hai policy chung cùng deny-by-default. Mở lại nếu chúng lệch directive hoặc static hosting có thể đặt header. |
| `10109` Modern Web Application | Info · 3 | **Accepted** | Đây là fingerprint khuyến nghị dùng Client Spider, không phải lỗ hổng. Scope chuẩn chỉ dùng standard spider; authenticated/client-spider coverage là công việc riêng. |
| `10049-1` Non-Storable Content | Info · 2 | **Accepted, policy explicit** | Sau hardening, HTML/JSON/health có `no-store`; denial `robots.txt`/`sitemap.xml` vẫn fail closed. Không cache nội dung runtime là chủ đích, đổi lại hiệu năng nhỏ. |
| `10049-3` Storable and Cacheable Content | Info · 5 | **Accepted, reduced** | Sau hardening chỉ JS/CSS công khai còn cache `max-age=300`, có version query và không chứa credential; HTML/data/health không cache. Mở lại nếu asset chứa dữ liệu theo người dùng hoặc secret scan fail. |
| `10031` User Controllable HTML Attribute | Info · 3 | **Reviewed hotspot / false positive** | StaticFiles bỏ qua query khi đọc `index.html`; regression test chứng minh response byte-for-byte không đổi và marker không phản chiếu. JavaScript không đọc query, DOM dùng `textContent`, CSP cấm inline script. Mở lại nếu thêm query parsing hoặc HTML sink. |

Hai alert Low đã được xử lý; năm alert còn lại đều Informational và có rationale
cụ thể. Không dùng `-I` để gọi toàn bộ cảnh báo là “Pass”: release evidence phải
giữ JSON, hash, số residual và các acceptance ở bảng trên.

## Giới hạn DAST đã chấp nhận

Spider quan sát 10 URL public/root/UI nhưng không có JWT, không gọi
`/api/users`, `/api/admin` hoặc ba route Safe API có credential. IAM và Safe
API boundary được kiểm chứng bằng integration tests riêng; receipt của những
test đó không được đổi tên thành DAST. Khi phạm vi sản phẩm yêu cầu
authenticated DAST, phải tạo context/user riêng, inject credential qua secret
runtime, giới hạn exact routes và tiếp tục redaction artefact trước khi commit.
