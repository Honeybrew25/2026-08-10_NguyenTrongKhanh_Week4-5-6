# Checklist hoàn thiện Project Sentinel

Nguồn yêu cầu gốc: [`docs/todo`](todo). File này chỉ theo dõi tiến độ; không
thay đổi yêu cầu gốc và không sửa các báo cáo tuần đã chốt.

- Rà soát gần nhất: 20/08/2026
- Nhánh local: `week-6`
- Mốc bằng chứng gần nhất: `ea98afa`
- Trạng thái: chức năng trên máy đạt; bản cuối vẫn chờ commit, CI và người kiểm tra độc lập

## Đọc nhanh

| Hạng mục | Kết quả hiện tại |
|---|---|
| Lần quét mới | 41 cảnh báo Bandit Low → 6 nhóm; High = 0 |
| Đánh giá | 10/10; 5 trường hợp phân tích + 5 trường hợp xử lý; TP=6, FP=0, FN=0 |
| Kiểm thử thường | 216 đạt, 28 không thuộc phạm vi |
| Kiểm thử đầy đủ | 244 đạt, Docker được dọn sạch |
| Demo thật | Reject=0 yêu cầu; Approve=1; nội dung xấu bị cách ly; admin=0 |
| Dữ liệu nhạy cảm | Không thấy thông tin bí mật hoặc dữ liệu cá nhân trong kết quả đã kiểm |

Evidence chính:
[`pre-release-verification-2026-08-20.log`](../evidence/week-6/pre-release-verification-2026-08-20.log).

Quy ước:

- `[x]`: đã có code, test và bằng chứng phù hợp.
- `[ ]`: còn cần làm hoặc cần người khác xác nhận.
- `P0`: bắt buộc trước khi gọi là release cuối.

## Week 1–4: phần nền đã hoàn thành

| ID | Trạng thái | Nội dung đã đạt |
|---|---|---|
| `BASE-01..14` | [x] | Mốc ban đầu, tìm kiếm, quét, Compose, `.env`, liên kết và số liệu đã được kiểm lại. |
| `W1-01..04` | [x] | FastAPI chạy sau Envoy; có Keycloak, Bandit, ZAP, CI và kết quả quét JSON. |
| `W2-01..02` | [x] | Bandit/ZAP dùng chung một mẫu dữ liệu; kho kiến thức có 17 mục và tìm đúng SQL Injection/XSS. |
| `W3-01..04` | [x] | Bộ phân tích gộp theo công cụ/mã cảnh báo, giữ nguồn, hạn chế bịa dữ liệu và tạo JSONL ổn định. |
| `W4-01..06` | [x] | Công cụ chỉ dùng chức năng/mẫu thử có sẵn và mọi yêu cầu đi qua Gateway. |

Các mốc lịch sử vẫn được giữ nguyên:

- Week 2: 27 finding đã chuẩn hóa.
- Week 3: 27 finding → 9 nhóm phân tích.
- Week 4: ba đường dẫn cho công cụ, bốn dữ liệu thử an toàn và biên nhận đã làm sạch.

Tài liệu liên quan:
[Week 1](week1.md), [Week 2](week2.md),
[Week 3–4](week3_4.md),
[Agent](security-analysis-agent.md) và
[Safe API Tool](safe-api-testing-tool.md).

## Week 5: các lớp bảo vệ

### Che dữ liệu (`RED-01..12`)

- [x] Che email, số điện thoại, token, API key, password và PII.
- [x] Che trước khi gửi cho AI, ghi nhật ký, biên nhận hoặc báo cáo cuối.
- [x] Dùng marker ổn định và đếm được số lần che.
- [x] Có ít nhất hai test dữ liệu nhạy cảm, gồm dữ liệu lồng nhau.
- [x] Không làm thay đổi object đầu vào và chạy lại vẫn cho cùng kết quả.

### Chống chỉ dẫn độc hại trong phản hồi HTTP (`PI-01..12`)

- [x] Mọi phản hồi HTTP được coi là dữ liệu không đáng tin.
- [x] Nội dung phản hồi không thể đổi mục tiêu, lấy thông tin bí mật hoặc tạo yêu cầu mới.
- [x] Nội dung trả về đáng ngờ bị đánh dấu và cách ly.
- [x] Không lưu bản thô sau khi phát hiện.
- [x] Có hai test chỉ dẫn độc hại và một luồng hoàn chỉnh qua đường dẫn mẫu.

### Phê duyệt thủ công (`HITL-01..12`)

- [x] POST hoặc dữ liệu có rủi ro phải hiện loại yêu cầu, đường dẫn, dữ liệu và mục đích.
- [x] Reject, thiếu quyết định, hết thời gian hoặc dữ liệu sai đều không gửi yêu cầu.
- [x] Approve chỉ dùng một lần, có thời hạn và gắn đúng nội dung yêu cầu.
- [x] Danh sách cho phép được kiểm lại ngay trước khi gửi.
- [x] Đường dẫn không được phép vẫn bị chặn dù đề xuất cố vượt quyền.
- [x] Quyết định và biên nhận không chứa API key hoặc dữ liệu thô ngoài phạm vi.

### Kiểm tra chung Week 5 (`CON-01..14`, `GR-01..08`)

- [x] Trạng thái, phê duyệt, nội dung trả về và nhật ký dùng mẫu dữ liệu riêng.
- [x] Lỗi cấu hình dừng trước khi gửi; lỗi lọc phản hồi dừng trước bước tiếp theo.
- [x] Biên nhận vẫn đọc được bằng định dạng Week 4.
- [x] Mỗi lần chạy chỉ có một đề xuất; Reject và Approve là hai lần chạy.
- [x] File sinh tự động được bỏ qua; chỉ bản mẫu đã làm sạch được giữ lại.

Xem [tóm tắt Week 5](week5.md).

## Week 6: nối thành sản phẩm hoàn chỉnh

### Quy trình hoàn chỉnh (`E2E-01..13`)

- [x] Luồng gồm scan → chuẩn hóa → phân tích → đề xuất → phê duyệt → Gateway →
  lọc phản hồi → báo cáo.
- [x] Dùng JSON quét mới của chính lần chạy và giữ mã SHA-256 đầu vào.
- [x] `run_id` nối từng bước, phê duyệt, biên nhận và báo cáo cuối.
- [x] Dữ liệu rỗng hoặc sai dừng an toàn và không ghi đè kết quả tốt.
- [x] Báo cáo cuối tách rõ dữ liệu quét, phần AI, quyết định người dùng và
  kết quả gửi yêu cầu.
- [x] HTTP 200 chỉ được ghi là tín hiệu kiểm tra, không phải bằng chứng khai thác.

### Docker và CI (`OPS-01..13`)

- [x] Compose có Keycloak, API, `authz-service`, Envoy và runner chạy một lần.
- [x] Runner dùng tài khoản không phải root, không mở port và chỉ đọc file cần thiết.
- [x] Có hai địa chỉ cố định cho host/Compose; AI không được chọn địa chỉ.
- [x] Bandit Low dùng làm dữ liệu; Bandit High chạy riêng để chặn release.
- [x] CI lấy Bandit/ZAP của cùng một lần chạy rồi mới chuẩn hóa và phân tích.
- [x] File kết quả được kiểm định dạng, mã SHA-256 và dữ liệu nhạy cảm trước khi tải lên.
- [x] ZAP được ghi đúng là quét thụ động, chưa bao phủ API cần đăng nhập.

### Log và số liệu (`OBS-01..08`)

- [x] Có thời gian chạy, số cảnh báo, số nhóm, số yêu cầu, Approve/Reject và lỗi.
- [x] Có số lần phát hiện injection và che dữ liệu.
- [x] Chỉ đếm yêu cầu sau khi thực sự mở kết nối.
- [x] Nhật ký có phiên bản cách phân tích, danh sách cho phép và định dạng dữ liệu nhưng không ghi thông tin đăng nhập.

### Bộ đánh giá (`EVAL-01..15`)

- [x] Có đúng 10 case do nhóm tự viết và có đáp án rõ ràng.
- [x] Năm trường hợp phân tích kiểm SQL Injection, XSS, gộp trùng, mức độ và bẫy bịa dữ liệu.
- [x] Năm trường hợp xử lý kiểm dữ liệu rỗng/sai, chỉ dẫn độc hại, che dữ liệu và phê duyệt.
- [x] Kết quả hiện tại: 10/10, TP=6, FP=0, FN=0.
- [x] Định dạng hợp lệ 100%, đủ nguồn 100%; không bịa, rò rỉ hoặc vượt quy tắc.
- [x] Không dùng AI để tự chấm kết quả AI.

Chi tiết: [Kết quả đánh giá](evaluation.md).

## Tài liệu và demo

| ID | Trạng thái | Kết quả |
|---|---|---|
| `DOC-01..07`, `DOC-10` | [x] | Có README, kiến trúc, kết quả, product brief, báo cáo và giới hạn lab. |
| `DOC-08 P0` | [ ] | Cần một người không tham gia code chạy lại từ bản mã mới tải về. |
| `DOC-09 P1` | [ ] | Dashboard đã khớp pre-release; cần cập nhật lại sau final commit. |
| `DEMO-01..11` | [x] | Có lần quét mới, phân tích, Reject, Approve, chặn admin, cách ly nội dung xấu, che dữ liệu, số liệu và bản dự phòng. |
| `DEMO-12 P0` | [ ] | Technical rehearsal đạt; còn chờ người nghiệm thu xác nhận buổi trình bày 10–15 phút. |

Các tài liệu dùng khi trình bày:

- [Kịch bản 10–15 phút](demo-script.md)
- [Hướng dẫn terminal](terminal-demo.md)
- [Hướng dẫn dashboard](ui-dashboard.md)
- [Product brief](product-brief.md)
- [Phiếu nghiệm thu](release-acceptance.md)

## Điều kiện phát hành

### Phần đã đạt

- [x] `REL-01..06`: từ lần quét mới đến báo cáo cuối, phê duyệt, bảo vệ, số liệu và đánh giá.
- [x] `REL-08`: bộ kiểm tra không thấy thông tin bí mật hoặc dữ liệu cá nhân trong kết quả.
- [x] `REL-09..10`: đủ README, demo, code, tài liệu, kết quả và product brief.
- [x] `RUBRIC-01`: từng nhóm tiêu chí đã có đường dẫn đến evidence.

### Phần còn chờ

- [ ] `REL-07 P0`: commit toàn bộ file, chạy lại kiểm thử đầy đủ bằng Docker
  trên chính commit đó và ghi bằng chứng mới.
- [ ] `REL-11 P0`: mọi file bàn giao phải được Git theo dõi; working tree phải
  sạch hoặc có giải thích rõ.
- [ ] Hosted CI phải chạy trên nhánh/commit đã push.
- [ ] `DOC-08` và `DEMO-12` phải có người xác nhận thật.

Không đánh dấu hoàn thành sản phẩm cho đến khi bốn việc trên đều đạt. Hiện tại
không có P0 chức năng nào thất bại; các mục mở đều là bước nghiệm thu cuối.

## Lệnh kiểm tra trước release

```powershell
python -m pip install --requirement requirements-dev.txt
python -m pip install --requirement security/requirements.txt
python -m ruff check src tests scripts
python -m pytest -q -m "not integration"
python -m security_pipeline search "SQL Injection" --limit 1
python -m security_pipeline search "XSS" --limit 1
python -m project_sentinel evaluate --provider deterministic
python -m project_sentinel demo --provider deterministic --format human
docker compose config --quiet
python scripts/run_all_tests.py
git diff --check
git rev-parse HEAD
git status --porcelain
git ls-files --error-unmatch docs/todo-checklist.md
```

Bandit Low có thể trả exit 1 vì tìm thấy cảnh báo; điều cần kiểm là JSON hợp lệ
và được phân tích. Bandit High phải trả 0 và không có finding High.

## Giới hạn đã chấp nhận

- Chỉ thử trên môi trường Docker Compose; không dùng dữ liệu phá hoại hoặc dữ liệu thật.
- Dashboard chỉ để xem, không giữ API key và không phê duyệt yêu cầu.
- Keycloak `start-dev`, HTTP nội bộ và giới hạn theo từng tiến trình chưa phù hợp môi trường thật.
- ZAP mới quét thụ động từ `/health`; chưa kiểm tra thư viện, image Docker và cấu hình.
- Cách nhận diện theo mẫu chữ có thể nhận nhầm hoặc bỏ sót ngoài bộ dữ liệu đã công bố.
- Gemini là tùy chọn; bản phát hành mặc định dùng chế độ cho kết quả cố định.

Các phần như GraphRAG, nhiều AI phối hợp, GPU tự vận hành, AI tự chấm và hệ
thống thật có tính sẵn sàng cao nằm ngoài phạm vi hiện tại.
