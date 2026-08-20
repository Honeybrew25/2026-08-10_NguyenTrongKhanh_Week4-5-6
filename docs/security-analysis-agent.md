# Công cụ phân tích cảnh báo bảo mật

> Week 3 · Xem [hướng dẫn chính](../README.md),
> [báo cáo tuần](../reports/week-3.md) và
> [lần chạy Gemini](../reports/week-3/gemini-live-run-2026-08-03.md).

## Mục đích

Công cụ đọc kết quả Bandit/ZAP, ghép tài liệu liên quan và tạo báo cáo JSONL.
Nó chỉ giúp sắp xếp, giải thích cảnh báo; người đọc vẫn phải xác minh vì kết
quả quét chưa chứng minh lỗ hổng có thể bị khai thác.

Dữ liệu mẫu gồm
[`normalized-findings.json`](../security-results/normalized-findings.json) với
27 cảnh báo Week 1 và
[`vulnerabilities.json`](../data/vulnerabilities.json) với 17 tài liệu Week 2.

## Cách xử lý

[`SecurityAnalysisAgent`](../src/security_pipeline/analysis/agent.py):

1. Kiểm tra định dạng, phần tổng kết và số bản ghi.
2. Gom theo `(tool, rule_id)`, giữ mức nghiêm trọng cao nhất và độ tin cậy thấp
   nhất để không làm nhẹ rủi ro.
3. Chỉ ghép tài liệu khi `related_scanner_rules` khớp chính xác công cụ và mã. B101
   và ZAP 10049 chưa có tài liệu vẫn được báo cáo, không bị gán gần đúng.
4. Tạo phần giải thích, cách kiểm tra và hướng khắc phục.
5. Ghép dữ liệu gốc, kiểm tra không thiếu/lặp cảnh báo rồi mới thay file kết quả.

Kết quả hiện tại là 27 cảnh báo → 9 nhóm. Mỗi ID nguồn xuất hiện đúng một lần
trong `source_finding_ids`, nên vẫn truy được vị trí và bằng chứng ban đầu.

Các file bàn giao: `security-results/security-analysis.jsonl` (9 nhóm offline),
`schemas/security-analysis-finding.schema.json` (định dạng mỗi dòng),
`src/security_pipeline/analysis/prompts/security_analysis_system.md` (quyền
viết của AI), `security-results/runs/week-3/gemini-live-2026-08-03.jsonl` (bản
Gemini để so sánh) và `reports/week-3.md` (lịch sử tuần). JSONL dành cho chương
trình; Markdown chỉ để đọc, không đưa ngược vào pipeline.

### Chi tiết 9 nhóm

| Rule | Mức | Số cảnh báo | Tài liệu ghép |
|---|---:|---:|---|
| Bandit `B310` | Medium | 2 | `ssrf` |
| Bandit `B101` | Low | 14 | Không gán cố ý |
| Bandit `B105` | Low | 1 | `authentication-failures` |
| Bandit `B404` | Low | 2 | `os-command-injection` |
| Bandit `B603` | Low | 2 | `os-command-injection` |
| ZAP `10021` | Low | 1 | `security-headers-misconfiguration` |
| ZAP `90004-1` | Low | 1 | `insecure-design`, `security-headers-misconfiguration` |
| ZAP `10049-1` | Informational | 3 | Không gán cố ý |
| ZAP `10049-3` | Informational | 1 | Không gán cố ý |

Tổng: 1 Medium, 6 Low, 2 Informational; 6 nhóm khớp tài liệu chính xác, 3 nhóm
giữ nguyên dữ liệu quét và không đoán.

### Mốc kiểm thử

| Mốc | Số liệu | Ghi chú |
|---|---|---|
| `reports/week-3.md` | 15 test Week 3; 53 toàn project | Lịch sử, không sửa lại |
| Week 3 `c8b2eb9` | 50 test không Docker; 60 test đầy đủ | [CI cuối Week 3](https://github.com/Honeybrew25/2026-08-07_NguyenTrongKhanh_Week3/actions/runs/31138335407) |
| Bản hiện tại | Chạy lại lệnh bên dưới | Suite tiếp tục tăng từ Week 4/UI |

## Kết quả và cách ngăn AI bịa dữ liệu

Mỗi dòng theo
[`security-analysis-finding.schema.json`](../schemas/security-analysis-finding.schema.json).
Kết quả quét sở hữu `name`, `severity`, `locations`, `scanner_evidence`,
`confidence`, `occurrence_count` và `source_finding_ids`; kho tài liệu sở hữu
`knowledge_ids`. AI chỉ viết `explanation`, `verification_steps` và
`remediation_steps`; `analysis_method` ghi model đã dùng.

JSONL không có khối Markdown hay dòng tổng kết. Thứ tự nhóm, trường và ID ổn
định khi đầu vào không đổi. SHA-256 có thể khác giữa LF/CRLF, nên chỉ so mã sau
khi thống nhất kiểu xuống dòng.

[`System Prompt`](../src/security_pipeline/analysis/prompts/security_analysis_system.md)
coi cảnh báo và kho tài liệu là dữ liệu, không phải câu lệnh. Trước khi gửi cho
AI, chương trình che email, số điện thoại lab, token, API key, mật khẩu và các
trường định danh; nội dung gửi cũng bị giới hạn độ dài. Sau khi nhận kết quả,
chương trình:

- từ chối URL đầy đủ, đường dẫn Windows, thiếu/thừa nhóm và ID bị mất/lặp;
- chỉ nhận đường dẫn API tương đối, đường dẫn trong kho mã, CWE/CVE hoặc mã Bandit
  đã có trong nguồn của nhóm;
- từ chối tên/alias lỗ hổng từ tài liệu không khớp chính xác rule.

File quét thô được giữ riêng theo thời hạn. Dữ liệu gửi AI và bằng chứng/vị trí
trong JSONL đều được che; báo cáo không giữ thông tin bí mật chỉ vì file gốc còn có.

## Chạy offline

Chế độ `deterministic` chạy theo quy tắc cố định, không cần API key và dùng cho
demo, kiểm thử, CI; nó không đánh giá chất lượng AI.

```powershell
python -m security_pipeline analyze `
    security-results/normalized-findings.json `
    --knowledge-base data/vulnerabilities.json `
    --provider deterministic `
    --output security-results/security-analysis.jsonl
```

Kết quả: [`security-analysis.jsonl`](../security-results/security-analysis.jsonl).
Kiểm tra file đã lưu không đổi:

```powershell
git diff --exit-code -- security-results/security-analysis.jsonl
```

## Chạy với Gemini

Gemini không bắt buộc. Cài phần `agent`, tạo `.env` từ `.env.example`, chỉ điền
`GEMINI_API_KEY` và `GEMINI_*` trên máy cá nhân. `.env` đã bị Git bỏ qua; không
đưa khóa vào commit, báo cáo hoặc log.

```powershell
python -m pip install --editable ".[agent]"

python -m security_pipeline analyze `
    security-results/normalized-findings.json `
    --knowledge-base data/vulnerabilities.json `
    --provider gemini `
    --output "$env:TEMP\security-analysis-gemini.jsonl"
```

Model chính: `gemini-3.5-flash-lite`, thinking `minimal`; `--model` ghi đè
`GEMINI_MODEL`. Google Search, URL context, chạy code và tool ngoài đều tắt.
Mỗi nhóm gửi tối đa ba đoạn cảnh báo; mỗi lần gọi nhận tối đa 4.096 token;
JSONL trên máy vẫn giữ đủ bằng chứng. Thư viện Google Gen AI yêu cầu kết quả
đúng định dạng Pydantic.

Nếu kết quả trống, sai định dạng hoặc không bám nguồn, chương trình thử đúng một
lần bằng `gemini-3.6-flash` với mức suy luận `low`. Không thử lại khi sai API
key, hết hạn mức hay lỗi mạng. `analysis_method` ghi model thực tế. Nếu cả hai
lần sai, mã trả về là `3` và file tốt trước đó không bị ghi đè.

Dữ liệu scanner rời máy khi dùng Gemini. Chỉ dùng khi được phép; với dữ liệu
bảo mật thật, nên dùng paid tier thay vì free tier theo chính sách dữ liệu.
Xem [model mới nhất](https://ai.google.dev/gemini-api/docs/latest-model),
[Structured Outputs](https://ai.google.dev/gemini-api/docs/structured-output)
và [bảng giá](https://ai.google.dev/gemini-api/docs/pricing).

## Lỗi và kiểm thử

- `findings: []` hợp lệ tạo JSONL 0 byte, trả mã `0`, không gọi bộ tạo nội dung.
- File trống, JSON lỗi, sai định dạng hoặc tổng kết lệch trả mã `2`; file tốt
  không bị thay.
- Bộ tạo nội dung lỗi, bịa đường dẫn hoặc trả sai nhóm trả mã `3`; không ghi
  file dở dang.

```powershell
python -m pytest -q tests/test_security_analysis_agent.py
```

Kiểm thử dùng dữ liệu Week 1/2 và xác nhận gom nhóm, ghép đúng mã, thứ tự JSONL
trong cùng môi trường, dữ liệu lỗi, chỉ dẫn độc hại, che thông tin bí mật, nội dung bịa,
Gemini đúng định dạng, một lần thử lại và System Prompt.

## Bàn giao sang Week 4

Week 4 chỉ dùng nhóm có nguồn và `source_finding_ids` để chọn bài kiểm tra có
sẵn. Phần AI viết không thể tạo địa chỉ, dữ liệu gửi, phương thức, đường dẫn,
API key hay trường HTTP; danh sách cho phép trong code vẫn giữ các quyền này.
Xem [hướng dẫn chính](../README.md) và
[Safe API Testing Tool](safe-api-testing-tool.md).

## Giới hạn

- Chỉ hỗ trợ định dạng chuẩn hóa `1.0` và Bandit/ZAP.
- Gom theo rule không chứng minh mọi cảnh báo trong nhóm có cùng nguyên nhân.
- Công cụ không khai thác, không sửa code và không thay người kiểm tra.
- Gemini gửi mọi nhóm trong một lượt với tổng 4.096 token; chưa chia
  nhỏ dữ liệu lớn.
- Trình ghi dùng một file `.tmp`, chưa khóa nhiều tiến trình. Chỉ chạy một tiến
  trình cho mỗi đường dẫn kết quả tại một thời điểm.
