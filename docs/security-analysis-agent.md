# Security Analysis Agent

## Mục tiêu và phạm vi

Security Analysis Agent đọc kết quả Bandit/ZAP đã chuẩn hóa ở Week 2, đối
chiếu với kho tri thức và tạo báo cáo JSONL dễ đọc. Agent hỗ trợ triage: một
cảnh báo của scanner vẫn cần được xác minh thủ công và không phải bằng chứng
rằng lỗ hổng có thể khai thác.

Hai nguồn đầu vào hiện tại là:

- [`normalized-findings.json`](../security-results/normalized-findings.json):
  27 finding được chuẩn hóa từ kết quả quét Week 1.
- [`vulnerabilities.json`](../data/vulnerabilities.json): 17 tài liệu trong kho
  tri thức Week 2.

## Luồng xử lý

```text
normalized findings + knowledge base
        |
        v
 validate input --> group by tool/rule --> exact-rule retrieval
        |                                      |
        +------------> narrative provider <----+
                              |
                              v
              grounding + provenance checks
                              |
                              v
                  atomic UTF-8 JSONL output
```

[`SecurityAnalysisAgent`](../src/security_pipeline/analysis/agent.py) thực hiện
các bước sau:

1. Kiểm tra schema, summary và số record nguồn trước khi phân tích.
2. Nhóm các finding theo cặp `(tool, rule_id)`. Nhóm lấy severity cao nhất và
   confidence thấp nhất của các record thành viên để không làm nhẹ cảnh báo.
3. Ghép tri thức chỉ khi `related_scanner_rules` khớp chính xác tool và rule.
   Rule chưa có tài liệu, như Bandit B101 hoặc ZAP 10049, vẫn được báo cáo bằng
   dữ liệu scanner thay vì bị ép vào một loại lỗ hổng gần giống.
4. Yêu cầu provider viết phần giải thích, bước kiểm tra và bước khắc phục.
5. Ghép lại các trường do source quản lý, kiểm tra coverage và ghi file bằng
   atomic replace.

Với baseline hiện tại, 27 finding tạo thành 9 nhóm. Mọi finding nguồn xuất hiện
đúng một lần trong `source_finding_ids`; vị trí và bằng chứng vẫn được giữ để
người review truy ngược.

## Hợp đồng JSONL

Mỗi dòng là một JSON object độc lập theo
[`security-analysis-finding.schema.json`](../schemas/security-analysis-finding.schema.json).
Các trường chính gồm:

| Trường | Ý nghĩa |
|---|---|
| `name`, `severity` | Tên cảnh báo và mức nghiêm trọng lấy từ scanner |
| `locations` | Danh sách file/URL, dòng và HTTP method có trong input |
| `scanner_evidence` | Bằng chứng cùng tool, rule, source file và finding ID |
| `explanation` | Giải thích ngắn bằng ngôn ngữ đơn giản |
| `verification_steps` | Cách kiểm tra không phá hoại trước khi kết luận |
| `remediation_steps` | Các bước khắc phục đề xuất, chưa khẳng định đã áp dụng |
| `confidence` | Confidence bảo thủ từ các finding nguồn |
| `occurrence_count` | Số cảnh báo đã được gom vào nhóm |
| `source_finding_ids`, `knowledge_ids` | Provenance để truy ngược dữ liệu |
| `analysis_method` | Provider và model thực sự đã tạo phần diễn giải |

JSONL không có code fence hoặc record tổng kết. Thứ tự nhóm, thứ tự field và ID
ổn định để chế độ deterministic tạo cùng một file khi input không đổi.

## Ranh giới chống bịa dữ liệu

[`System Prompt`](../src/security_pipeline/analysis/prompts/security_analysis_system.md)
coi toàn bộ scanner evidence và kho tri thức là dữ liệu không tin cậy, không
phải chỉ dẫn. Provider không được tạo `name`, severity, location, evidence hoặc
provenance; các trường này luôn do chương trình dựng từ input.

Trước khi gọi provider, token/secret giống credential được che và context dài
được giới hạn. Sau khi nhận diễn giải, Agent từ chối URL, endpoint, đường dẫn
repository, CWE/CVE/Bandit rule không có căn cứ trong nhóm nguồn. Agent cũng từ
chối output thiếu/thừa group và kiểm tra rằng không finding nguồn nào bị mất
hoặc lặp. Tên và alias của loại lỗ hổng thuộc một tài liệu tri thức không được
exact-match với nhóm cũng bị từ chối. Bằng chứng gốc vẫn được giữ trong file
local; chỉ payload gửi provider được redact.

## Chạy không cần API key

Provider `deterministic` là baseline offline dùng cho demo, test và CI. Nó
không được xem là phép đánh giá chất lượng của LLM.

```powershell
python -m security_pipeline analyze `
    security-results/normalized-findings.json `
    --knowledge-base data/vulnerabilities.json `
    --provider deterministic `
    --output security-results/security-analysis.jsonl
```

Kết quả bàn giao nằm tại
[`security-analysis.jsonl`](../security-results/security-analysis.jsonl).
Chạy lại lệnh rồi dùng lệnh sau để kiểm tra output được commit không thay đổi:

```powershell
git diff --exit-code -- security-results/security-analysis.jsonl
```

## Chạy với Gemini

Gemini là provider tùy chọn. Cài extra `agent`, copy `.env.example` thành file
`.env` đã được ignore và chỉ điền `GEMINI_API_KEY` cùng cấu hình `GEMINI_*` ở
máy local. Không commit khóa API hoặc dán khóa vào báo cáo/log.

```powershell
python -m pip install --editable ".[agent]"

python -m security_pipeline analyze `
    security-results/normalized-findings.json `
    --knowledge-base data/vulnerabilities.json `
    --provider gemini `
    --output "$env:TEMP\security-analysis-gemini.jsonl"
```

Provider dùng Google Gen AI SDK và Pydantic Structured Output. Model chính là
`gemini-3.5-flash-lite` với thinking `minimal`; có thể truyền `--model` để ghi
đè `GEMINI_MODEL`. Provider không bật Google Search, URL context, code
execution hoặc tool bên ngoài vì scanner data và kho tri thức nội bộ là nguồn
grounding duy nhất. Mỗi nhóm chỉ gửi tối đa ba scanner context đại diện và mỗi
request bị giới hạn 4.096 output token; JSONL local vẫn giữ đủ bằng chứng nguồn.

Nếu kết quả model chính trống, sai schema hoặc bị Agent từ chối bởi kiểm tra
grounding, Agent thử lại **đúng một lần** bằng `gemini-3.6-flash` với thinking
`low`. Fallback không chạy cho lỗi API key, quota hoặc mạng, tránh retry tốn
chi phí nhưng không thể cải thiện output. `analysis_method` ghi model thực sự
đã tạo record; nếu cả hai lần đều không hợp lệ, lệnh trả exit code `3` và không
ghi đè output tốt trước đó.

Scanner data vẫn rời máy khi dùng provider này; chỉ sử dụng với dữ liệu đã
được phép gửi tới dịch vụ bên ngoài. Với dữ liệu bảo mật thật, nên dùng paid
tier thay vì free tier theo chính sách sử dụng dữ liệu trên trang giá.

Tham khảo tài liệu chính thức: [model Gemini mới
nhất](https://ai.google.dev/gemini-api/docs/latest-model), [Structured Outputs
với Pydantic](https://ai.google.dev/gemini-api/docs/structured-output) và
[Gemini API pricing](https://ai.google.dev/gemini-api/docs/pricing).

## Dữ liệu lỗi và kiểm thử

- Input hợp lệ có `findings: []` tạo file JSONL 0 byte, exit code `0` và không
  gọi provider.
- File trống, JSON lỗi, sai schema hoặc summary không nhất quán trả exit code
  `2`; output tốt trước đó không bị thay thế.
- Provider lỗi, bịa endpoint hoặc trả sai tập group trả exit code `3`; không
  ghi output dở dang.

Chạy bộ test riêng:

```powershell
python -m pytest -q tests/test_security_analysis_agent.py
```

Test bao phủ dữ liệu thật Week 1/2, grouping, mapping tri thức chính xác,
JSONL byte-stable, input rỗng/lỗi, prompt injection, redact secret, provider
bịa endpoint/loại lỗ hổng, Gemini Structured Output, fallback đúng một lần và
nội dung bắt buộc của System Prompt.

## Giới hạn

Agent hiện chỉ hỗ trợ schema chuẩn hóa `1.0` và hai scanner Bandit/ZAP. Việc
gom theo rule làm báo cáo ngắn hơn nhưng không chứng minh các occurrence có
cùng nguyên nhân gốc. Agent không chạy exploit, không sửa code và không thay
thế security review thủ công.
