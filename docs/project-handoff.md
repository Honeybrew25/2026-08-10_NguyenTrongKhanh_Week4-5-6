# Project handoff — lịch sử Session và workflow tiếp tục

> Cập nhật: 10/08/2026 (UTC+7)
> Repository: `Honeybrew25/2026-08-10_NguyenTrongKhanh_Week4-5-6`
> Working copy: `D:\AI Vinsoc\2026-08-10_NguyenTrongKhanh_Week4-5-6`
> Baseline trước Week 4: commit chuẩn bị `9a8f78c`, kế thừa Week 3 từ `c8b2eb9`

## 1. Mục đích tài liệu

Đây là điểm bắt đầu cho Session tiếp theo. Tài liệu tổng hợp các Session Codex
đã làm trực tiếp trên repository này, quyết định kỹ thuật đã chốt, workflow
hiện tại, trạng thái kiểm thử và các việc nên làm tiếp.

Nguồn đối chiếu gồm lịch sử Session cục bộ, Git history, source code, tài liệu,
artifact và trạng thái GitHub Actions. Nội dung nhạy cảm như API key, token và
toàn bộ transcript thô không được sao chép vào repository.

## 2. Tóm tắt nhanh để làm tiếp

Project hiện có bốn lớp chức năng nối tiếp nhau:

1. **Week 1 — thu thập dữ liệu:** Bandit và OWASP ZAP tạo kết quả quét.
2. **Week 2 — chuẩn hóa và tra cứu:** kết quả từ các scanner được đổi về một
   schema chung; kho tri thức có 17 chủ đề bảo mật.
3. **Week 3 — phân tích:** Security Analysis Agent đọc 27 finding chuẩn hóa,
   gom thành 9 nhóm, lấy tri thức bằng exact rule match và tạo JSONL có
   grounding/provenance.
4. **Week 4 — kiểm thử API an toàn:** deterministic planner chỉ đề xuất
   capability ID; policy code dựng GET/POST hữu hạn, thực thi qua Envoy với API
   key riêng, exact allowlist, request/response cap, rate limit và receipt đã
   redact.

Trạng thái cần nhớ:

- Source hiện hành nằm trong `src/`; không tạo source tree riêng cho mỗi tuần.
- `reports/week-N.md` đã có là snapshot lịch sử bất biến.
- Provider `deterministic` là mặc định cho local/CI và không cần API key.
- Gemini là tùy chọn; chỉ dùng khi dữ liệu được phép gửi ra dịch vụ bên ngoài.
- Không ghi đè baseline deterministic bằng một lần chạy LLM.
- Baseline Week 3 `c8b2eb9` đã có một GitHub Actions run xanh toàn bộ; baseline
  chuẩn bị workspace Week 4 là `9a8f78c`.
- Các tham chiếu repo cũ trong `docs/ci-cd.md` đã được sửa khi chuẩn bị working
  copy Week 4–5–6.

## 3. Các Session đã tìm thấy

### 3.1 Session chính

| Thời gian | Session ID | Tiêu đề/đường dẫn | Vai trò và kết quả |
|---|---|---|---|
| 03/08–05/08/2026 | `019fc54b-d291-7d80-a667-62972de69950` | `Sắp xếp lại cấu trúc project`; cwd cũ `2026-07-30_NguyenTrongKhanh_Week3` | Session triển khai chính: tái cấu trúc repo, xây Week 3 Agent, xử lý remote GitHub, chuyển OpenAI provider sang Gemini, chạy live và hướng dẫn OpenGrep PowerShell. Đã archive. |
| 10/08/2026 | `019fe94b-4665-79e2-934a-30270f670bd9` | `Tổng hợp session project`; cwd hiện tại `2026-08-07_NguyenTrongKhanh_Week3` | Truy tìm Session, đối chiếu repository/CI và tạo tài liệu handoff này. |

Session ngày 03/08 dùng tên thư mục cũ nhưng đúng là cùng project: metadata của
Session bắt đầu tại commit `d3270f8`, và commit này là commit gốc trong lịch sử
Git hiện tại. Transcript về sau cũng ghi nhận repository đã đổi sang tên ngày
`2026-08-07`.

### 3.2 Các subagent thread trong Session 03/08

11 thread dưới đây là các nhánh công việc nội bộ của cùng Session chính. Các
thay đổi được thực hiện trên shared worktree và được agent chính rà soát/gộp
lại.

| Thread | Session ID | Công việc thực tế |
|---|---|---|
| `/root/structure_audit` | `019fc54c-1aef-72c3-9c01-b196ecd27362` | Audit vai trò folder, mức độ rối và hướng tổ chức lại. |
| `/root/reports_audit` | `019fc54c-2e3e-7141-9091-f852bd18b5b2` | Kiểm tra báo cáo tuần, checksum, link và phân biệt tài liệu người đọc với artifact máy đọc. |
| `/root/path_audit` | `019fc54c-67a8-7491-80a1-6e0e77184be6` | Tìm dependency đường dẫn trong import, Docker, Compose, CI, scripts và tests trước khi move file. |
| `/root/week3_architecture` | `019fc567-4016-7231-a068-b32d658a6faf` | Review kiến trúc Agent, schema, grouping, grounding và provider boundary. |
| `/root/week3_prompt_review` | `019fc567-6263-74d2-a0d5-3d8a6813b43e` | Triển khai phần tạo JSONL deterministic trong CI; bản cuối được gộp vào `security-scan.yml`. |
| `/root/week3_deliverables` | `019fc567-884d-7512-a38f-fac390edf688` | Hoàn thiện README, tài liệu Agent, báo cáo Week 3 và JSONL mẫu. |
| `/root/gemini_sdk_review` | `019fc5c4-4676-7803-bf28-98a9ba79a14f` | Review Google Gen AI SDK, fallback, type checking và giới hạn output. |
| `/root/gemini_test_review` | `019fc5c4-550c-7352-8209-7bbae4f250fc` | Bổ sung test primary/fallback, lỗi provider, context limit và provenance. |
| `/root/gemini_docs_review` | `019fc5c4-6838-7fe2-8aa8-b92e99e27467` | Cập nhật dependency, `.env.example`, README và tài liệu Gemini. |
| `/root/report_location_review` | `019fc5d5-062c-7553-87e1-5025612d37d0` | Chốt vị trí report chạy thật và raw JSONL mà không sửa snapshot tuần. |
| `/root/schema_adapter_review` | `019fc5d6-91dd-7af1-9c9f-ece0ed548540` | Xác định lỗi `response_schema`; đề xuất `response_json_schema` và giữ strict validation local. |

## 4. Workflow công việc đã thực hiện

### 4.1 Tổ chức lại repository theo góp ý mentor

Mục tiêu là để người mới nhìn repo trong khoảng năm phút có thể phân biệt code,
config, dataset, output và báo cáo.

Các quyết định đã áp dụng:

- Chuyển ba Python package vào `src/`.
- Chuyển Envoy, Keycloak và ZAP config vào `config/`.
- Chuyển kho tri thức đã curate vào `data/`.
- Giữ raw/derived scanner artifact ở `security-results/` và verification log
  ở `evidence/`.
- Đổi tên báo cáo thành `reports/week-1.md` và `reports/week-2.md` bằng Git
  rename; nội dung/checksum lịch sử được giữ nguyên tại thời điểm di chuyển.
- Thêm `AGENTS.md` làm repository guide duy nhất; không tạo `CLAUDE.md` trùng
  lặp hoặc `DEBT.md` rỗng.
- Thêm `pyproject.toml` để package discovery và pytest dùng `src/` layout.
- Cập nhật đồng bộ Dockerfile, Compose, CI, imports, scripts và đường dẫn tài
  liệu.

Kiểm chứng tại thời điểm tái cấu trúc: 28 unit test pass, sau đó 38 test pass
với Docker integration; hai image build thành công và Compose hợp lệ.

### 4.2 Xây Security Analysis Agent Week 3

Luồng đã triển khai:

```text
Bandit/ZAP raw
    -> normalize + validate
    -> normalized-findings.json
    -> group theo (tool, rule_id)
    -> exact-rule knowledge retrieval
    -> deterministic hoặc Gemini narrative
    -> grounding + provenance validation
    -> atomic JSONL output
```

Ranh giới quan trọng:

- Code, không phải LLM, sở hữu `name`, `severity`, `locations`, evidence,
  confidence và provenance.
- Provider chỉ viết `explanation`, `verification_steps` và
  `remediation_steps`.
- Severity lấy giá trị cao nhất trong nhóm; confidence lấy giá trị thấp nhất
  để tránh làm nhẹ cảnh báo.
- Knowledge chỉ được gắn khi `(tool, rule_id)` khớp chính xác.
- Rule chưa có knowledge vẫn xuất hiện bằng dữ liệu scanner, không bị ép sang
  một lỗ hổng gần giống.
- Output bị từ chối nếu thêm endpoint, repo path, CWE/CVE, scanner rule hoặc
  loại lỗ hổng không có căn cứ.
- Mỗi finding nguồn phải xuất hiện đúng một lần trong `source_finding_ids`.
- File được ghi nguyên tử; input/provider lỗi không ghi đè output tốt trước đó.

Baseline hiện tại: **27 finding → 9 nhóm JSONL**.

### 4.3 Tích hợp CI/CD

Workflow duy nhất là `.github/workflows/security-scan.yml`:

1. Unit tests và Bandit.
2. Tạo JSONL Week 3 bằng provider deterministic.
3. Docker integration với Keycloak, Envoy, staging API và authz service.
4. OWASP ZAP Baseline qua Envoy.
5. Upload Bandit, ZAP và Week 3 JSONL artifacts.
6. Khi push vào `main`, build và publish `staging-api` cùng `authz-service`
   lên GHCR.

Provider Gemini không chạy trong CI, vì vậy CI không cần Gemini API key và có
kết quả lặp lại được.

### 4.4 Sửa lỗi Git push

Lỗi lịch sử:

```text
Repository not found:
Honeybrew25/2026-07-30_NguyenTrongKhanh_Week3
```

Nguyên nhân là `origin` dùng ngày cũ trong URL trong khi repo thật được tạo với
tên `2026-08-07_NguyenTrongKhanh_Week3`. Remote hiện đã đúng:

```text
https://github.com/Honeybrew25/2026-08-07_NguyenTrongKhanh_Week3.git
```

Không force-push sang repository SAST Training vì đó là project/lịch sử Git
khác.

### 4.5 Chuyển narrative provider sang Gemini

Thiết kế hiện hành:

- SDK: `google-genai==2.16.0`.
- Primary: `gemini-3.5-flash-lite`, thinking `minimal`.
- Fallback: `gemini-3.6-flash`, thinking `low`, tối đa một lần.
- Fallback chỉ dùng khi output trống, sai schema hoặc không đạt grounding.
- Lỗi API key, quota, mạng/server request không kích hoạt fallback tự động.
- Tối đa ba scanner context đại diện được gửi cho mỗi nhóm; JSONL local vẫn
  giữ toàn bộ evidence.
- Giới hạn cứng `4096` output token/request.
- `analysis_method` ghi model thực sự tạo narrative.
- Gemini dùng `response_json_schema`; `minLength`/`maxLength` được bỏ khỏi
  schema gửi API vì không được hỗ trợ, nhưng Pydantic vẫn validate strict sau
  khi nhận output.

Pydantic được nâng lên `2.13.4` để tương thích dependency. Provider
deterministic vẫn là default và nguồn baseline.

### 4.6 Chạy Gemini thật

Run đã được giữ riêng tại:

- Human report: `reports/week-3/gemini-live-run-2026-08-03.md`.
- Raw JSONL: `security-results/runs/week-3/gemini-live-2026-08-03.jsonl`.

Kết quả đã xác minh:

- Primary thành công trong 8,01 giây; không dùng fallback.
- 27/27 finding được phủ đúng một lần, tạo 9 nhóm.
- Phân bố: 1 Medium, 6 Low, 2 Informational.
- Pydantic, JSON Schema và grounding đều pass.
- SHA-256:
  `ad027dda8264eb39c2f2ad034b13cda5fd4bcc72b7ff9332aa755abf19822e2b`.
- Không lưu usage metadata, nên chưa có số token/chi phí thực tế.

## 5. Lịch sử commit liên quan

| Commit | Nội dung |
|---|---|
| `d3270f8` | Baseline Week 1–2 trước Session tái cấu trúc; là commit gốc của repo hiện tại. |
| `fa256f9` | Chuyển source/config/data/report sang cấu trúc mới. |
| `894edda` | Thêm Security Analysis Agent, System Prompt, schema, tests, docs và deterministic JSONL. |
| `625e58e` | Tích hợp Gemini, fallback/grounding nâng cao và lưu live-run artifact. |
| `c8b2eb9` | Rút gọn mô tả trong báo cáo Week 2/3; HEAD lịch sử của Week 3. Không tìm thấy một local Codex Session riêng tương ứng với commit này. |
| `9a8f78c` | Chuẩn bị repository/remote Week 4–5–6 trước khi triển khai Safe API Tool. |

## 6. Bản đồ repository hiện tại

| Vị trí | Source of truth |
|---|---|
| `src/app/` | FastAPI staging API. |
| `src/authz_service/` | Envoy external authorization service và JWT validation. |
| `src/security_pipeline/normalizers/` | Adapter Bandit/ZAP về normalized schema. |
| `src/security_pipeline/analysis/agent.py` | Validate, group, retrieve, ground, coverage và atomic JSONL write. |
| `src/security_pipeline/analysis/models.py` | Strict Pydantic contracts cho input, narrative và output. |
| `src/security_pipeline/analysis/providers.py` | Deterministic và Gemini providers. |
| `src/security_pipeline/analysis/prompts/` | System Prompt được package cùng module. |
| `src/safe_api_tool/` | Planner, policy engine, bounded client, CLI và sanitized audit Week 4. |
| `config/safe-api-tool/policy.json` | Capability allowlist và resource budget Week 4. |
| `data/safe-api-test-cases.json` | Bốn payload profile an toàn được curate. |
| `config/` | Envoy, Keycloak và ZAP config. |
| `data/vulnerabilities.json` | Kho tri thức curate Week 2, 17 chủ đề. |
| `schemas/` | Hợp đồng normalized findings và analysis finding. |
| `security-results/` | Raw/derived machine artifacts và các run JSONL. |
| `evidence/` | Verification logs. |
| `tests/` | Unit tests; `tests/integration/` cần Docker stack. |
| `docs/` | Tài liệu kỹ thuật lâu dài theo chủ đề. |
| `reports/` | Snapshot tiến độ theo tuần; file `week-N.md` đã có là bất biến. |
| `.github/workflows/security-scan.yml` | Pipeline kiểm thử, scan, artifact và publish image. |

Tài liệu nên đọc theo thứ tự khi bắt đầu Session mới:

1. `AGENTS.md` — quy tắc repository và quality gates.
2. Tài liệu này — lịch sử và trạng thái bàn giao.
3. `README.md` — lệnh sử dụng nhanh.
4. `docs/security-analysis-agent.md` — thiết kế chi tiết của Agent.
5. `docs/safe-api-testing-tool.md` — contract và threat model Week 4.
6. `reports/week-4.md` — snapshot kết quả Week 4, không chỉnh sửa.

## 7. Workflow chuẩn cho công việc tiếp theo

### 7.1 Chuẩn bị và lấy baseline

```powershell
git status --short --branch
git pull --ff-only

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --requirement requirements-dev.txt
```

Nếu `.venv` đã tồn tại thì chỉ activate và đồng bộ requirements. Không đọc,
in hoặc commit nội dung `.env`.

### 7.2 Chốt phạm vi trước khi sửa

Với mỗi task mới, ghi rõ:

- Input/source of truth nào được dùng.
- Output thuộc `src/`, `data/`, `security-results/`, `evidence/`, `docs/` hay
  `reports/`.
- Acceptance criteria và lệnh kiểm tra.
- Có cần gọi Gemini hoặc gửi scanner data ra ngoài hay không.
- Báo cáo tuần hiện tại đã tồn tại chưa; nếu đã có thì tạo tuần kế tiếp.

### 7.3 Phát triển

- Sửa code dùng chung trong `src/`, không tạo `week-4/src`.
- Thêm test tương ứng trong `tests/`.
- Dataset curate đi vào `data/`; raw scan hoặc JSONL run đi vào
  `security-results/`; log kiểm chứng đi vào `evidence/`.
- Tài liệu kỹ thuật mới dùng tên theo chủ đề trong `docs/`.
- Không thêm generated JSON/CSV/HTML/log vào `docs/` hoặc `reports/`.
- Không thêm `DEBT.md` cho một ghi chú lẻ; dùng issue hoặc mục “Việc tiếp theo”
  cho đến khi có backlog kỹ thuật thực sự.

### 7.4 Quality gates bắt buộc

Chạy từ repository root:

```powershell
python -m pip install --requirement requirements-dev.txt
python -m pytest -q -m "not integration"
python -m security_pipeline search "SQL Injection" --limit 1
python -m security_pipeline analyze security-results/normalized-findings.json `
  --knowledge-base data/vulnerabilities.json `
  --provider deterministic `
  --output "$env:TEMP\security-analysis-check.jsonl"
docker compose config --quiet
git diff --check
```

Khi thay đổi Docker, IAM, Envoy, Keycloak hoặc flow end-to-end, chạy thêm:

```powershell
python scripts/run_all_tests.py
```

### 7.5 Tạo báo cáo/analyzer output

Baseline deterministic có thể tái tạo bằng:

```powershell
python -m security_pipeline analyze `
  security-results/normalized-findings.json `
  --knowledge-base data/vulnerabilities.json `
  --provider deterministic `
  --output security-results/security-analysis.jsonl

git diff --exit-code -- security-results/security-analysis.jsonl
```

Gemini là run tùy chọn. Mặc định ghi ra temp để không đè baseline:

```powershell
python -m security_pipeline analyze `
  security-results/normalized-findings.json `
  --knowledge-base data/vulnerabilities.json `
  --provider gemini `
  --output "$env:TEMP\security-analysis-gemini.jsonl"
```

Chỉ lưu một live run vào repo khi có mục đích kiểm chứng rõ ràng. Khi đó đặt
raw JSONL dưới `security-results/runs/week-N/` và báo cáo người đọc dưới một
thư mục phụ `reports/week-N/`; không sửa `reports/week-N.md` đã chốt.

### 7.6 Kết thúc một task/tuần

1. Chạy quality gates phù hợp với mức thay đổi.
2. Kiểm tra secret không xuất hiện trong tracked/untracked files.
3. Kiểm tra `git status`, `git diff --check` và generated artifacts.
4. Cập nhật durable docs nếu contract/workflow thay đổi.
5. Nếu sang tuần mới, tạo đúng một `reports/week-(N+1).md` ngắn, tách rõ
   `Quá trình` và `Kết quả`.
6. Push branch, mở pull request và chờ CI xanh trước khi merge.

## 8. Trạng thái xác minh tại thời điểm bàn giao

Local ngày 10/08/2026 trên commit `c8b2eb9`:

| Kiểm tra | Kết quả |
|---|---|
| `pytest -m "not integration"` | `50 passed, 10 deselected`; có 1 `StarletteDeprecationWarning` từ dependency. |
| Knowledge search | Trả đúng `SQL Injection` ở kết quả đầu. |
| Deterministic analysis | 27 finding → 9 grounded JSONL record. |
| `docker compose config --quiet` | Pass. |
| Full Docker integration trong working copy mới | `60 passed`; hai image build thành công, bốn service healthy và stack được dọn sạch. |
| Live artifact SHA-256 | Khớp báo cáo: `ad027d...22e2b`. |

Remote GitHub:

- Repository Week 4–5–6 public, default branch `main`.
- `origin/main` và local HEAD cùng ở `9a8f78c` sau bước chuẩn bị/push.
- GitHub Actions run đầu tiên trên repo mới kết thúc thành công ngày
  10/08/2026.
- Các job xanh: Unit tests and Bandit, Docker integration tests, OWASP ZAP
  Baseline, Publish staging-api và Publish authz-service.

Docker integration được chạy lại sau khi tạo working copy Week 4–5–6. Lần
build đầu gặp lỗi kết nối PyPI tạm thời trong container; retry tải đúng
`pydantic==2.13.4` và toàn bộ 60 test pass, nên đây không phải lỗi source code.

## 9. Việc còn lại và rủi ro đã biết

### Việc tiếp theo hiện tại

1. Week 4 đã hoàn tất theo trạng thái ở mục 12; không khởi động lại hoặc sửa
   `reports/week-4.md`. Trước khi triển khai Week 5, đọc lại yêu cầu Week 5,
   chốt acceptance criteria và đối chiếu chúng với Safe API Tool hiện có.

### Đã xử lý khi chuẩn bị working copy Week 4–5–6

- Năm tham chiếu repo/path cũ trong `docs/ci-cd.md` đã được cập nhật. GHCR và
  `Set-Location` đều dùng tên Week 4–5–6 hiện hành.

### Giới hạn kỹ thuật hiện tại

- Agent chỉ hỗ trợ normalized schema `1.0` và hai scanner Bandit/ZAP.
- Group theo scanner rule giúp rút gọn báo cáo nhưng không chứng minh các
  occurrence có cùng root cause.
- Agent không exploit, không tự sửa code và không thay thế security review.
- Gemini run gửi phần scanner/knowledge context đã redact ra dịch vụ ngoài;
  phải có quyền xử lý dữ liệu trước khi bật.
- Chưa lưu usage metadata nên chưa đo token/chi phí theo run.
- Cảnh báo deprecation giữa Starlette TestClient và `httpx` chưa làm test fail;
  cần đánh giá khi nâng dependency, chưa đủ để tạo `DEBT.md` riêng.
- Commit `c8b2eb9` có trong Git nhưng không có local Codex Session riêng được
  tìm thấy; khi cần điều tra lý do thay đổi, dùng `git show c8b2eb9` làm source
  of truth.

## 10. Definition of Done cho công việc kế tiếp

Một task tiếp theo chỉ nên được coi là hoàn tất khi:

- Code/data/output đặt đúng thư mục và không phá repository invariants.
- Test mới chứng minh happy path cùng các lỗi quan trọng.
- Deterministic provider vẫn chạy không cần secret.
- Output có schema, grounding và provenance nếu liên quan Security Analysis.
- Unit gates pass; integration pass nếu thay đổi boundary Docker/IAM/network.
- Không rò `.env`, API key, client secret hoặc token.
- Tài liệu theo chủ đề được cập nhật; báo cáo tuần cũ không bị sửa.
- Git diff dễ review, CI xanh và phần “việc còn lại” được ghi rõ trong handoff
  hoặc issue tiếp theo.

## 11. Trạng thái working copy Week 4–5–6

Đã chuẩn bị ngày 10/08/2026:

- Clone tại `D:\AI Vinsoc\2026-08-10_NguyenTrongKhanh_Week4-5-6`.
- `main` và nhánh local `week-4-5-6` cùng trỏ tới commit chuẩn bị `9a8f78c`;
  `main` đã được push.
- `origin` trỏ tới
  `Honeybrew25/2026-08-10_NguyenTrongKhanh_Week4-5-6`; repository Week 3 được
  giữ dưới remote `upstream` để tra cứu lịch sử khi cần.
- `.venv` dùng Python 3.11.9, đã cài `requirements-dev.txt`; `pip check` không
  phát hiện dependency hỏng.
- `.env` local đã được tạo với IAM secret ngẫu nhiên và được `.gitignore` bảo
  vệ. `GEMINI_API_KEY` để trống; chỉ điền khi một live run đã được cho phép.
- `docs/ci-cd.md` đã sửa path local và tên GHCR hiện hành.
- Quality gates: 50 unit test pass, knowledge search pass, deterministic
  analysis 27→9 pass, Compose config pass và full Docker integration 60 test
  pass.
- GitHub Actions run `31349435574` pass cả Unit/Bandit, Docker integration,
  ZAP và publish hai image GHCR.
- Không tạo trước `reports/week-4.md`; báo cáo chỉ được thêm sau khi có công
  việc và kết quả thực tế.

## 12. Trạng thái sau khi hoàn thành Week 4

Đã triển khai và xác minh ngày 10/08/2026:

- Giữ Envoy + `ext_authz` làm Gateway fail-closed; thêm identity API key riêng
  `safe-api-tool`, exact route allowlist và limiter 12 request/phút trên mỗi
  key/method/route.
- Policy dùng chung nằm tại `config/safe-api-tool/policy.json`; bốn payload
  curate nằm tại `data/safe-api-test-cases.json`; proposal và receipt có JSON
  Schema tương ứng trong `schemas/`.
- API test chỉ gồm `GET /api/test/status` và `POST /api/test/validate`, đều
  stateless. Backend có canary trả lỗi nếu `x-api-key` lọt qua Gateway.
- Package mới `src/safe_api_tool/` thực hiện proposal, policy decision,
  dry-run, bounded HTTP execution, streaming response cap và sanitized audit.
- Envoy áp request-body cap 4 KiB cho đúng safe POST trước `ext_authz`; HTTP
  status khác contract có outcome `unexpected_status` và không thể làm CLI/CI
  báo đậu.
- CLI chuẩn: `python -m safe_api_tool propose`, `run` và `demo`; network chỉ mở
  khi truyền `--execute`.
- Evidence thật: `security-results/runs/week-4/safe-api-demo.jsonl` và
  `evidence/week-4/verification.log`.
- Quality gates: 120 non-integration test pass; full Docker 140 test pass;
  Bandit High, knowledge search, deterministic analysis, Compose config,
  schema validation và `git diff --check` đều pass.
- CI sinh secret tạm, chạy full Safe API demo và upload artifact
  `week4-safe-api-demo-receipts`.
- `reports/week-4.md` đã được tạo sau run thật; từ đây coi báo cáo này là lịch
  sử bất biến giống các báo cáo tuần trước.

Giới hạn chủ động để chuyển sang công việc tiếp theo:

- Limiter authz hiện process-local; khi scale nhiều replica cần distributed
  rate-limit store/service.
- Planner Week 4 cố ý deterministic. Nếu thêm LLM, model vẫn chỉ được chọn
  capability ID, không được sở hữu URL, raw payload hoặc credential.
- ZAP baseline CI vẫn chỉ scan `/health`; authenticated/allowlisted DAST là
  hướng mở rộng riêng, không thay thế safety contract của Safe API Tool.
